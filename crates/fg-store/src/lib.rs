//! The analysis cache (design §5.1–§5.2): every fact the passes produced,
//! persisted in SQLite so that reopening a binary does not re-run them.
//!
//! The cache is regenerable by definition: deleting it loses no human work,
//! only time. So it is never trusted. Every fact read back is rebuilt through
//! [`Fact::new`] (evidence present, ranges non-empty, confidences in range),
//! its id must match the one recomputed from its claim and pass, and the store
//! it rebuilds must be closed and acyclic ([`FactStore::restore`]). A cache
//! that fails any check is reported as corrupt, never half-loaded.
//!
//! Facts are kept per binary, keyed by an id the caller chooses (the binary's
//! content hash). Saving replaces a binary's facts in one transaction, so a
//! crash mid-save leaves the previous version.

use fg_facts::{Fact, FactId, FactStore, OpSeq, StoreError};
use rusqlite::{Connection, OptionalExtension, params};
use std::fmt;
use std::path::Path;

/// Bumped when the table layout or the stored JSON changes. A cache with
/// another version is cleared when opened.
pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS binaries (
    binary TEXT PRIMARY KEY,
    seq    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS facts (
    binary     TEXT    NOT NULL REFERENCES binaries(binary) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    claim      TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    confidence REAL    NOT NULL,
    provenance TEXT    NOT NULL,
    evidence   TEXT    NOT NULL,
    changed    INTEGER NOT NULL,
    dirty      INTEGER NOT NULL,
    PRIMARY KEY (binary, id)
) WITHOUT ROWID;
";

/// Why the cache could not be used.
#[derive(Debug)]
pub enum CacheError {
    /// SQLite reported an error (file unreadable, disk full, locked...).
    Sqlite(rusqlite::Error),
    /// A stored row is not a valid fact.
    Corrupt(String),
    /// The stored facts do not form a valid store.
    Store(StoreError),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Sqlite(e) => write!(f, "analysis cache: {e}"),
            CacheError::Corrupt(why) => write!(f, "analysis cache is corrupt: {why}"),
            CacheError::Store(e) => write!(f, "analysis cache is corrupt: {e}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<rusqlite::Error> for CacheError {
    fn from(e: rusqlite::Error) -> CacheError {
        CacheError::Sqlite(e)
    }
}

/// An open analysis cache.
pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Opens or creates the cache file. A cache written with another
    /// [`SCHEMA_VERSION`] is cleared.
    pub fn open(path: &Path) -> Result<Cache, CacheError> {
        Cache::init(Connection::open(path)?, true)
    }

    /// A cache that lives only in memory (tests, one-shot command-line runs).
    pub fn in_memory() -> Result<Cache, CacheError> {
        Cache::init(Connection::open_in_memory()?, false)
    }

    fn init(conn: Connection, wal: bool) -> Result<Cache, CacheError> {
        if wal {
            // Readers never block the writer (design §19.2).
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            conn.execute_batch("DROP TABLE IF EXISTS facts; DROP TABLE IF EXISTS binaries;")?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        conn.execute_batch(SCHEMA)?;
        Ok(Cache { conn })
    }

    /// Replaces the facts stored for `binary` with `store`'s.
    pub fn save(&mut self, binary: &str, store: &FactStore) -> Result<(), CacheError> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM binaries WHERE binary = ?1", params![binary])?;
        tx.execute(
            "INSERT INTO binaries (binary, seq) VALUES (?1, ?2)",
            params![binary, to_i64(store.seq().0)?],
        )?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO facts (binary, id, claim, status, confidence, provenance, evidence, changed, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for (fact, changed, dirty) in store.snapshot() {
                ins.execute(params![
                    binary,
                    fact.id().to_string(),
                    json(fact.claim())?,
                    json(&fact.status())?,
                    f64::from(fact.confidence().value()),
                    json(fact.provenance())?,
                    json(fact.evidence())?,
                    to_i64(changed.0)?,
                    dirty,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The facts stored for `binary`, or `None` if it has none.
    pub fn load(&self, binary: &str) -> Result<Option<FactStore>, CacheError> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM binaries WHERE binary = ?1",
                params![binary],
                |r| r.get(0),
            )
            .optional()?;
        let Some(seq) = seq else {
            return Ok(None);
        };
        let mut q = self.conn.prepare(
            "SELECT id, claim, status, confidence, provenance, evidence, changed, dirty
             FROM facts WHERE binary = ?1 ORDER BY id",
        )?;
        let rows = q.query_map(params![binary], |r| {
            Ok(Row {
                id: r.get(0)?,
                claim: r.get(1)?,
                status: r.get(2)?,
                confidence: r.get(3)?,
                provenance: r.get(4)?,
                evidence: r.get(5)?,
                changed: r.get(6)?,
                dirty: r.get(7)?,
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?.into_fact()?);
        }
        let seq = u64::try_from(seq).map_err(|e| CacheError::Corrupt(e.to_string()))?;
        FactStore::restore(entries, OpSeq(seq))
            .map(Some)
            .map_err(CacheError::Store)
    }

    /// Forgets everything stored for `binary`.
    pub fn remove(&mut self, binary: &str) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM binaries WHERE binary = ?1", params![binary])?;
        Ok(())
    }

    /// Direct access for tests that need to damage the file on purpose.
    #[doc(hidden)]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// One stored fact, as read.
struct Row {
    id: String,
    claim: String,
    status: String,
    confidence: f64,
    provenance: String,
    evidence: String,
    changed: i64,
    dirty: bool,
}

impl Row {
    /// Rebuilds the fact through every check a new fact goes through.
    fn into_fact(self) -> Result<(Fact, OpSeq, bool), CacheError> {
        let stored: FactId = self.id.parse().map_err(CacheError::Corrupt)?;
        let ctx = |what: &str, e: &dyn fmt::Display| {
            CacheError::Corrupt(format!("fact {stored}: {what}: {e}"))
        };
        // An f32 survives the round trip through f64 exactly; anything that
        // does not is not a value Fulgurite wrote.
        let c = self.confidence;
        let confidence = fg_facts::Confidence::new(c as f32)
            .filter(|v| f64::from(v.value()) == c)
            .ok_or_else(|| ctx("confidence", &c))?;
        let fact = Fact::new(
            serde_json::from_str(&self.claim).map_err(|e| ctx("claim", &e))?,
            serde_json::from_str(&self.status).map_err(|e| ctx("status", &e))?,
            confidence,
            serde_json::from_str(&self.provenance).map_err(|e| ctx("provenance", &e))?,
            serde_json::from_str(&self.evidence).map_err(|e| ctx("evidence", &e))?,
        )
        .map_err(|e| ctx("invalid fact", &e))?;
        if fact.id() != stored {
            return Err(ctx("id", &format!("its claim and pass give {}", fact.id())));
        }
        let changed = u64::try_from(self.changed).map_err(|e| ctx("change position", &e))?;
        Ok((fact, OpSeq(changed), self.dirty))
    }
}

fn json<T: serde::Serialize + ?Sized>(v: &T) -> Result<String, CacheError> {
    serde_json::to_string(v).map_err(|e| CacheError::Corrupt(format!("cannot encode: {e}")))
}

/// SQLite integers are signed; positions above `i64::MAX` cannot occur in
/// practice and are refused rather than wrapped.
fn to_i64(v: u64) -> Result<i64, CacheError> {
    i64::try_from(v).map_err(|_| CacheError::Corrupt(format!("{v} does not fit the cache")))
}
