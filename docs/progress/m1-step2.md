# M1 step 2: the analysis cache

Status: **done** for the fact cache (2026-10-11). The project folder (`project.toml`,
blobs named by SHA-256, the `user/` JSONL layer of §5.1/§5.3) comes with the service
integration. Builds on [step 1](m1-step1.md).

## What was added

| Area | Details |
|---|---|
| `fg-store` (new crate, layer 2) | `Cache::open(path)` / `Cache::in_memory()`, `save(binary, &FactStore)`, `load(binary)`, `remove(binary)`. SQLite through `rusqlite` 0.40 with the `bundled` feature: the same SQLite on every machine and in CI, nothing taken from the system |
| Layout | `binaries(binary, seq)` and `facts(binary, id, claim, status, confidence, provenance, evidence, changed, dirty)`, keyed by a binary id the caller chooses (its content hash). Claims, provenance and evidence are JSON; ids are 32 hex digits |
| Durability | WAL mode (readers never block the writer, §19.2); a save replaces a binary's facts in one transaction, so a crash mid-save keeps the previous version |
| Schema versions | `SCHEMA_VERSION` in SQLite's `user_version`; a cache written with another version is cleared on open (the cache is regenerable by design) |
| `fg-facts` | `Deserialize` for claims, statuses, evidence and provenance; `FactId` written as 32 hex digits; `Confidence` checked when read; `FactStore::snapshot` / `restore`; `Deserialize` for `Va`, `Span` and `Evidence` in `fg-core` |

## The cache is never trusted

Deleting it loses no human work, only time, so a damaged cache is refused, never
half-loaded. Every row is rebuilt through `Fact::new` (evidence present, valid range and
name, status-consistent confidence), the confidence must be a value an `f32` could
have written, the stored id must equal the id recomputed from the claim and pass, and
`FactStore::restore` checks that every clean fact's inputs exist, that no id appears
twice and that the dependency graph has no cycle (one depth-first search, linear in
facts plus edges). A dirty fact may keep the id of a retracted input: it is waiting to
be recomputed.

## Verification

| Check | Result |
|---|---|
| `fg-store/tests/cache.rs` | Exact round trip of a store with every claim kind and status, a dependency chain, dirty facts and a retracted input (facts, change positions, dirty flags, every slot's resolution); replacing and removing per binary; reopening from a file; clearing on another schema version; refusing a changed claim (id mismatch), out-of-range and non-`f32` confidences, missing evidence, an empty range, an unknown status, a malformed id and a clean fact with a missing input |
| `fg-facts/tests/store.rs` | `restore` refuses a cycle built from valid facts, a missing input of a clean fact and a duplicate id, and accepts a dirty fact waiting for a retracted input |
| `fg-analysis/tests/cfg.rs` | On every binary it analyses: save, reload, and re-running the seed pass and CFG recovery on the reloaded store changes nothing |
| Minimum Rust | The new dependencies declare at most Rust 1.85 (`hashbrown`, `hashlink`); the CI job on 1.88 builds them |
