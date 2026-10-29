//! The cache gives back exactly the store it was given, and refuses anything
//! that is not a store Fulgurite could have written.

use fg_core::{Evidence, Span, Va};
use fg_facts::{
    Claim, Confidence, EvidenceKind, Fact, FactId, FactStore, Provenance, Slot, Status, Support,
    Verdict,
};
use fg_store::{Cache, CacheError};

fn fact(claim: Claim, status: Status, c: f32, pass: &str, inputs: Vec<FactId>) -> Fact {
    let mut p = Provenance::new(pass, 3);
    p.inputs = inputs;
    p.insns = vec![Va(0x1000), Va(0x1004)];
    let ev = Support::new(
        EvidenceKind::Symbol,
        Evidence::at(format!("{pass}: \"quoted\" ✓"), Span::new(0x40, 24)),
        Confidence::new(c).unwrap(),
    )
    .at(Va(0x1000));
    Fact::new(claim, status, Confidence::new(c).unwrap(), p, vec![ev]).unwrap()
}

/// Every claim kind and status, a dependency chain, a dirty fact and one whose
/// input was retracted.
fn sample() -> (FactStore, [FactId; 3]) {
    let mut s = FactStore::new();
    let f = |e| Claim::IsFunction { entry: Va(e) };
    let seed = fact(f(0x1000), Status::Declared, 0.98, "seeds", vec![]);
    let seed_id = seed.id();
    s.insert(seed).unwrap();
    let callee = fact(
        f(0x2000),
        Status::Inferred,
        0.931,
        "cfg.calls",
        vec![seed_id],
    );
    let callee_id = callee.id();
    s.insert(callee).unwrap();
    let doomed = fact(f(0x3000), Status::Inferred, 0.5, "guess", vec![]);
    let doomed_id = doomed.id();
    s.insert(doomed).unwrap();
    let orphan = fact(
        Claim::NoReturn { entry: Va(0x3000) },
        Status::Inferred,
        0.7,
        "noreturn",
        vec![doomed_id],
    );
    let orphan_id = orphan.id();
    s.insert(orphan).unwrap();
    s.retract(doomed_id).unwrap(); // the orphan is now dirty with a missing input
    for (claim, status) in [
        (
            Claim::IsCode {
                start: Va(0x1000),
                end: Va(0x1040),
            },
            Status::Declared,
        ),
        (
            Claim::IsData {
                start: Va(0x4000),
                end: Va(0x4008),
            },
            Status::Observed,
        ),
        (
            Claim::FunctionEnd {
                entry: Va(0x1000),
                end: Va(0x1040),
            },
            Status::Inferred,
        ),
        (
            Claim::Edge {
                from: Va(0x1010),
                to: Va(0x2000),
                edge: fg_facts::EdgeKind::Call,
            },
            Status::Inferred,
        ),
        (
            Claim::Name {
                entity: Va(0x1000),
                name: "main".into(),
            },
            Status::User,
        ),
        (
            Claim::Name {
                entity: Va(0x1000),
                name: "sub_1000".into(),
            },
            Status::Rejected,
        ),
    ] {
        let c = if matches!(status, Status::User | Status::Rejected | Status::Observed) {
            1.0
        } else {
            0.875
        };
        s.insert(fact(claim, status, c, "misc", vec![])).unwrap();
    }
    s.invalidate(callee_id).unwrap();
    (s, [seed_id, callee_id, orphan_id])
}

fn same(a: &FactStore, b: &FactStore) {
    let x: Vec<_> = a.snapshot().map(|(f, c, d)| (f.clone(), c, d)).collect();
    let y: Vec<_> = b.snapshot().map(|(f, c, d)| (f.clone(), c, d)).collect();
    assert_eq!(x, y);
    assert_eq!(a.seq(), b.seq());
    for slot in a.slots() {
        assert_eq!(a.resolve(slot), b.resolve(slot), "{slot:?}");
    }
}

#[test]
fn round_trip_is_exact() {
    let (store, [seed, callee, orphan]) = sample();
    let mut cache = Cache::in_memory().unwrap();
    assert!(cache.load("bin").unwrap().is_none());
    cache.save("bin", &store).unwrap();
    let back = cache.load("bin").unwrap().unwrap();
    same(&store, &back);
    assert_eq!(back.is_dirty(callee), Some(true));
    assert_eq!(back.is_dirty(orphan), Some(true));
    assert_eq!(back.dependents(seed), vec![callee]);
    assert_eq!(
        back.resolve(&Slot::Name { entity: Va(0x1000) }).verdict,
        Verdict::Accepted(
            back.facts_in(&Slot::Name { entity: Va(0x1000) })
                .find(|f| f.status() == Status::User)
                .unwrap()
                .id()
        )
    );
    // Saving again replaces, and binaries are kept apart.
    let mut smaller = FactStore::new();
    smaller
        .insert(fact(
            Claim::IsFunction { entry: Va(9) },
            Status::Declared,
            1.0,
            "seeds",
            vec![],
        ))
        .unwrap();
    cache.save("other", &smaller).unwrap();
    cache.save("bin", &smaller).unwrap();
    same(&smaller, &cache.load("bin").unwrap().unwrap());
    cache.remove("bin").unwrap();
    assert!(cache.load("bin").unwrap().is_none());
    same(&smaller, &cache.load("other").unwrap().unwrap());
}

#[test]
fn survives_reopening_and_clears_other_schema_versions() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("fg-store-file");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("analysis.sqlite");
    let (store, _) = sample();
    Cache::open(&path).unwrap().save("bin", &store).unwrap();
    same(
        &store,
        &Cache::open(&path).unwrap().load("bin").unwrap().unwrap(),
    );

    let c = Cache::open(&path).unwrap();
    c.connection()
        .pragma_update(None, "user_version", 999)
        .unwrap();
    drop(c);
    assert!(Cache::open(&path).unwrap().load("bin").unwrap().is_none());
}

/// Damages one stored value and expects the load to be refused.
fn refused(sql: &str) -> CacheError {
    let (store, _) = sample();
    let mut cache = Cache::in_memory().unwrap();
    cache.save("bin", &store).unwrap();
    let n = cache.connection().execute(sql, []).unwrap();
    assert!(n >= 1, "{sql} changed nothing");
    match cache.load("bin") {
        Err(e) => e,
        Ok(_) => panic!("loaded after: {sql}"),
    }
}

#[test]
fn damaged_caches_are_refused() {
    let corrupt = |e: CacheError| assert!(matches!(e, CacheError::Corrupt(_)), "{e}");
    // A changed claim no longer matches its id.
    corrupt(refused(
        "UPDATE facts SET claim = replace(claim, '4096', '4097') WHERE claim LIKE '%is_function%4096%'",
    ));
    // Out-of-range or non-f32 confidences.
    corrupt(refused(
        "UPDATE facts SET confidence = 1.5 WHERE id = (SELECT min(id) FROM facts)",
    ));
    corrupt(refused(
        "UPDATE facts SET confidence = 0.1 WHERE id = (SELECT min(id) FROM facts)",
    ));
    // A fact without evidence, an empty range, a bad status, a bad id.
    corrupt(refused(
        "UPDATE facts SET evidence = '[]' WHERE id = (SELECT min(id) FROM facts)",
    ));
    corrupt(refused(
        "UPDATE facts SET claim = '{\"kind\":\"is_code\",\"start\":64,\"end\":64}' WHERE claim LIKE '%is_code%'",
    ));
    corrupt(refused(
        "UPDATE facts SET status = '\"maybe\"' WHERE id = (SELECT min(id) FROM facts)",
    ));
    corrupt(refused(
        "UPDATE facts SET id = 'xyz' WHERE id = (SELECT min(id) FROM facts)",
    ));
    // A clean fact whose input is missing.
    let e = refused("UPDATE facts SET dirty = 0");
    assert!(
        matches!(e, CacheError::Store(fg_facts::StoreError::UnknownInput(_))),
        "{e}"
    );
}
