// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! The resolution rules (design document, section 4.4) and invalidation through
//! the dependency graph (section 4.5).

use fg_core::{Evidence, Va};
use fg_facts::{
    Claim, Confidence, EvidenceKind, Fact, FactStore, Inserted, Provenance, Slot, Status,
    StoreError, Support, Verdict, Warning,
};

fn conf(v: f32) -> Confidence {
    Confidence::new(v).unwrap()
}

fn fact(claim: Claim, status: Status, c: f32, pass: &str, inputs: Vec<fg_facts::FactId>) -> Fact {
    let mut p = Provenance::new(pass, 1);
    p.inputs = inputs;
    let kind = match status {
        Status::User | Status::Rejected => EvidenceKind::User,
        Status::Observed => EvidenceKind::TraceHit,
        Status::Declared => EvidenceKind::Symbol,
        Status::Inferred => EvidenceKind::Flow,
    };
    let ev = Support::new(kind, Evidence::new(format!("{pass} says so")), conf(c));
    Fact::new(claim, status, conf(c), p, vec![ev]).unwrap()
}

fn func(va: u64) -> Claim {
    Claim::IsFunction { entry: Va(va) }
}

fn name(va: u64, n: &str) -> Claim {
    Claim::Name {
        entity: Va(va),
        name: n.into(),
    }
}

fn add(s: &mut FactStore, f: Fact) -> fg_facts::FactId {
    let id = f.id();
    assert_eq!(s.insert(f), Ok(Inserted::Added));
    id
}

#[test]
fn empty_slot_is_unknown() {
    let s = FactStore::new();
    let r = s.resolve(&Slot::IsFunction { entry: Va(1) });
    assert_eq!(r.verdict, Verdict::Unknown);
    assert!(r.warnings.is_empty() && !r.stale);
}

#[test]
fn agreeing_facts_are_not_a_conflict() {
    let mut s = FactStore::new();
    let a = add(
        &mut s,
        fact(func(0x10), Status::Inferred, 0.6, "calls", vec![]),
    );
    let b = add(
        &mut s,
        fact(func(0x10), Status::Inferred, 0.62, "prologue", vec![]),
    );
    assert_ne!(a, b);
    assert_eq!(
        s.resolve(&Slot::IsFunction { entry: Va(0x10) }).verdict,
        Verdict::Accepted(b)
    );
}

#[test]
fn rejection_beats_everything_for_that_claim_only() {
    let mut s = FactStore::new();
    add(
        &mut s,
        fact(func(0x10), Status::Declared, 0.98, "symbols", vec![]),
    );
    add(&mut s, fact(func(0x10), Status::User, 1.0, "user", vec![]));
    let rej = add(
        &mut s,
        fact(func(0x10), Status::Rejected, 1.0, "user.reject", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::IsFunction { entry: Va(0x10) }).verdict,
        Verdict::Rejected(rej)
    );
    // Rejecting one name leaves the slot open for a different name.
    add(
        &mut s,
        fact(
            name(0x10, "sub_10"),
            Status::Rejected,
            1.0,
            "user.reject",
            vec![],
        ),
    );
    add(
        &mut s,
        fact(
            name(0x10, "sub_10"),
            Status::Declared,
            1.0,
            "symbols",
            vec![],
        ),
    );
    let other = add(
        &mut s,
        fact(name(0x10, "parse"), Status::Inferred, 0.3, "guess", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::Name { entity: Va(0x10) }).verdict,
        Verdict::Accepted(other)
    );
}

#[test]
fn status_outranks_confidence() {
    let mut s = FactStore::new();
    add(
        &mut s,
        fact(name(0x20, "a"), Status::Inferred, 0.99, "guess", vec![]),
    );
    let d = add(
        &mut s,
        fact(name(0x20, "b"), Status::Declared, 0.5, "symbols", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::Name { entity: Va(0x20) }).verdict,
        Verdict::Accepted(d)
    );
    // Observed outranks Declared: metadata can lie.
    let o = add(
        &mut s,
        fact(name(0x20, "c"), Status::Observed, 1.0, "trace", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::Name { entity: Va(0x20) }).verdict,
        Verdict::Accepted(o)
    );
    let u = add(
        &mut s,
        fact(name(0x20, "d"), Status::User, 1.0, "user", vec![]),
    );
    let r = s.resolve(&Slot::Name { entity: Va(0x20) });
    assert_eq!(r.verdict, Verdict::Accepted(u));
    // Rule 4: the user's choice stands, the contradiction is shown.
    assert_eq!(
        r.warnings,
        vec![Warning::ObservedContradictsUser {
            observed: o,
            user: u
        }]
    );
}

#[test]
fn near_ties_are_conflicts_not_coin_flips() {
    let mut s = FactStore::new();
    let a = add(
        &mut s,
        fact(name(0x30, "a"), Status::Inferred, 0.70, "p1", vec![]),
    );
    let b = add(
        &mut s,
        fact(name(0x30, "b"), Status::Inferred, 0.68, "p2", vec![]),
    );
    add(
        &mut s,
        fact(name(0x30, "c"), Status::Inferred, 0.60, "p3", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::Name { entity: Va(0x30) }).verdict,
        Verdict::Conflict(vec![a, b])
    );
    // A clear winner (0.80 vs 0.70) is decided.
    let w = add(
        &mut s,
        fact(name(0x30, "w"), Status::Inferred, 0.80, "p4", vec![]),
    );
    assert_eq!(
        s.resolve(&Slot::Name { entity: Va(0x30) }).verdict,
        Verdict::Accepted(w)
    );
}

#[test]
fn rejecting_what_execution_reached_warns() {
    let mut s = FactStore::new();
    let o = add(
        &mut s,
        fact(func(0x40), Status::Observed, 1.0, "trace", vec![]),
    );
    let rej = add(
        &mut s,
        fact(func(0x40), Status::Rejected, 1.0, "user.reject", vec![]),
    );
    let r = s.resolve(&Slot::IsFunction { entry: Va(0x40) });
    assert_eq!(r.verdict, Verdict::Rejected(rej));
    assert_eq!(
        r.warnings,
        vec![Warning::ObservedContradictsUser {
            observed: o,
            user: rej
        }]
    );
}

#[test]
fn invalidation_follows_the_dependency_graph() {
    let mut s = FactStore::new();
    let seed = add(
        &mut s,
        fact(func(0x50), Status::Declared, 0.98, "symbols", vec![]),
    );
    let end = add(
        &mut s,
        fact(
            Claim::FunctionEnd {
                entry: Va(0x50),
                end: Va(0x60),
            },
            Status::Inferred,
            0.9,
            "cfg",
            vec![seed],
        ),
    );
    let nr = add(
        &mut s,
        fact(
            Claim::NoReturn { entry: Va(0x50) },
            Status::Inferred,
            0.8,
            "noreturn",
            vec![end],
        ),
    );
    let other = add(
        &mut s,
        fact(func(0x70), Status::Declared, 0.98, "symbols", vec![]),
    );

    assert_eq!(s.why(nr), sorted(vec![seed, end]));
    assert_eq!(s.dependents(seed), sorted(vec![end, nr]));
    assert_eq!(s.invalidate(seed), Ok(sorted(vec![seed, end, nr])));
    assert_eq!(s.is_dirty(other), Some(false));
    assert!(s.resolve(&Slot::NoReturn { entry: Va(0x50) }).stale);

    // Recomputing to the same result cleans the fact; its dependents stay dirty
    // until they are recomputed themselves.
    assert_eq!(
        s.insert(fact(func(0x50), Status::Declared, 0.98, "symbols", vec![])),
        Ok(Inserted::Unchanged)
    );
    assert_eq!(s.is_dirty(seed), Some(false));
    assert_eq!(s.is_dirty(nr), Some(true));

    // A changed re-derivation dirties what was built on it.
    s.insert(fact(
        Claim::NoReturn { entry: Va(0x50) },
        Status::Inferred,
        0.8,
        "noreturn",
        vec![end],
    ))
    .unwrap();
    assert_eq!(
        s.insert(fact(func(0x50), Status::Declared, 0.97, "symbols", vec![])),
        Ok(Inserted::Updated(sorted(vec![end, nr])))
    );

    // Retracting dirties dependents and empties the slot.
    assert_eq!(s.retract(end), Ok(vec![nr]));
    assert_eq!(s.why(nr), Vec::new());
    assert_eq!(
        s.resolve(&Slot::FunctionEnd {
            entry: Va(0x50),
            end: Va(0x60)
        })
        .verdict,
        Verdict::Unknown
    );
    assert!(s.slots().all(|sl| *sl
        != Slot::FunctionEnd {
            entry: Va(0x50),
            end: Va(0x60)
        }));
    assert_eq!(s.retract(end), Err(StoreError::UnknownFact(end)));
}

#[test]
fn the_graph_stays_acyclic_and_closed() {
    let mut s = FactStore::new();
    let ghost = fact(func(0x99), Status::Declared, 0.98, "symbols", vec![]).id();
    assert_eq!(
        s.insert(fact(func(0x80), Status::Inferred, 0.5, "p", vec![ghost])),
        Err(StoreError::UnknownInput(ghost))
    );
    let a = add(&mut s, fact(func(0x80), Status::Inferred, 0.5, "a", vec![]));
    let b = add(
        &mut s,
        fact(func(0x90), Status::Inferred, 0.5, "b", vec![a]),
    );
    // `a` re-derived from `b`, which is derived from `a`.
    assert_eq!(
        s.insert(fact(func(0x80), Status::Inferred, 0.6, "a", vec![b])),
        Err(StoreError::Cycle(b))
    );
    let self_ref = fact(func(0x80), Status::Inferred, 0.6, "a", vec![a]);
    assert_eq!(s.insert(self_ref), Err(StoreError::Cycle(a)));
    // The refused updates left the store as it was.
    assert_eq!(s.get(a).unwrap().confidence(), conf(0.5));
    assert_eq!(s.dependents(a), vec![b]);
}

fn sorted(mut v: Vec<fg_facts::FactId>) -> Vec<fg_facts::FactId> {
    v.sort();
    v
}

#[test]
fn restore_refuses_what_insert_would_refuse() {
    let a = fact(func(0x10), Status::Inferred, 0.5, "a", vec![]);
    let b = fact(func(0x20), Status::Inferred, 0.5, "b", vec![a.id()]);
    // Ids do not depend on inputs, so a cycle can be built from valid facts.
    let a_on_b = fact(func(0x10), Status::Inferred, 0.5, "a", vec![b.id()]);
    let seq = fg_facts::OpSeq(2);
    let ok = FactStore::restore(
        [
            (a.clone(), fg_facts::OpSeq(1), false),
            (b.clone(), seq, false),
        ],
        seq,
    )
    .unwrap();
    assert_eq!(ok.dependents(a.id()), vec![b.id()]);
    assert!(matches!(
        FactStore::restore([(a_on_b, seq, false), (b.clone(), seq, false)], seq),
        Err(StoreError::Cycle(_))
    ));
    assert!(matches!(
        FactStore::restore([(b.clone(), seq, false)], seq),
        Err(StoreError::UnknownInput(_))
    ));
    // A dirty fact may wait for a retracted input.
    assert!(FactStore::restore([(b.clone(), seq, true)], seq).is_ok());
    assert!(matches!(
        FactStore::restore([(a.clone(), seq, false), (a, seq, false)], seq),
        Err(StoreError::IdCollision(_))
    ));
}
