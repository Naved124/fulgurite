// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! The in-memory fact store: every fact, the resolution rules that pick what is
//! shown (section 4.4), and the dependency graph that tells which facts must be
//! recomputed when one changes (section 4.5).
//!
//! All maps are ordered, so every query returns the same order on every run.

use crate::confidence::Confidence;
use crate::fact::{Claim, Fact, FactId, Slot, Status};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Position in the store's history; later operations have larger numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpSeq(pub u64);

/// Confidences closer than this, at the same status, are a conflict to show,
/// not a contest to decide silently (section 4.4, rule 3).
pub const TIE: f32 = 0.05;

#[derive(Clone, Debug)]
struct Entry {
    fact: Fact,
    changed: OpSeq,
    dirty: bool,
}

/// What [`FactStore::insert`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// A new fact.
    Added,
    /// The same pass re-derived the fact with a different status, confidence,
    /// provenance or evidence; the listed dependents are now dirty.
    Updated(Vec<FactId>),
    /// Identical to the stored fact. A dirty fact recomputed to the same result
    /// is clean again.
    Unchanged,
}

/// Why the store refused an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The fact lists an input the store does not hold.
    UnknownInput(FactId),
    /// No fact with this id.
    UnknownFact(FactId),
    /// The fact would (indirectly) be derived from itself.
    Cycle(FactId),
    /// Two different (claim, pass) pairs hashed to the same id.
    IdCollision(FactId),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::UnknownInput(id) => write!(f, "input fact {id} is not in the store"),
            StoreError::UnknownFact(id) => write!(f, "fact {id} is not in the store"),
            StoreError::Cycle(id) => write!(f, "fact {id} would depend on itself"),
            StoreError::IdCollision(id) => write!(f, "two different facts hash to {id}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The outcome of resolving one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No fact answers the question.
    Unknown,
    /// This fact's claim stands; it is the strongest fact making that claim.
    Accepted(FactId),
    /// A human rejected every claim made in this slot; this is the rejection.
    Rejected(FactId),
    /// Different claims at the same status with confidences within [`TIE`]:
    /// shown to the user as a conflict, strongest first.
    Conflict(Vec<FactId>),
}

/// A disagreement worth showing even though a verdict was reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// Execution was observed to contradict a human decision (section 4.4,
    /// rule 4). The human decision is kept.
    ObservedContradictsUser {
        /// The observed fact.
        observed: FactId,
        /// The user or rejection fact that decided the slot.
        user: FactId,
    },
}

/// The resolution of a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// What stands.
    pub verdict: Verdict,
    /// Disagreements to surface.
    pub warnings: Vec<Warning>,
    /// A fact in the verdict is dirty: the answer may change once it is recomputed.
    pub stale: bool,
}

/// Every fact, indexed by id and by slot, with the reverse dependency edges.
#[derive(Clone, Debug, Default)]
pub struct FactStore {
    facts: BTreeMap<FactId, Entry>,
    by_slot: BTreeMap<Slot, BTreeSet<FactId>>,
    dependents: BTreeMap<FactId, BTreeSet<FactId>>,
    seq: OpSeq,
}

impl FactStore {
    /// An empty store.
    pub fn new() -> FactStore {
        FactStore::default()
    }

    /// Number of facts.
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// No facts.
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// The fact with this id.
    pub fn get(&self, id: FactId) -> Option<&Fact> {
        self.facts.get(&id).map(|e| &e.fact)
    }

    /// Whether the fact is waiting to be recomputed.
    pub fn is_dirty(&self, id: FactId) -> Option<bool> {
        self.facts.get(&id).map(|e| e.dirty)
    }

    /// When the fact was last added or changed.
    pub fn changed_at(&self, id: FactId) -> Option<OpSeq> {
        self.facts.get(&id).map(|e| e.changed)
    }

    /// Every fact, by id.
    pub fn iter(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values().map(|e| &e.fact)
    }

    /// Every slot that holds at least one fact, in order.
    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.by_slot.keys()
    }

    /// The facts in a slot, by id.
    pub fn facts_in(&self, slot: &Slot) -> impl Iterator<Item = &Fact> {
        self.by_slot
            .get(slot)
            .into_iter()
            .flatten()
            .filter_map(|id| self.get(*id))
    }

    /// Adds a fact, or updates the fact the same pass made for the same claim.
    pub fn insert(&mut self, fact: Fact) -> Result<Inserted, StoreError> {
        let id = fact.id();
        for &input in &fact.provenance().inputs {
            if input == id {
                return Err(StoreError::Cycle(id));
            }
            if !self.facts.contains_key(&input) {
                return Err(StoreError::UnknownInput(input));
            }
        }
        let Some(old) = self.facts.get(&id) else {
            self.seq.0 += 1;
            self.link(&fact);
            self.by_slot
                .entry(fact.claim().slot())
                .or_default()
                .insert(id);
            self.facts.insert(
                id,
                Entry {
                    fact,
                    changed: self.seq,
                    dirty: false,
                },
            );
            return Ok(Inserted::Added);
        };
        if old.fact.claim() != fact.claim() || old.fact.provenance().pass != fact.provenance().pass
        {
            return Err(StoreError::IdCollision(id));
        }
        if old.fact == fact {
            if let Some(e) = self.facts.get_mut(&id) {
                e.dirty = false;
            }
            return Ok(Inserted::Unchanged);
        }
        let above = self.closure(id, |s, n| s.dependents.get(&n));
        if let Some(&bad) = fact.provenance().inputs.iter().find(|i| above.contains(i)) {
            return Err(StoreError::Cycle(bad));
        }
        let old = self.facts.remove(&id).map(|e| e.fact);
        if let Some(old) = &old {
            self.unlink(old);
        }
        self.seq.0 += 1;
        self.link(&fact);
        self.facts.insert(
            id,
            Entry {
                fact,
                changed: self.seq,
                dirty: false,
            },
        );
        let dirtied = self.mark_dirty(above);
        Ok(Inserted::Updated(dirtied))
    }

    /// Removes a fact (its pass no longer derives it, or a human undid it).
    /// Facts derived from it become dirty and keep its id in their inputs until
    /// they are recomputed. Returns the facts made dirty.
    pub fn retract(&mut self, id: FactId) -> Result<Vec<FactId>, StoreError> {
        let above = self.closure(id, |s, n| s.dependents.get(&n));
        let entry = self.facts.remove(&id).ok_or(StoreError::UnknownFact(id))?;
        self.unlink(&entry.fact);
        let slot = entry.fact.claim().slot();
        if let Some(ids) = self.by_slot.get_mut(&slot) {
            ids.remove(&id);
            if ids.is_empty() {
                self.by_slot.remove(&slot);
            }
        }
        self.seq.0 += 1;
        Ok(self.mark_dirty(above))
    }

    /// Marks a fact and everything derived from it dirty. Returns them, in id order.
    pub fn invalidate(&mut self, id: FactId) -> Result<Vec<FactId>, StoreError> {
        if !self.facts.contains_key(&id) {
            return Err(StoreError::UnknownFact(id));
        }
        let mut set = self.closure(id, |s, n| s.dependents.get(&n));
        set.insert(id);
        Ok(self.mark_dirty(set))
    }

    /// "Why?": every fact this one was built from, directly or not, in id order.
    /// Inputs that were retracted are left out.
    pub fn why(&self, id: FactId) -> Vec<FactId> {
        let inputs = |s: &FactStore, n: FactId| {
            s.facts.get(&n).map(|e| {
                e.fact
                    .provenance()
                    .inputs
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
            })
        };
        let mut seen = BTreeSet::new();
        let mut work = vec![id];
        while let Some(n) = work.pop() {
            for i in inputs(self, n).into_iter().flatten() {
                if self.facts.contains_key(&i) && seen.insert(i) {
                    work.push(i);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// "What depends on this?": every fact built from this one, in id order.
    pub fn dependents(&self, id: FactId) -> Vec<FactId> {
        self.closure(id, |s, n| s.dependents.get(&n))
            .into_iter()
            .collect()
    }

    /// Every fact with its change position and dirty flag, by id: what a cache
    /// needs to rebuild this store with [`FactStore::restore`].
    pub fn snapshot(&self) -> impl Iterator<Item = (&Fact, OpSeq, bool)> {
        self.facts.values().map(|e| (&e.fact, e.changed, e.dirty))
    }

    /// The position of the latest change.
    pub fn seq(&self) -> OpSeq {
        self.seq
    }

    /// Rebuilds a store from a snapshot. A clean fact's inputs must all be
    /// present; a dirty one may still list an input that was retracted (it is
    /// waiting to be recomputed). The same id twice, or a cycle, is refused.
    pub fn restore(
        entries: impl IntoIterator<Item = (Fact, OpSeq, bool)>,
        seq: OpSeq,
    ) -> Result<FactStore, StoreError> {
        let mut store = FactStore {
            seq,
            ..FactStore::default()
        };
        for (fact, changed, dirty) in entries {
            let id = fact.id();
            if store.facts.contains_key(&id) {
                return Err(StoreError::IdCollision(id));
            }
            store.seq = store.seq.max(changed);
            store.link(&fact);
            store
                .by_slot
                .entry(fact.claim().slot())
                .or_default()
                .insert(id);
            store.facts.insert(
                id,
                Entry {
                    fact,
                    changed,
                    dirty,
                },
            );
        }
        for e in store.facts.values() {
            for &input in &e.fact.provenance().inputs {
                if input == e.fact.id() {
                    return Err(StoreError::Cycle(input));
                }
                if !e.dirty && !store.facts.contains_key(&input) {
                    return Err(StoreError::UnknownInput(input));
                }
            }
        }
        if let Some(id) = store.find_cycle() {
            return Err(StoreError::Cycle(id));
        }
        Ok(store)
    }

    /// Applies the resolution rules of section 4.4 to one slot.
    pub fn resolve(&self, slot: &Slot) -> Resolution {
        let entries: Vec<&Entry> = self
            .by_slot
            .get(slot)
            .into_iter()
            .flatten()
            .filter_map(|id| self.facts.get(id))
            .collect();
        let rejected: BTreeMap<&Claim, &Entry> = entries
            .iter()
            .filter(|e| e.fact.status() == Status::Rejected)
            .map(|e| (e.fact.claim(), *e))
            .collect();

        // Rule 1: a rejected claim is out, whoever makes it. Then the strongest
        // fact for each remaining claim represents it.
        let mut best: BTreeMap<&Claim, &Entry> = BTreeMap::new();
        for e in &entries {
            let claim = e.fact.claim();
            if e.fact.status() == Status::Rejected || rejected.contains_key(claim) {
                continue;
            }
            let slot = best.entry(claim).or_insert(e);
            if rank(e) > rank(slot) {
                *slot = e;
            }
        }
        let mut reps: Vec<&Entry> = best.into_values().collect();
        // Rule 2 then rule 3: status first, confidence within a status.
        reps.sort_by_key(|e| std::cmp::Reverse(rank(e)));

        let (verdict, decider, used): (Verdict, Option<&Entry>, Vec<&Entry>) = match reps.first() {
            None => match rejected.values().min_by_key(|e| e.fact.id()) {
                None => (Verdict::Unknown, None, vec![]),
                Some(r) => (Verdict::Rejected(r.fact.id()), Some(*r), vec![*r]),
            },
            Some(top) => {
                let rivals: Vec<&Entry> = reps
                    .iter()
                    .copied()
                    .filter(|e| {
                        e.fact.status() == top.fact.status()
                            && top.fact.confidence().value() - e.fact.confidence().value() < TIE
                    })
                    .collect();
                if rivals.len() > 1 {
                    let ids = rivals.iter().map(|e| e.fact.id()).collect();
                    (Verdict::Conflict(ids), None, rivals)
                } else {
                    (Verdict::Accepted(top.fact.id()), Some(*top), vec![*top])
                }
            }
        };

        // Rule 4: execution contradicting a human decision is surfaced.
        let mut warnings = Vec::new();
        if let Some(d) =
            decider.filter(|d| matches!(d.fact.status(), Status::User | Status::Rejected))
        {
            for e in &entries {
                let disagrees = match d.fact.status() {
                    Status::Rejected => e.fact.claim() == d.fact.claim(),
                    _ => e.fact.claim() != d.fact.claim(),
                };
                if e.fact.status() == Status::Observed && disagrees {
                    warnings.push(Warning::ObservedContradictsUser {
                        observed: e.fact.id(),
                        user: d.fact.id(),
                    });
                }
            }
        }
        Resolution {
            verdict,
            warnings,
            stale: used.iter().any(|e| e.dirty),
        }
    }

    /// A fact on a dependency cycle, if there is one: one depth-first search
    /// over the dependency edges, linear in facts plus edges.
    fn find_cycle(&self) -> Option<FactId> {
        // 0 = not visited, 1 = on the current path, 2 = finished.
        let mut state: BTreeMap<FactId, u8> = BTreeMap::new();
        for &root in self.facts.keys() {
            if state.contains_key(&root) {
                continue;
            }
            let mut stack: Vec<(FactId, Vec<FactId>)> = vec![(root, self.next_of(root))];
            state.insert(root, 1);
            while let Some((node, rest)) = stack.last_mut() {
                match rest.pop() {
                    Some(m) => match state.get(&m).copied().unwrap_or(0) {
                        1 => return Some(m),
                        0 => {
                            state.insert(m, 1);
                            let next = self.next_of(m);
                            stack.push((m, next));
                        }
                        _ => {}
                    },
                    None => {
                        state.insert(*node, 2);
                        stack.pop();
                    }
                }
            }
        }
        None
    }

    fn next_of(&self, id: FactId) -> Vec<FactId> {
        self.dependents
            .get(&id)
            .map(|d| d.iter().copied().collect())
            .unwrap_or_default()
    }

    fn link(&mut self, fact: &Fact) {
        for &input in &fact.provenance().inputs {
            self.dependents.entry(input).or_default().insert(fact.id());
        }
    }

    fn unlink(&mut self, fact: &Fact) {
        for input in &fact.provenance().inputs {
            if let Some(d) = self.dependents.get_mut(input) {
                d.remove(&fact.id());
                if d.is_empty() {
                    self.dependents.remove(input);
                }
            }
        }
    }

    fn closure<'a>(
        &'a self,
        id: FactId,
        next: impl Fn(&'a FactStore, FactId) -> Option<&'a BTreeSet<FactId>>,
    ) -> BTreeSet<FactId> {
        let mut seen = BTreeSet::new();
        let mut work = vec![id];
        while let Some(n) = work.pop() {
            for &m in next(self, n).into_iter().flatten() {
                if seen.insert(m) {
                    work.push(m);
                }
            }
        }
        seen
    }

    fn mark_dirty(&mut self, ids: BTreeSet<FactId>) -> Vec<FactId> {
        let mut out = Vec::new();
        for id in ids {
            if let Some(e) = self.facts.get_mut(&id) {
                e.dirty = true;
                out.push(id);
            }
        }
        out
    }
}

/// Order of strength: status (rule 2), then confidence (rule 3), then the lower
/// id, so that equal facts still sort the same way on every run.
fn rank(e: &Entry) -> (Status, Confidence, std::cmp::Reverse<FactId>) {
    (
        e.fact.status(),
        e.fact.confidence(),
        std::cmp::Reverse(e.fact.id()),
    )
}
