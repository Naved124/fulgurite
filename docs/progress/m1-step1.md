# M1 step 1: the fact store

Status: **done** (2026-10-11): the fact model, the resolution rules and the dependency
graph. Persistence is step 2. Builds on
[M0 step 6](m0-step6.md).

## Goal

Everything M1 recovers (code ranges, function starts and ends, edges, no-return
functions, names) is a **fact** with a status, a confidence, a provenance and evidence
(design §4.2–§4.5, §12.1–§12.2). The functions and edges other crates show are
projections of the facts the store accepts. The M1 exit criterion "every fact has
evidence" is enforced by the type: a fact without evidence cannot be built.

## What was added

| Area | Details |
|---|---|
| `fg-facts` (new crate, layer 1) | Depends only on `fg-core` |
| `Confidence` | `f32` in `[0, 1]`; NaN and out-of-range values cannot be built; totally ordered (`-0.0` is normalised); the four display buckets; noisy-OR for independent evidence (`any_of`), weakest-link × pass for derivations (`derived`), `contradicted_by` |
| `Claim` (v1 kinds) | `IsCode`, `IsData` (half-open ranges), `IsFunction`, `FunctionEnd`, `Edge` (fall, jump, conditional taken/not taken, call, tail call, indirect), `NoReturn`, `Name` |
| `Slot` | The question a claim answers. A name slot holds one value, so different names for one address are rivals; every other kind is yes/no, and only a rejection competes with it |
| `Fact` | Built only through `Fact::new`, which refuses empty ranges, empty or control-character names, an empty pass name, no evidence, and user/rejected/observed facts below 1.0. Evidence items (`Support`) carry a kind, the `fg-core` `Evidence` (text and file span), an address anchor and a weight |
| `FactId` | 128-bit FNV-1a of the canonical claim bytes and the pass name. Stable across runs and Rust releases (not `std`'s hasher), pinned by a test against an independent computation. A pass re-deriving the same claim gets the same id, so a re-run updates instead of duplicating |
| `FactStore` | Ordered maps (deterministic output). `insert` reports `Added`, `Updated(dirtied dependents)` or `Unchanged` (and cleans a dirty fact recomputed to the same result); refuses unknown inputs, cycles (direct or through an update) and id collisions. `retract`, `invalidate`, `why` (inputs, downward), `dependents` (upward) |
| Resolution | `resolve(slot)` → `Unknown`, `Accepted(fact)`, `Rejected(rejection)` or `Conflict(facts)`, plus warnings and a `stale` flag when a fact in the verdict is dirty |

## Resolution rules as implemented (design §4.4)

1. A rejected claim is out, whoever makes it, including a user fact for the same claim:
   the rejection has to be retracted first. Rejecting one name leaves the slot open for
   other names.
2. Status first: User > Observed > Declared > Inferred. A lower status never wins on
   confidence.
3. Within the winning status, rival claims with confidences within 0.05 of the strongest
   are returned as a `Conflict`, not decided.
4. An observed fact that contradicts the user's decision (a different value, or a
   rejected claim that execution reached) is a warning; the user's decision stands.

Facts that make the same claim agree; they are not a conflict. The strongest of them
represents the claim.

## Decisions that avoid rebuilding later

1. **The subject is derived from the claim.** The design's `Fact` has a separate
   `subject`; here every claim carries its addresses and `slot()` derives the subject, so
   the two can never disagree.
2. **Invalidation marks, it does not delete.** A retracted fact's dependents stay, dirty,
   with the retracted id still in their inputs until their pass recomputes them; `why`
   skips the missing input. This is the shape the worklist (§19.1) needs.
3. **Code/data overlap is not a slot rivalry.** `IsCode` and `IsData` over overlapping
   ranges both stay (§8.5); the overlap query comes with CFG recovery (step 4).

## Verification

| Check | Result |
|---|---|
| Unit tests (`confidence`, `fact`) | Buckets at every boundary, combining rules, invalid values refused, id stability and the length prefixes that keep `("ab", "c")` apart from `("a", "bc")`, FNV-1a 128 test vector |
| `tests/store.rs` | Each resolution rule, agreeing facts, near ties, rule 4 for both a different value and a rejection, invalidation through a three-fact chain, unchanged recomputation, updates dirtying dependents, retraction, unknown inputs, direct and indirect cycles leaving the store unchanged |
| Gate | `cargo fmt`, `clippy -D warnings`, rustdoc `-D warnings`, `cargo test --workspace`, `cargo xtask layers` |

## Next in this step

Persistence and the project layout are step 2 (`fg-store`: SQLite cache, user layer as
sorted JSONL, round trip and "delete the cache, get the same facts").
