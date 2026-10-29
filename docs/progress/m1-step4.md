# M1 step 4: CFG recovery

Status: **done** (2026-10-11): recursive descent, function discovery and
`fulg functions`. What needs register tracking (jump tables, AArch64 `adrp` pairs and
PLT stubs) is step 6; no-return functions are step 5. Builds on [step 3](m1-step3.md).

## What was added

`fg-analysis::cfg::recover(bin, file, arch, mode, store)` decodes every accepted
function by following control flow, adds the functions it discovers to the store, and
repeats until nothing new is found. CFGs are rebuilt against the final set of entries,
so whether a jump is a tail call never depends on discovery order. Blocks and edges are
a projection (`Cfg`), rebuilt deterministically from the facts; only claims that need
evidence are facts.

| Source of a function | Pass | Confidence | Evidence |
|---|---|---|---|
| Direct call target | `cfg.calls` | 0.95 × caller | up to 8 call sites, with the count of the rest |
| Entry-state FDE, at its first instruction after padding | `cfg.unwind` | 0.9 | the FDE's range and the padding skipped |
| Relocated pointer (`RELATIVE`, `IRELATIVE` resolvers) or an address computed without a memory access (`lea`), landing on code no recovered function contains | `cfg.pointers` | 0.8 | the relocation's bytes, or the instruction and its function |
| Jump out of the caller's own FDE into code no FDE covers, or the jump that ends a function's entry block when that block is only a jump out: at most 2 instructions (`endbr64`/`bti` + `jmp`), or at most 4 (argument set-up + `jmp`) jumping back before the entry or forward over nothing but padding | `cfg.tailcalls` | 0.8 × caller | the jump |

An indirect jump through an import slot (ELF `JUMP_SLOT`/`GLOB_DAT` targets, PE IAT
entries) is a resolved tail call to the import (`Block::import`), not an unresolved
jump: x86 PLT stubs and PE import thunks.

A call to an import that never returns by definition (`NO_RETURN`: `abort`, `exit`,
`_exit`, `__stack_chk_fail`, `__assert_fail`, `__cxa_throw`, `_Unwind_Resume`,
`longjmp`, `pthread_exit`, `ExitProcess`...; not `error()`, which returns depending on
its arguments) ends its block: a direct call to a stub whose jump goes through such an
import's slot, or a `call [slot]`. Without it, decoding ran on past `call abort@plt`
into the next function and swallowed it (found by CI with clang 18, where `op_add`
follows such a call). The fixed-point analysis for local functions is step 5.

A signal trampoline's FDE (CIE augmentation `S`, `SeedKind::UnwindSignal`) starts one
instruction unit before the code by convention: on AArch64 a `nop`, skipped as padding;
on x86 glibc defines `pc_begin = __restore_rt - 1`, a byte that can sit inside the
padding before it, so the entry is `pc_begin + 1`.

Not functions: an FDE that starts mid-frame (a `.cold` part, or the linker's PLT FDE);
an FDE covering a whole PLT section; a call to the next instruction (the AArch64 ABI's
encoding of a call to an undefined weak function, and x86's way of reading its own
address); a call to memory that is not code (a weak undefined function linked to 0 in a
static binary); a pointer into the middle of a recovered function (computed-goto labels,
landing pads), or strictly inside any FDE's range (hand-written assembly takes the
addresses of its own labels for computed jumps; an FDE gives the real extent).

## `fulg functions`

`fulg functions FILE [--json]` (`Session::functions()` in `fg-service`): every function
with its size in decoded bytes, blocks, confidence (rounded down, so 0.9999 is never
shown as a certain 1.00) and bucket, the pass that found it, and its name (symbols,
aliases resolved to one) or the listing's label (`puts@plt`), else its strongest
evidence. Blocks ending in an unresolved indirect jump are flagged. JSON schema
`fulgurite.functions.v1`, with every piece of evidence and the split-off parts.

```
  Address               Bytes Blocks  Confidence      Found by       Name / evidence
  0x0000000000001000       27      3  0.99 Strong     seeds          _init
  0x0000000000001030        6      1  0.93 Strong     cfg.calls      strcpy@plt
  0x0000000000001060       38      1  1.00 Certain    seeds          _start
```

## Rules tried and dropped

Each was measured against symbols and removed because it was wrong:

- "An FDE reached by a jump is a split-off part": it absorbed functions reached only by
  tail calls. Replaced by the unwind state at the FDE's start.
- "A jump leaving the caller's FDE is a tail call", for any target: hand-written
  assembly has FDEs that cover only part of a function (precision fell to 74%). Now
  only targets no FDE covers.
- "A backward jump before the caller's entry is a tail call": gcc places split-off parts
  before their function when there are no unwind tables. Replaced by the thunk rule.
- "A thunk is at most two instructions": Ubuntu's gcc enables `-fcf-protection` by
  default, so a wrapper is `endbr64; add; jmp` (found by CI). A forward jump from an
  entry block is a tail call only over padding: a rotated loop's jump goes over the
  function's own blocks.
- "Any `lea` of code is a function pointer": glibc's string functions take the
  addresses of their own labels (precision fell to 95% on a static PIE). Now not inside
  any FDE's range.

## Measurements

Function starts found, on binaries with the static symbol table removed (what `strip`
does; exports stay). Ground truth: function symbols, without compiler-split `.cold`
parts (function chunks, not functions). PLT stubs are not scored.

| Binary | Functions | Recall | Precision |
|---|---|---|---|
| The `fg-analysis` test program (debug) | 13,530 | 100% | 100% |
| Rust release binaries (5) | 10,024 | 100% | 100% |
| Static glibc program, gcc `-O2` | 1,067 | 99.91% | 99.44% |
| The same, static PIE | 1,067 | 100% | 99.44% |
| Python extension, gcc and clang `-O2`, with unwind tables | 129 | 100% | 100% |
| The same without unwind tables | 129 | 100% | 100% |
| Test C program (`tests/cfg.rs`), gcc and clang, PIE and shared, with and without unwind tables | 12–17 | 100% except below | 100% |

Without the pointer rule, clang `-O2` without unwind tables found 5.4% of the Python
extension's functions: most are reached only through tables of pointers.

Known gaps, each pinned by a test or listed here:

- clang without unwind tables: a function called only from a `switch` case reached
  through a jump table (step 6).
- Static glibc (non-PIE): `register_tm_clones` (older `crtstuff`, reached by a backward
  jump from a function that is not a thunk). Six `.cold` parts of frameless functions
  are found as functions, because their unwind state at the start is an entry state,
  exactly like a tail-called function's; telling them apart needs no-return analysis
  (they end in `abort`). Fixed in [step 5](m1-step5.md).
- AArch64: `adrp` + `add` address computations and PLT stubs (`adrp`/`ldr`/`br x17`)
  need register tracking (step 6); the stubs are found and named, but flagged as
  unresolved jumps.

## Verification

| Check | Result |
|---|---|
| `fg-analysis/tests/cfg.rs` | The test program itself: every function found, no extra. A C program with a pointer table, a cold path, a tail call, a thunk and static functions, built with gcc and clang at `-O2 -fcf-protection=full` as PIE and shared library, with and without unwind tables: every function found, no extra, except the jump-table case above (allowed by name: only recent clang emits that jump table). No function's blocks run over another function's entry; every recovered function is an accepted fact with evidence; a second run adds nothing; the cache round trip changes nothing |
| `fg-cli/tests/functions.rs` | `fulg functions` on the `fulg` executable: JSON schema, every function with evidence and a confidence in range, `main` found from its symbol, the text listing's count |
| `fg-loader/tests/oracle.rs` | Signal-trampoline FDEs start exactly one byte before a function symbol |
| `examples/recall.rs` | The measurement tool behind the table: `cargo run --release -p fg-analysis --example recall -- FILE...` (`VERBOSE=1` lists misses and extras with the evidence) |
