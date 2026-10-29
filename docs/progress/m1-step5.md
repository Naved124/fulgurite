# M1 step 5: no-return analysis

Status: **done** (2026-10-11). Builds on [step 4](m1-step4.md).

## What was added

A call to a function that never returns ends its block, so the bytes after it are not
decoded as a fall-through (design §8.4). Step 4 knew only the imports that never return
by definition (`NO_RETURN`). Now functions of the binary itself are proven no-return too
(`abort`, `exit`, `__stack_chk_fail` and `__assert_fail` in a static binary, a
program's own `die()`), as `NoReturn` facts with evidence (`cfg.noreturn`).

A function never returns when no path from its entry reaches a return. Every path has to
end in one of these:

- a call or tail call to a function that never returns;
- a call through the import slot of one;
- a trap (`ud2`, `hlt`, `brk`, `udf`);
- a loop with no exit (no path reaches a return or leaves the function).

Anything not understood may return:

- an unresolved indirect jump;
- bytes that do not decode;
- a tail call to an import not in the list.

A wrong no-return claim would hide the code after every call to the function, so unknowns
never count as an end.

It is a fixed point that grows from the import list. Each function proven no-return cuts
its callers' paths: their CFGs are rebuilt and checked again within the same stage,
until nothing more is proven. The stage order in each round is:

1. call targets;
2. no-return;
3. FDE promotion;
4. pointers;
5. tail calls.

So a function is never judged on a call graph that is still growing. A `NoReturn` fact
depends on its function's `IsFunction` fact and on the `NoReturn` facts it relies on, so
invalidating any of them marks it dirty through the dependency graph. Facts already made
are not recomputed: a second run on the cached store adds and changes nothing.

| Fact | Pass | Confidence | Evidence |
|---|---|---|---|
| `NoReturn` | `cfg.noreturn` | 0.95 × the weakest of the function's own fact and the facts relied on | how each path ends, up to 8 (`0x403703 calls 0x406620, which never returns`, `0x402e65 traps`, `0x401371 runs on into 0x401376, which never returns`) |

### Split-off parts that start like functions

An FDE that starts mid-frame is a `.cold` part and was already left out in step 4. In a
function with no frame at the jump, however, the split-off part's FDE starts in an entry
state, exactly like a tail-called function's. glibc has six of these: `get_reg.cold`-style
`push rbp; mov rbp, rsp; call abort` and a lone `ud2`. They were the remaining false
functions in step 4.

They are told apart by what they do. Such a part:

- never returns;
- is reached by a jump from exactly one other function;
- has nothing falling into it.

Compilers do not tail-call a function that never returns: the call is followed by
`unreachable`, not a return, so it is not in tail position. A jump to code that never
returns is a branch to the jumping function's own cold path. The part is listed as a
fragment of that function. A function shaped the same way that is *called*
(`detach_arena.part.0`, `ryu::pow5bits.part.0`) stays a function.

### Calls that are not calls

- **Retpolines.** A call followed by a speculation capture loop (`pause` and `lfence`
  only, jumping back into itself) is a retpoline: the call only pushes a return address
  that its target overwrites. The target is the thunk's own code, not a function, and the
  thunk returns through it. Without this, gcc's `__x86_indirect_thunk_*` was proven
  no-return, which hid the code after every indirect call, and its internal label was
  reported as a function.
- **Calls into the function's own code.** A call to a label inside the calling function,
  or right after its last block, is a stack trick. glibc's `__push___start_context`
  switches stacks and returns from the callee, so the code after the call is not where it
  returns. Such a function may return.
- **A call to the next instruction where a function starts.** This one is a call. glibc's
  static `_dl_start` is only `call abort`, and `abort` follows it. Step 4 ignored every
  call to the next instruction: the AArch64 weak-undefined `bl` and the x86 get-PC idiom
  are still ignored when no function starts there.

## `fulg functions`

Functions that never return are marked `[no return]`, and the summary line counts them.
The JSON (`fulgurite.functions.v1`) gains `no_return`: how each path ends, empty if the
function may return.

## Measurements

Function starts, measured as in step 4: static symbol table removed, ground truth from
it, `.cold` parts and PLT stubs not scored.

| Binary | Functions | Recall | Precision (step 4) | Precision | No-return |
|---|---|---|---|---|---|
| The `fg-analysis` test program (debug) | 20,629 | 100% | 100% | 100% | 31 |
| Static glibc program, gcc `-O2` | 1,067 | 99.91% | 99.44% | **100%** | 23 |
| The same, static PIE | 1,067 | 100% | 99.44% | **100%** | 23 |
| Python extension, gcc and clang, with and without unwind tables | 129 | 100% | 100% | 100% | 2–3 |
| Test C program with retpolines, gcc | 21 | 100% | 95.45% | **100%** | 6 |
| The same, clang | 17 | 94.12% | 100% | 100% | 6 |

Every no-return claim was checked by hand against the code:

- Static glibc: all 23. Each is declared `noreturn` in glibc or ends in one:
  - `abort`, `exit`, `_exit`, `__libc_start_main`, `__libc_fatal`, `malloc_printerr`;
  - `_dl_signal_error`, `_dl_reloc_bad_type` and the rest.
- System `libc.so.6`: all 45 (stripped static functions named from objdump).
- System `libstdc++.so.6`, 110 claims: a sample including every name that is not an
  obvious throw, abort or terminate. These include `__throw_*`, `__glibcxx_assert_fail`
  and the `.part.0` clones that call it.

The self-check found one false claim, `__push___start_context`. It led to the
calls-into-itself rule above; the retpoline case was then found by building it.

Cost: recovery on the 20,629-function test program takes 3.1 s instead of 2.7 s (7
rounds instead of 5). Proofs iterate within the stage, rebuilding only the callers of
what was just proven, rather than one round per link of a no-return chain (18 rounds,
5.8 s).

## Known gaps

- A call target found before its caller's earlier call was proven no-return keeps its
  fact: it was decoded after that call. Eight cases were measured in five binaries
  (`STALE=1 cargo run --example recall`). All eight are real functions
  (`_Unwind_Resume`, `cancel_handler`, `print_select_list`, `_Dir::~_Dir`...), most of
  them called from exception landing pads. Landing pads are reached through the
  exception tables (LSDA), which are not parsed yet.
- A no-return proof through a GOT slot of a function the binary itself defines (a
  `GLOB_DAT` to its own export, like libstdc++'s `__glibcxx_assert_fail`) does not see
  the definition. The call is treated as returning, which is safe but finds fewer
  no-return functions. Resolved in [step 6](m1-step6.md).
- Stack tricks are recognised by shape, not by tracking the stack pointer (register
  operands are step 6). A function that switches stacks without calling into its own
  code is not recognised.
- clang's retpoline thunk is not found when nothing references it (clang compiled the
  only indirect call to compares). No FDE covers it, and finding it would take a linear
  sweep.
- The evidence of a fact made early stays as it was made. `_start`'s says `traps` (the
  `hlt`), because it was proven before `__libc_start_main` was. Both are true.

## Verification

| Check | Result |
|---|---|
| `fg-analysis/tests/cfg.rs` | The C program gains `die` (through `exit`), `give_up` (through `die`), `spin` (a loop with no exit), and a frameless `get_reg` whose cold path gcc splits off under an entry-state FDE. It is built with gcc and clang as PIE and shared library: with and without unwind tables, and with retpolines (`-mindirect-branch=thunk`, `-mretpoline`). In all 12 builds the no-return functions are exactly `die`, `give_up`, `spin` and, in executables, `_start`; no extra functions. Disabling the retpoline rule fails it (an extra function at the thunk's label), and so does disabling the split-off rule (`get_reg.cold` as a function) |
| `fg-cli/tests/functions.rs` | `fulg functions` on itself: some functions never return (Rust's panic path), `main` returns, and the summary line counts them |
| `examples/recall.rs` | `NORETURN=1` lists the no-return functions, `STALE=1` the call targets whose calls are no longer decoded, `DUMP=ADDR` one function's blocks |
