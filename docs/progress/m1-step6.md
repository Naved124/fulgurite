# M1 step 6: jump tables and register values

Status: **done** (2026-10-11). Builds on [step 5](m1-step5.md).

## What was added

### What an instruction does to registers

`fg-ir` gains `Effect`: what one instruction does to registers and flags, in the forms
M1 follows a value through. It covers:

- moves and loads, with their zero or sign extension (`mov`, `movzx`, `movsxd`, `lea`);
- `add`, `sub`, `and` and `shl`;
- compares and the conditional branches on them;
- indirect jumps and their targets.

Every other instruction is `Other`, with the registers it may write, so a value is never
carried across an instruction that changes it. `Arch::effect` computes it on demand
(few instructions are ever asked), so `Insn` is unchanged. `Arch::callee_saved` gives
the registers a call preserves:

- System V x86-64: `rbx`, `rbp`, `r12`–`r15`;
- Microsoft x64: also `rsi` and `rdi`;
- 32-bit x86: `ebx`, `esi`, `edi` and `ebp`;
- AArch64: `x19`–`x29` and `sp`.

On AArch64 the effects are read from the encoding's fields, for the forms tables and
address pairs use:

- `adrp`, `adr`;
- `add`/`sub`/`adds`/`subs`/`cmp` in their immediate, shifted and extended forms
  (`add x0, x0, w1, sxtb #2`);
- `movz`, `movn`, `mov`;
- loads with an immediate, register (`ldrb w1, [x1, w0, uxtw]`), unscaled or literal
  address;
- `b.cond`, `br`.

Every other instruction of the base integer, load/store, branch, system and SIMD&FP
classes says which general registers it may write (the destination, a pair's second
register, a writeback base). Anything else (SVE, SME, atomics) may write any register.

M2's lifter supersedes both.

### Following a value along a path

`fg-analysis::track` follows register values symbolically along one path. Every
register starts as its unknown value at the path's start; each effect rewrites the
registers it writes as expressions over those.

A compare followed by the way the path leaves the branch bounds an *expression*, not a
register. `cmp eax, 7; ja default` on the not-taken path bounds `low32(rax)`, and the
bound still holds after the value is copied, zero-extended, or carried in a callee-saved
register across a call. An `and` with a low mask (`and ebx, 3`) is a bound in itself.

An indirect jump's target is then an expression too. When its only unknown is a bounded
expression, the table is read by evaluating the target for every value the bound
allows. Nothing is assumed about the compiler's layout: all of these are the same
evaluation:

- gcc's and clang's position-independent tables (`movsxd rax, [rdx+rax*4]; add rax, rdx`);
- absolute tables (`jmp [8*rax+table]`);
- a table whose index was bounded before a call.

### Jump tables

The path into an indirect jump runs back through every block with a single predecessor,
up to 8 blocks. The table is read exactly first. If that fails, it is read again with
two things relaxed:

- **Integer constants are forgotten.** A register set by `mov r, imm` becomes
  unknown, while addresses (`lea`, `adrp`) stay known. The only path known into a jump
  may be a loop's first iteration, where the index is a constant (clang's `table[i % 4]`
  with `i = 1`), before the cases that loop back are found.
- **Facts from before the path count.** What holds on every way into its first block
  carries over, computed by a forward pass to a fixed point over the function: the
  same address (a table's base loaded before a loop), or a value that fits in fewer
  bits (an index written as 32 bits, so `cmp ebx, 45` bounds `rbx`).

Every entry must be aligned code of this file, or none is taken. A table is read only
from memory that is not writable, and not where a relocation with an explicit addend
writes (the file's bytes there are not what the program reads). At most 4,096 entries
are read.

Each target becomes an `Edge` fact (`cfg.tables`). Its confidence is 0.95 × the
function's. Its evidence names:

- the entries that lead to the target;
- the table's address, entry count and entry size;
- the bound and the instruction that proves it (`entries 0, 3 of the jump table at
  ADDR (8 entries of 4 bytes); the index is at most 7, by ADDR`).

The stage runs right after call targets, so no-return proofs see the cases (an
unresolved jump means "may return"). The cases' code is then inside the function, so
it is never taken for functions through the pointer stages.

### Slots that hold the file's own functions

A call or jump through a slot that holds one of the file's own functions is a call or
tail call to that function. Such a slot is either:

- a `RELATIVE` GOT entry;
- a library's `GLOB_DAT` or `JUMP_SLOT` entry for a symbol it defines itself.

Rust calls other crates' functions this way (`call [rip+GOT]`), and libstdc++ calls its
own `__glibcxx_assert_fail` and `__throw_*` this way. Before this change those calls
were unknown:

- Their targets were not found as call targets.
- No-return proofs did not see them (a gap of step 5).

The fact's evidence says `called through the slot at …` or `jumped to through the slot
at …`.

A jump through an `IRELATIVE` slot (static glibc's `jmp [memcpy's GOT entry]`, filled by
an IFUNC resolver) is a tail call out of the function, as through an import's slot.

### AArch64 address pairs and PLT stubs

AArch64 builds an address from two instructions: `adrp` gives the 4 KiB page and an
`add` or a load's offset the rest. While a block is decoded, its register values are
followed with the same tracker:

- An `add` that produces an address in code is an address taken (`adrp x0, f; add x0,
  x0, :lo12:f`). The page alone is not taken for an address.
- A `br` or `blr` through a register loaded from a constant address goes through that
  slot. A PLT stub's `adrp x16, page; ldr x17, [x16, #off]; br x17` is a tail call to
  the import, as an x86 stub's `jmp [rip+slot]` is, so a call to `abort@plt` ends its
  block.

### Files loaded at a fixed address

A non-PIE executable keeps code addresses without relocations, so step 4's pointer
sources missed them: in the C test program built `-no-pie` without unwind tables, 9 of
25 functions were found. Two sources are added, both only for an ELF `ET_EXEC` file and
only for values of at least 0x10000:

- An immediate that lands in code is an address taken (`mov edi, offset main` in
  `_start`).
- An aligned word of data that holds the address of code starting with a clean
  instruction (not padding, not a trap) is a pointer (a table of function pointers).
  This is the weakest source. It runs last, after every other stage has settled, so a
  jump table's entries are already inside its function and not taken for functions. A
  word a relocation writes is skipped: a GOT entry holds the PLT's lazy-binding
  address until its import is bound.

### Calls to the function that follows

Step 5 treats a call to the code right after a function's own as a stack trick
(`__push___start_context`), so the function may return. That also caught ordinary
calls to the next function: AArch64 `_start` calling `classify`, which starts where
`_start` ends. A call target known as a function from more than this caller's calls
is now an ordinary call. That means a symbol, an entry-state FDE starting there, or
callers elsewhere. Without such evidence the step 5 rule still applies, which keeps
`__push___start_context` "may return" (the label it calls becomes a function only
through that call).

## Measurements

Function starts as in step 4 (static symbol table removed, ground truth from it,
`.cold` parts and PLT stubs not scored).

| Binary | Recall | Precision | Jump tables | Unresolved jumps | No-return (step 5) | Time (step 5) |
|---|---|---|---|---|---|---|
| Static glibc program, gcc `-O2` | 99.91% | 100% | 53 | 76 | 23 (23) | 0.41 s (0.26 s) |
| The same, static PIE | 100% | 100% | 55 | 78 | 23 (23) | 0.42 s (0.25 s) |
| The `fg-analysis` test program (debug, 22,177 functions) | 100% | 100% | 87 | 260 | 119 (31) | 4.3 s (3.7 s) |
| System `libc.so.6` | — | — | 105 | 183 | 46 (45) | 1.73 s (0.94 s) |
| System `libstdc++.so.6` | — | — | 76 | 276 | 124 (110) | 1.40 s (1.00 s) |

The system libraries have no static symbol table, so recall and precision are not
measured there.

What the step changed:

- **The Rust test program.** Unresolved jumps fell from 561 to 260, and no-return
  functions grew from 31 to 119, all panics, aborts, exits and the guards that abort.
  Rust calls other crates' functions through the GOT, so the panic paths were invisible
  before. All 119 were checked by name: one `NonZero::new_unchecked::precondition_check`
  is listed, and its code has no compare at all (the instance that always fails); the
  three that compare are not listed.
- **libstdc++.** 18 fewer functions: each was a split-off cold part (`push rbp; …; call
  __throw_logic_error`) that step 5 promoted. Its call through a GOT slot now proves it
  never returns, so the split-off rule applies (fragments 357 → 381).
- **Static glibc.** The table entries of libgcc's `read_encoded_value_with_base` land
  in its `.cold` part, so the split-off rule counts a table entry as a jump.

What is left unresolved in static glibc, by kind:

- jumps through function pointers (`_IO_*` vtables, `__tunable_get_val`'s callback,
  `__longjmp`);
- hand-written string functions;
- the cases listed under known gaps.

## Follow-up: the gaps closed after the step

- **Tables in `.data.rel.ro`** (inside `PT_GNU_RELRO`) are read, through the addends of
  their `RELATIVE` relocations. **Tables in writable memory** are read as the file
  starts them, and their edges get confidence 0.4 instead of 0.95; the fact says so.
- **Wrapped lower bounds.** A register holding `low(a + k)` with `a ≥ n` and
  `n + k ≡ 0` mod 2^width is at most `k − 1`: gcc's `cmp edx, -8; jb default;
  lea eax, [rdx+8]`. glibc's `mallopt` is resolved.
- **32-bit PIC.** A call to a PC thunk (`mov reg, [sp]; ret`) sets that register to the
  return address. No 32-bit build is tested yet.
- **Edges are checked again.** Before a new table is accepted, the function is built
  again with its cases in place and the table read again; it must read the same
  targets. Each round, every accepted table is read again on the current CFG, and its
  edges are retracted if it no longer reads the same.
- **Cost.** Call targets and jump tables are found in the same round (static glibc:
  26 → 18 rounds; libc.so.6: 1.9 s → 1.7 s).

| Binary | Jump tables | Unresolved jumps | No-return |
|---|---|---|---|
| Static glibc program | 53 | 76 | 23 |
| The same, static PIE | 55 | 78 | 23 |
| The `fg-analysis` test program | 84 (87) | 260 (260) | 119 |
| System `libc.so.6` | 104 (105) | 184 (183) | 45 (46) |
| System `libstdc++.so.6` | 76 | 276 | 124 |

In brackets: the numbers above, where they changed. libc gains `mallopt` and
`_authenticate`, and loses three tables to the stricter check (next section).
`__spawni_child`, whose table is one of them, is no longer proven not to return.

## Known gaps

- **The check rejects some true tables.** Read again with its cases in place, a table
  whose cases jump back to a loop head before the bound check loses a value set before
  that loop: `_nl_intern_locale_data` (the index is a copy of the bounded register, made
  before the loop), `__spawni_child` (the table's address), `peek_token`. Values are not
  carried through merges, only constants and addresses. The check never accepts a wrong
  target; it only drops these.
- **A no-return function calling the function right after it**, with nothing but that
  call to say the callee is a function (no symbol, no FDE), may return.
- **Computed gotos** indexed through another table, with the bound before a merge
  (`printf_positional`): bounds are not carried through merges either.
- **Writable tables** may change at run time; their edges are the initial values only.

## Verification

| Check | Result |
|---|---|
| `fg-arch-x86/tests/decode.rs` | Effects of the table idioms (`lea`, `movsxd` from `[rdx+rax*4]`, `add`, `jmp rax`, `jmp [8*rax+T]`), zero and sign extensions (`mov eax, eax`, `movzx`, `cdqe`), `sub` as a compare, `cmp` with a negative immediate at 32 bits, the branch conditions, and what anything else writes (`xor`, `loop`, a store, `mov ah`, a `fs:` load, a call, a direct jump). Every instruction of the opcode sweeps has an effect without panicking |
| `fg-analysis` `track` unit tests | A relative table read for every index the bound allows; a bound on `edi` does not bound `rdi`; each branch direction and condition; a zero-extending move keeps the bound and a clobber loses it; an `and` mask bounds; a bound in a callee-saved register survives a call and one in a scratch register does not; an unreadable entry fails the table |
| `fg-arch-arm64/tests/effects.rs` | The effects of gcc's AArch64 table (`cmp`, `b.hi`, `adrp`, `add`, `ldrb` with `uxtw`, `adr`, `add` with `sxtb #2`, `br`), loads with a shifted register and a PLT stub's `ldr x17`, `mov`, `movz`, `mov x0, sp`, `subs` as a compare, the conditions; what anything else writes (`stp` and `ldp` with writeback, `str`, `mul`, `tst`, `fcmp`, a SIMD add, an SVE add); every word of a sweep has an effect. Every encoding used was checked against `llvm-mc` |
| `fg-analysis/tests/cfg.rs`, AArch64 | A freestanding AArch64 program compiled by clang and linked by `rust-lld` (the linker that ships with Rust) against a shared library, as PIE and at a fixed address, with and without unwind tables. Every function is found and none extra; the 14-case switch's table is read; every jump is resolved, the PLT stubs' included; `die` (which calls `abort` through the PLT) never returns, and `_start` with unwind tables (see the gap above). Disabling the PLT slot resolution fails it |
| `fg-analysis/tests/cfg.rs` | The C program gains a dense `switch` with different code in each case, one of which calls a function reached only through it. It is built 18 ways: gcc and clang, PIE, shared library and non-PIE, with and without unwind tables and with retpolines. In every build, every indirect jump is resolved except crt's `(de)register_tm_clones`, which jump through a pointer read at run time; the switch has 8 targets. Every function is found, none extra (the only exception, as in step 5, is clang's unreferenced retpoline thunk). clang's `table[i % 4]` loop, which step 4 allowed to miss `reverse`, is now resolved (bounded by `and ebx, 3` before a call to `strtol`) |
| `examples/recall.rs` | Prints the jump tables and unresolved jumps; `UNRESOLVED=1` lists the unresolved jumps by function |
