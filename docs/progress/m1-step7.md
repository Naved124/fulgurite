# M1 step 7: cross-references

Status: **done** (2026-10-14). Builds on [step 6](m1-step6.md).

## What was added

### The pass

`fg-analysis::xrefs::collect(bin, file, arch, mode, cfg)` lists every reference the
recovered code and the file's data make (design §4.1 `Xref`). Like the CFG, it is a
projection of the accepted facts, not facts of its own:

- only the instructions of recovered blocks are read, so every reference comes from
  bytes accepted as code;
- a data word counts only where a relocation says it holds a pointer.

Each reference has a source (`from`), a target (`to`), the function it is in, a kind
and how it was found:

| Kind | Meaning |
|---|---|
| `call`, `jump`, `branch`, `tail call` | Control flow, as the CFG resolved it |
| `table` | An entry of the jump table read at an indirect jump |
| `read`, `write`, `read/write` | A memory access |
| `address` | The address is computed or loaded as a value (`lea`, `adrp` + `add`, `mov edi, offset s`) |
| `pointer` | A data word holds the address |

| How | Meaning |
|---|---|
| operand | The instruction's own operand: a direct target, a PC-relative or absolute address, or an absolute array start indexed by a register (`call [8*rax + table]`) |
| immediate | An immediate a relocation patches (PE base relocations, text relocations), or, in a file loaded at a fixed address, one that lands in the file |
| register built by earlier instructions | `adrp` + `add`/`ldr`/`str`, the GOT pointer of 32-bit PIC code, a table base read at an index |
| through the pointer at *p* | A call or jump through a GOT slot holding this file's function, or an access through a register loaded from a relocated pointer (`mov rax, [rip + x@GOTPCREL]; mov [rax], edi`) |
| jump table entry | An entry of the table at this jump |
| relocated data word | A pointer-sized word a load-time relocation fills (`RELATIVE`, PE base relocations, `GLOB_DAT`/absolute relocations of the file's own symbols) |
| data word | In a file loaded at a fixed address without relocations: an aligned word holding a recovered function's entry |

Some references are guesses, and are marked so (`certain: false`):

- immediates and data words in a file loaded at a fixed address, which may be numbers;
- accesses through a pointer in writable memory, which give its first value only (the
  rule step 6 applied to writable jump tables).

A named data symbol with a size covers its whole extent (`xrefs table` lists `table+0x18`
too). A function name covers its entry only, so its own branches are not listed.

### What the pass needed below it

- **`Arch::mem_addr`:** the address of an instruction's memory operand (base, index,
  displacement) and its access, for any access, stores included.
  - x86: from the decoder's operand.
  - AArch64: from the encoding's fields. Covered: unsigned scaled, unscaled, pre- and
    post-indexed, register-offset (with extension and shift), pairs (a Q register
    scales by 16), literal, exclusive, ordered and atomic forms.
- **`Effect::Call`:** an indirect call says where it goes (x86 `call r/m`, AArch64
  `blr`), as an indirect jump did.
- **`call next; pop r`** (clang's 32-bit PIC) no longer clobbers every register. The
  tracker learns `r` once the `pop` runs (`Tracker::assume_after_next`). Before, every
  global access in clang-built 32-bit PIC code was lost.
- **`Relocation::applied_at_load`:** a file linked with `--emit-relocs` keeps its
  link-time relocations (`.rela.text`, `.rela.rodata`), which the linker already
  applied. Step 6 took them for dynamic ones, so it would not read a jump table whose
  entries a link-time relocation had filled: `classify`'s switch stayed unresolved in
  such builds. Only load-time relocations now count, in the CFG, the xref pass and the
  listing's import slots. Files without such tables are unchanged: the CFG of the five
  measurement binaries is identical before and after.

### Service and CLI

`Session::xrefs(target)` and `fulg xrefs FILE [NAME | 0xADDR] [--json]`:

```text
$ fulg xrefs a.out counter
3 references to 0x4034 counter (4 bytes: references anywhere inside)
  From                                     Kind       To                                       How
  0x1053 main+0x3                          read/write 0x4034 counter                           operand
  0x106e main+0x1e                         read       0x4034 counter                           operand
  0x107a main+0x2a                         read       0x4034 counter                           operand
```

Without a target it lists every reference in the file.

## Measurements

**Against the linker's own record.** A program linked with `--emit-relocs` keeps its
code relocations, and each says which instruction refers to which address. The C test
program of step 4 is built 6 ways:
- gcc and clang;
- PIE, shared library, and loaded at a fixed address.

| Build | Relocated instructions | Reached | With a reference | Targets right | Data references without a relocation |
|---|---|---|---|---|---|
| gcc PIE | 55 | 55 | 55 | 31 / 31 | 0 |
| gcc shared library | 54 | 54 | 54 | 26 / 26 | 0 |
| gcc fixed address | 54 | 54 | 54 | 32 / 32 | 0 |
| clang PIE | 49 | 49 | 49 | 20 / 20 | 0 |
| clang shared library | 47 | 47 | 47 | 19 / 19 | 0 |
| clang fixed address | 48 | 48 | 48 | 26 / 26 | 0 |
| AArch64 PIE (clang, `rust-lld`) | 16 | 16 | 16 | 6 / 6 | 0 |
| AArch64 fixed address | 16 | 16 | 16 | 6 / 6 | 0 |
| 32-bit PIC library, gcc (thunk) | 10 | 10 | 10 | — | 0 |
| 32-bit PIC library, clang (`call next; pop`) | 7 | 7 | 7 | — | 0 |

How the columns are checked:
- **Targets right:** the target is checked where it can be computed: PC-relative and
  absolute relocations against a defined symbol, and on AArch64 the low-12-bits half of
  an `adrp` pair, which gives the whole address.
- **PLT stubs:** a call that a shared library routes through a PLT stub (an exported
  function may be replaced by another file) counts as right.
- **Not checked:** `adrp`'s own page relocations (the pair's other half carries the
  reference), and i386 targets: `REL` relocations keep their addend in bytes the linker
  has already overwritten.
- **Last column:** every data reference that leaves `.text` must come from a relocated
  instruction. A register-built reference counts if the same function's relocated
  instruction refers to the same target. One through a pointer counts if a relocated
  instruction read that pointer.

**Larger binaries:**

| Binary | References | Guesses | `fulg functions` | `fulg xrefs --json` |
|---|---|---|---|---|
| Static glibc program, gcc `-O2` | 25,971 | 316 | 0.28 s | 0.34 s |
| System `libc.so.6` | 81,992 | 4 | 1.46 s | 1.72 s |
| System `libstdc++.so.6` | 91,438 | 1 | 1.29 s | 1.58 s |
| The `fg-analysis` test program (debug, 23,328 functions) | 322,829 | 0 | 2.89 s | 4.06 s |

The xref times include CFG recovery and writing the JSON.

**By hand.** Nine of libc's register-built and pointer references were picked at random
and checked against objdump; all nine are right:
- `printf`'s `jump_table`, read at an index;
- `_tens_in_limb`;
- two jump-table bases;
- an array of structures written at a field;
- `_res_hconf` and `_nl_domain_bindings` written through their GOT entries;
- two strings reached through `_nl_C_LC_TIME`'s pointers.

## Known gaps

- **Values are followed within a block only.** An `adrp` in one block and its `ldr` in a
  successor, or a GOT pointer set before a branch, give no reference. Compilers keep
  pairs together, but not always.
- **Data words in a file loaded at a fixed address** count only when they hold a
  recovered function's entry. Pointers to strings and other data in a non-PIE `.data`
  are missed: with no relocation to say so, a word is as likely a number.
- **Code the CFG does not reach** makes no references.
- **Not described:** segment-based operands (`fs:`), vector-indexed (gather) operands,
  AArch64 SIMD structure loads, tag and pointer-authenticated accesses.
- **The listing does not show references yet.** `fulg disasm` could print who refers
  to a label.
- **Recomputed each time.** References are a projection with their reason, not facts
  in the store: the store would gain a million rows for libc.

## Verification

| Check | Result |
|---|---|
| `fg-analysis/tests/xrefs.rs` | The relocation oracle above: x86-64 (6 builds), AArch64 (2) and 32-bit PIC (2), with `counter`'s read and write and `table`'s read found in the 32-bit libraries |
| `fg-arch-x86/tests/decode.rs` | `call rax` and `call [8*rax + table]` say where they go, a direct call does not; `mem_addr` of a RIP-relative store (and its access), an absolute array indexed by a register, a 32-bit `[ebx + 0x20]`; none for a register operand or an `fs:` one |
| `fg-arch-arm64/tests/effects.rs` | `blr x8` is a call; `mem_addr` and the access of every addressing form listed above, each encoding taken from `llvm-mc` |
| `fg-cli/tests/xrefs.rs` | `fulg xrefs` on itself: `_start` takes `main`'s address; the same by name and by address, as JSON and as text; an unknown name fails |
| `fg-analysis/tests/cfg.rs` | Unchanged; its C and AArch64 sources moved to `tests/data/` and are shared with the xref tests |
| Full gate | fmt, clippy (`-D warnings`), docs, layers, 216 tests |
