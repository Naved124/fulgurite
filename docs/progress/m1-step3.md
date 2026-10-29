# M1 step 3: seeds

Status: **done** (2026-10-11). Builds on [step 1](m1-step1.md). (Step 2, persistence,
waits for the SQLite dependency to be approved; nothing here depends on it.)

## What was added so far

| Area | Details |
|---|---|
| `.eh_frame` (`fg-loader/src/elf/ehframe.rs`) | Found the way the run time finds it: `PT_GNU_EH_FRAME` → `.eh_frame_hdr` → `eh_frame_ptr`, with the `.eh_frame` section as the fallback, so it works on files without section headers. CIEs of version 1, 3 and 4, augmentations `z`, `R`, `L`, `P`, `S`, `B`, `G` (unknown letters skipped with `z`'s length), 32- and 64-bit record lengths, every `DW_EH_PE_*` value format, absolute, PC-relative and (in the header) data-relative pointers, 32-bit address wrapping. Each FDE in executable memory becomes a `SeedKind::UnwindTable` seed with its end address |
| Mid-frame FDEs | An FDE whose call-frame instructions change the unwind state before the first `DW_CFA_advance_loc` starts in the middle of a frame: `SeedKind::UnwindFragment`. In the test binaries all 145 are compiler-split `.cold` parts or the linker's PLT FDE (PLT0 pushes before jumping). Signal-handler trampolines (CIE augmentation `S`) are `SeedKind::UnwindSignal`: their state at the start is the interrupted code's by design, and their range starts one instruction unit early |
| Cross-check | The `.eh_frame_hdr` lookup table, which the run-time unwinder actually uses, is checked against the FDEs: an entry whose FDE is missing or starts elsewhere, and an FDE missing from the table (the unwinder cannot see it) are reported |
| Anomalies | `elf.eh_frame.truncated`, `.bad_cie`, `.bad_cie_pointer`, `.bad_pointer`, `.range_overflow`, `.outside_code`, `.unmapped`; `elf.eh_frame_hdr.bad`, `.mismatch`, `.unlisted_fde`. One anomaly per kind of damage, with the first location and a count, so a damaged table cannot flood the report |
| Hostile input | Every read is bounds-checked; LEB128 longer than 10 bytes or overflowing 64 bits is refused; at most 2^22 records; a CIE that cannot be parsed makes its FDEs untrusted rather than guessed |
| `fulg seeds` | Lists the FDE seeds (`.eh_frame`) |
| `fg-analysis` (new crate, layer 3) | Home of M1's passes. `seeds::seed_facts` / `add_seed_facts`: everything the file declares about code, as `Declared` facts with the declaring bytes as evidence (table below) |

## The seed pass

| Source | Facts | Weight |
|---|---|---|
| Entry point | `IsFunction` | 1.0 |
| Defined function symbols (ELF, COFF), PE exports in executable memory that are not forwarded | `IsFunction`, `IsCode` when the size is known, `Name` | 0.98 |
| PE exception table | `IsFunction`, `IsCode` | 0.97 |
| `.eh_frame` FDEs, PE exception-table fragments | `IsCode` only | 0.97 |
| `DT_INIT`/`DT_FINI`, init/fini/preinit arrays, TLS callbacks, CFG targets, SafeSEH handlers | `IsFunction` | 0.95 |

- One fact per claim: when the entry point, a symbol and an FDE all say the same thing,
  their evidence is listed together and combined by noisy-OR (§12.2).
- **Aliases** (`malloc` / `__libc_malloc`) give one `Name` fact, not a conflict: the
  name is chosen by exported or global binding, then fewer leading underscores, then
  length, then alphabetically (never table order); every alias stays in the evidence
  as "also named".
- An IFUNC symbol's address is its resolver: it is a function, but it is not named after
  the function it resolves.
- Names a fact cannot hold (control characters, which only a hostile file has) are left
  out instead of failing the pass.
- This is a deliberate refinement of §8.2, which lists FDEs as function seeds: here they
  are code ranges, and step 4 promotes the ones that are entries.

## An FDE is a code range, not always a function

Checking every FDE seed against the symbol table of the test binaries found three
cases where an FDE does not start at a function, all legitimate:

| Case | Example |
|---|---|
| The linker's FDE for a whole PLT section | `.plt` 0x1020..0x1060, `.plt.sec` 0x1060..0x1090 |
| Alignment padding inside the CFI region of hand-written assembly | `_dl_tlsdesc_undefweak`: the FDE starts at the 7-byte `nopl` before it |
| glibc's `__restore_rt`: the FDE starts one byte early on purpose, because unwinders look up `return address - 1` and the signal frame's return address is the function's first byte (now `SeedKind::UnwindSignal`) | libc 0x3e6ef for 0x3e6f0 |

So the loader reports FDEs as they are, and:

- the listing does not restart decoding at FDE seeds (it did, and decoded across
  `__restore_rt`'s first instruction; the objdump oracle caught it);
- the seed oracle test accepts exactly these three cases and fails on anything else;
- CFG recovery (step 4) weighs FDE seeds: a PLT-section FDE is not a function, leading
  padding is skipped to the real entry, and FDEs for compiler-split parts (`.cold`)
  are told apart from entries by their call-frame state at `pc_begin`
  (`SeedKind::UnwindFragment`).

## Verification

| Check | Result |
|---|---|
| GNU `readelf --debug-dump=frames` | 442 ELF files (x86-64 executables and shared libraries, i386, AArch64): 265,111 FDE ranges, identical. The only file readelf does not read is the fixture without section headers, where Fulgurite finds the same FDEs as in the original |
| `tests/oracle.rs` | Entry-state FDE seeds at function symbols (2,172), PLT sections (2) or padding before a function (4); mid-frame FDE seeds at `.cold` parts or PLT sections (145); nothing else; the same FDEs with and without section headers |
| Unit tests | LEB128 edge cases, every pointer encoding, a PC-relative table, an augmentation without `z`, a bad CIE pointer, an over-long record, an unsupported pointer application |
| Listing oracle | `objdump -d` comparison unchanged (622,601 instructions) |
| `fg-analysis/tests/seeds.rs` | On the test program itself: the entry is a certain function, every function symbol is an accepted and named function, every FDE is accepted code and never a function on its own, every fact's evidence points at file bytes, and a second run changes nothing |

Pending: a larger AArch64 corpus (only the test fixtures so far).
