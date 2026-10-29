# Changelog

## Unreleased

### M1 step 8: measurement tools (2026-10-29)

- `tools/measure/corpus.sh`: builds the function-recovery corpus from 12 pinned
  open-source programs (GNU coreutils, grep, sed, diffutils, findutils, gawk, groff,
  jq, SQLite, Lua as C and as C++, zlib, bzip2), Fulgurite's own `fulg` (Rust) and Go
  distribution tools, in 36 configs: gcc and clang at every `-O` level, static, LTO,
  no unwind tables, non-PIE, function sections, CET on and off, 32-bit, AArch64,
  MinGW 32- and 64-bit PE. Every binary is kept stripped, unstripped, and with its
  true function list read from the symbol table by binutils.
- `cargo xtask measure CORPUS`: recall and precision of Fulgurite, IDA and Binary
  Ninja against the true lists, per config, for the M1 gate (`gcc-O2`, `clang-O2`), and
  Fulgurite against each other tool on the binaries both have.
- `tools/measure/ida-export.sh` and `fulg_export.idc`: IDA Free's function lists,
  unattended (Xvfb and xdotool drive the GUI; IDA Free has no batch mode).
- `tools/measure/setup-ubuntu.sh`: everything above on a fresh Ubuntu 24.04 server.

### Fuzzing the analysis (2026-10-21)

- New fuzz targets `functions` (seeds, `.eh_frame`, CFG, no-return, jump tables) and
  `xrefs` (cross-references); `tools/fuzz/seeds.sh` rebuilds the seed corpora from
  system ELF files and the analysis test programs (gcc, clang, 32-bit PIC, AArch64).
- Fix (found by fuzzing): a branch to bytes that do not decode makes a block with no
  instructions; the check for blocks running over an FDE-only function built an
  invalid range from it and panicked.

### M1 step 7: cross-references (2026-10-14)

- `fg-analysis::xrefs`: every reference the recovered code and the file's data make
  (calls, jumps, branches, tail calls, jump-table entries, reads, writes, addresses
  taken, pointers), with how each was found and whether it is a guess. Register-built
  addresses (`adrp` pairs, the 32-bit GOT pointer), accesses through relocated pointers
  (GOT entries), and absolute arrays indexed by a register are followed.
- `fulg xrefs FILE [NAME | 0xADDR] [--json]` and `Session::xrefs`.
- `Arch::mem_addr`: the address and access of any memory operand, stores included
  (x86, AArch64). `Effect::Call` for indirect calls.
- `call next; pop r` (clang's 32-bit PIC) sets `r` instead of clobbering every
  register.
- Fix: link-time relocations a file keeps (`--emit-relocs`) were taken for load-time
  ones, so a jump table they had filled was not read. `Relocation::applied_at_load`
  tells them apart.
- Checked against the linker: in 10 builds (x86-64, AArch64, 32-bit PIC), every
  relocated instruction has a reference, every computable target is right, and every
  data reference out of `.text` comes from a relocated instruction.

### Loader limits (2026-10-14)

- PE: a limit on imports in all (`Limits::max_imports`, 65,536): import descriptors
  sharing one long lookup table no longer multiply the work (`pe.import.total_limit`).
- ELF: a limit on relocations in all (`Limits::max_total_relocations`): many tables
  over the same bytes no longer multiply it either (`elf.reloc.total_limit`).
- ELF: relocation places are found through an index of the `PT_LOAD` headers built
  once, not by scanning every header for each relocation.

### M1 step 6: jump tables and register values (2026-10-11)

- AArch64: `Effect` from the encoding's fields. Jump tables (`ldrb`/`ldrh` + `adr` +
  `add ..., sxtb #2`), `adrp` + `add` address pairs, and PLT stubs' `br x17` through
  the import's slot. Tested on clang-built, `rust-lld`-linked programs.
- A call to the function right after the caller is an ordinary call when the callee
  is known from more than that call (a symbol, an FDE, other callers).
- Data words a relocation writes (GOT entries) are not pointers in a fixed-address file.
- Tables in `.data.rel.ro` are read through their `RELATIVE` addends; tables in
  writable memory as the file starts them, at confidence 0.4. Wrapped lower bounds
  (`cmp edx, -8; jb; lea eax, [rdx+8]`) bound the index. A call to a PC thunk sets its
  register (32-bit PIC).
- A new table is read again with its cases in place, and accepted tables are read again
  each round; a table that no longer reads the same is rejected or retracted. Call
  targets and tables are found in the same round (static glibc: 26 → 18 rounds).


- `fg-ir` gains `Effect` (`Arch::effect`): what an instruction does to registers and
  flags, enough to follow a value through a jump-table sequence, and
  `Arch::callee_saved`. Implemented for x86 and AArch64.
- Jump tables are read when the path into the jump bounds the index (`cmp; ja`, `and`),
  by evaluating the jump's target symbolically for every index allowed. Each target is
  an `Edge` fact (`cfg.tables`). gcc and clang, PIC and absolute tables, bounds carried
  across calls in callee-saved registers, a table base loaded before a loop.
- Calls and jumps through a slot holding one of the file's own functions (`RELATIVE`
  GOT entries, a library's GOT entries for its own exports) are calls and tail calls to
  that function; `IRELATIVE` slots are tail calls out. Rust's test program: no-return
  functions 31 → 119, unresolved jumps 561 → 260.
- Files loaded at a fixed address: immediates and, last, aligned data words that hold
  code addresses are pointers (a non-PIE C program without unwind tables: 9 → 25 of 25
  functions).
- The C test matrix adds a `switch` and non-PIE builds (18 builds); every indirect jump
  in them is resolved but crt's.

### M1 step 5: no-return analysis (2026-10-11)

- Functions that never return are found by a fixed point over the call graph, starting
  from the imports that never return by definition. They become `NoReturn` facts
  (`cfg.noreturn`) with how each path ends as evidence, and calls to them end their
  block. Anything not understood (an unresolved jump, undecodable bytes) may return.
- A split-off `.cold` part whose FDE starts in an entry state (in a function without a
  frame at the jump) is a fragment, not a function: it never returns, and one other
  function jumps to it. Static glibc program: precision 99.44% → 100%.
- Retpoline thunks: the call over the capture loop is the thunk's own code, not a call
  to a function. A call into the calling function's own code (a stack switch) means it
  may return.
- `fulg functions` marks functions that never return; the JSON gains `no_return`.

### M1 step 4: CFG recovery and `fulg functions` (2026-10-11)

- `fulg functions FILE [--json]`: every function with its confidence, the pass that
  found it, its name or strongest evidence, and unresolved jumps flagged
  (`fulgurite.functions.v1`).
- Jumps through import slots (PLT stubs, PE import thunks) are resolved tail calls to
  the import. Signal-trampoline FDEs (`SeedKind::UnwindSignal`) start one instruction
  unit before the code. Addresses taken strictly inside an FDE's range are labels, not
  functions.
- Calls to imports that never return (`abort`, `exit`, `__stack_chk_fail`...) end
  their block, so decoding no longer runs on into the next function.
- Static glibc program: 99.91% of function starts (99.44% precision), static PIE 100%.
- CI builds the C test programs with clang 23 from apt.llvm.org (was Ubuntu's clang 18).

### M1 step 2: the analysis cache (2026-10-11)

- New crate `fg-store`: facts persisted per binary in SQLite (bundled, WAL, one
  transaction per save). A damaged cache is refused: every fact is rebuilt and its id
  checked, and the store must be closed and acyclic.

### M1 step 3: seeds (2026-10-11)

- ELF `.eh_frame` and `.eh_frame_hdr`: every FDE becomes a code seed with its end
  address (`SeedKind::UnwindTable`), found through `PT_GNU_EH_FRAME` like the run time
  does, so files without section headers work. FDEs that start mid-frame (`.cold`
  parts) are `SeedKind::UnwindFragment`. The header's lookup table is checked
  against the FDEs. Identical to `readelf` on 265,111 FDEs in 442 files.
- New crate `fg-analysis` with the seed pass: entry point, symbols, exports, unwind and
  exception tables, init/fini arrays, TLS callbacks and CFG targets become `Declared`
  facts with the declaring bytes as evidence. FDEs say "code", not "function"; aliases
  give one deterministic name.
- The listing does not restart decoding at FDE starts: an FDE can begin in padding or,
  for glibc's `__restore_rt`, one byte before its function.

### M1 step 1: the fact store (2026-10-11)

- New crate `fg-facts`: `Fact` (claim, status, confidence, provenance, evidence), the M1
  claim kinds, `Confidence` with its buckets and combining rules, stable 128-bit fact ids,
  and `FactStore` with the design's resolution rules (rejections, status order, near ties
  reported as conflicts, observed-vs-user warnings) and invalidation through the
  dependency graph (`invalidate`, `retract`, `why`, `dependents`). A fact cannot be built
  without evidence.

### M0 step 6: the AArch64 decoder (2026-10-11)

- New crate `fg-arch-arm64`: A64 decoding and formatting from tables generated by
  `tools/arm64/gen.py` out of Arm's Machine Readable Specification (JSON, BSD-3) and the
  A64 ISA XML (2026-09; not stored in the repository). Covers 4,393 encodings with every
  architecture feature, including SVE/SVE2, SME/SME2 and MOPS, plus 314 aliases with
  Arm's preferred disassembly.
- The checks for UNDEFINED encodings are translated from Arm's decode pseudocode, and
  CONSTRAINED UNPREDICTABLE encodings are reported (`is_unpredictable`) but still decoded.
- `fulg disasm` lists ARM64 ELF and PE files, with `name@plt` for ARM64 PLT stubs; Arm
  mapping symbols are no longer used as names.
- The `disasm` fuzz target also decodes A64.
- Tests: an `llvm-mc` oracle (163,179 words per run, including the whole system
  instruction and system register space, 0 unexplained differences), decoder semantics,
  and ARM64 listings checked against `llvm-objdump`.
- Every 32-bit word compared with LLVM 23 and GNU binutils 2.47: no unexplained
  differences. The comparison found, and this release fixes: `msr pm, #imm`; DC, TLBI
  and PLBI operations the XML's `SysOp()` leaves out (now taken from `Registers.json`);
  system aliases that dropped a register other than XZR; operations that read their
  register now show XZR (`tlbi vae1, xzr`). New: `system_register()`,
  `system_register_names()`.

### Fixes (2026-10-10)

- ELF: a dynamic segment, or a relocation table, mapped to file offsets within a word
  of 2^64 overflowed an offset addition (found by fuzzing; in release builds the read
  wrapped to the start of the file). Offsets taken from the file are now checked
  wherever they are extended.

### M0 step 5: the x86 decoder and `fulg disasm` (2026-10-10)

- New crate `fg-ir`: the architecture-neutral `Insn` (bytes, mode, control flow with
  targets, the explicit memory operand with its resolved address, first immediate,
  padding flag), typed display tokens, and the `Arch` trait (`decode`, `format`).
- New crate `fg-arch-x86`: x86 and x86-64 in 16/32/64-bit modes through `iced-x86`,
  Intel syntax that reads like `objdump -M intel`, AT&T available.
- Disassembly listing in the service layer: every code section, a section, a function, a
  count from an address or a range; restarts at every symbol and seed; overlapping labels
  flagged; invalid and cut-off bytes reported; `name@plt` stubs, `<sym+off>` targets and
  import slots (`[puts@GLIBC_2.2.5]`) named; streamed one line at a time.
- CLI: `fulg disasm` with `--json` (`fulgurite.disasm.v1`), `--att`, `-s`, `-n`, `--end`,
  `entry`. All commands end quietly when their output pipe closes.
- New fuzz target `disasm`.
- Tests: 146, adding an objdump oracle (4,996,181 instructions compared in the full run,
  622,601 in the default one, no unexplained difference), instruction-family fixtures
  for ELF and PE in both modes, decoder semantics, exhaustive two-byte and random-byte
  sweeps, listing semantics and CLI tests.

### M0 step 4: the PE loader (2026-10-10)

- PE32 and PE32+ for every machine type (x86, x86-64, ARM64 incl. ARM64EC/ARM64X, ARMv7,
  RISC-V recognised). DOS, Rich, COFF and optional headers; data directories; sections
  mapped with the Windows loader's rules (raw pointer rounding, raw size capped by virtual
  size, low-alignment images), and every table read through that map.
- Imports (name, hint, ordinal), delay imports, bound imports, exports (ordinal-only,
  forwarders), base relocations, TLS callbacks, load configuration (every field by name,
  CFG / long-jump / EH-continuation / SafeSEH tables), exception table with x64 unwind
  codes and ARM64 packed / `.xdata` unwind data, debug directory (PDB, CET marking, `/GS`
  counts), resources, certificates, CLR header, COFF symbols, checksum, overlay.
- Neutral model: PE symbols in their own tables (`Imports`, `DelayImports`, `Exports`,
  `Coff`) with `library`, `ordinal` and `forwarder`; IAT slots as relocations, so
  `slot_at(va)` works for PE; `build_id` = PDB GUID + age.
- New format-neutral `LoadedBinary::seeds` (code start addresses with their kind): entry,
  PE TLS callbacks, exception-table functions and fragments, CFG targets, SafeSEH
  handlers; ELF `DT_INIT` / `DT_FINI` and preinit/init/fini arrays.
- PE mitigation verdicts (ASLR, DEP, IAT protection, `/GS`, FORTIFY, CFG + CET shadow
  stack, W^X layout, DLL search path) and a new optional SafeSEH check.
- CLI: PE support in `info`, `sections`, `symbols`, `relocs`, `notes`; new `fulg imports`,
  `fulg exports`, `fulg seeds`, `fulg resources` with `--json`.
- 96 PE anomaly codes, each triggered by a test. Tests: 125, adding an llvm-readobj and
  objdump oracle on 62 PE files (built per run with MinGW, plus Go test data and system
  UEFI/MinGW/MSVC files), 23 semantics tests, a 104-case hostile suite, PE mutation seeds
  and an ELF init/fini seed oracle.

### M0 step 3: relocations, notes, libraries and the remaining checks (2026-10-10)

- Relocations: `REL`, `RELA` and packed `RELR`, found through the dynamic segment as the
  dynamic linker does (section headers only name them), plus link-time tables from section
  headers. `DT_RELASZ`-includes-`DT_JMPREL` handled like glibc. Type names for x86-64, i386,
  AArch64, ARM, RISC-V; neutral `Relocation` / `RelocKind` with resolved symbol names and the
  stored value at each location; `LoadedBinary::slot_at(va)`.
- Library names and search paths: `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`;
  `LoadedBinary::libraries`.
- Notes from `PT_NOTE` and `SHT_NOTE`: build ID (`LoadedBinary::build_id`), ABI tag, GNU
  properties with readelf-identical descriptions, gold version, package metadata, Go build ID.
- New checks: CFI (x86 IBT/SHSTK, AArch64 BTI/PAC, RISC-V Zicfilp/Zicfiss), separate code,
  library paths. RELRO evidence counts GOT slots inside the read-only range. Text
  relocations reported.
- CLI: `fulg relocs [--slots]`, `fulg notes`, both with `--json` (`fulgurite.relocs.v1`,
  `fulgurite.notes.v1`); `fulg info` shows libraries, paths, build ID and the new checks.
  `fulgurite.info.v1` gains fields (additive).
- 23 new anomaly codes (80 total). Tests: 86, adding relocation, note and dynamic-string
  oracles against readelf and five more checksec checks on 35 binaries, 16 synthetic tests,
  and a libc mutation seed.

### M0 step 2: sections, symbols and versions (2026-10-10)

- Section headers: ELF32/64, both escapes (`e_shnum == 0`, `e_shstrndx == SHN_XINDEX`),
  names via `.shstrtab`, cross-checked against the segments the OS maps.
- Shared bounds-checked string-table reader.
- `.symtab` and `.dynsym`: value, size, type, binding, visibility, section index
  (including `SHN_XINDEX` via `SHT_SYMTAB_SHNDX`); section symbols named after their section.
- GNU symbol versioning (`.gnu.version`, `.gnu.version_r`, `.gnu.version_d`), including
  copy-relocated data that uses a needed version.
- The dynamic symbol table is found through the dynamic segment (`DT_SYMTAB`, `DT_STRTAB`,
  hash tables, relocations), so symbols survive removal of section headers. The count is
  bounded by the SysV hash, the GNU hash and relocation indexes (lower bounds) and the
  table layout (upper bound).
- Format-neutral `Section`, `Symbol`, `SymbolVersion`; `LoadedBinary::imports`, `exports`,
  `file_offset_of(va)`.
- Canary verdict (`__stack_chk_fail` / `__stack_chk_guard`) and FORTIFY verdict over all 88
  fortifiable glibc 2.44 functions, reporting partially fortified functions.
- `MitigationReport::all()` now returns a `Vec` so future checks don't break callers.
- CLI: `fulg sections`, `fulg symbols [--imports|--exports] [--table dynamic|static]`,
  both with `--json`; `fulg info` gains section and symbol summaries.
- 28 new anomaly codes (57 total). Tests: 63, adding section/symbol oracles against
  `readelf -S` / `readelf -s` on 21 binaries, a no-section-headers recovery test, and
  canary/FORTIFY oracles against checksec.

### M0 step 1: ELF header and program headers (2026-10-10)

- Cargo workspace with the layered crate structure from the design (section 22.8),
  enforced by `cargo xtask layers`.
- `fg-core`: `Va` / `FileOffset` newtypes, `Span` / `Field<T>` byte-level provenance,
  bounds-checked `ByteView` (both byte orders), `Anomaly`, `Evidence`, `ArchId`, `Perms`.
- `fg-loader`: ELF32 and ELF64, little- and big-endian. Header, program headers
  (including the `PN_XNUM` extended count), `PT_INTERP`, dynamic section via
  `PT_DYNAMIC`. Format-neutral model (`LoadedBinary`, `Segment`, `BinaryKind`).
  PIE / NX / RELRO verdicts with evidence; canary reported as not yet checked.
  29 anomaly codes for malformed or suspicious input.
- `fg-service`: `Session`, the single API every front end uses.
- `fg-cli`: `fulg info <file>` (text with `@offset` provenance) and `--json`
  (schema `fulgurite.info.v1`).
- Tests: unit, hostile-input, semantics, `readelf` and `checksec` oracles on system
  binaries and nine compiled variants, 3,000-case mutation test, CLI end-to-end.
- `fuzz/` libFuzzer target; CI (fmt, clippy, docs, tests, layering, MSRV 1.88).
