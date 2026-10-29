# M0 step 4: the PE loader

Status: **done** (2026-10-10). Builds on [step 3](m0-step3.md).

## Goal

Load Windows (and UEFI) PE images into the same format-neutral model the ELF loader
fills, following what the Windows loader looks at rather than what tools usually show:
`e_lfanew`, the NT headers, the section table mapped with the loader's own rounding
rules, then each data directory read through that map. Every value keeps its file
bytes. Then give PE files the same mitigation report, with checks that mean something
on Windows.

## What was added

| Area | Details |
|---|---|
| Formats | PE32 and PE32+ for every machine type. Recognised architectures: x86, x86-64, ARM64 (incl. ARM64EC / ARM64X), ARMv7 (Thumb-2), RISC-V; others load with an `Unknown` architecture |
| Headers | DOS header (all fields), Rich header (decoded and its checksum verified), COFF file header, optional header (both layouts), 16 data directories |
| Image map | Headers mapped at RVA 0, then each section: `VirtualSize` (or `SizeOfRawData` when 0), raw size capped at the virtual size, raw pointer rounded down to 0x200, low-alignment images mapped as is. Every RVA lookup in the loader goes through this map, so tables in the headers, in zero-filled tails or across sections are read as Windows would see them |
| Imports | Import directory (by name with hint, by ordinal; images without a lookup table read names from the IAT), delay-import directory (RVA- and VA-based descriptors), bound-import directory |
| Exports | Export directory: ordinal base, named and ordinal-only exports, multiple names per entry, forwarders, unused slots skipped, name order checked (`GetProcAddress` binary-searches it) |
| Base relocations | Every block and entry; `HIGHADJ` consumes its parameter slot; types named per machine (incl. ARM/Thumb `MOV32`, RISC-V, LoongArch); the value stored at each place |
| TLS | TLS directory and the callback array (VAs, zero-terminated) |
| Load configuration | Every field the structure's own `Size` covers, by `winnt.h` name, in both layouts (they order two fields differently); CFG function table (with the per-entry flag byte), address-taken IAT, long-jump and EH-continuation tables; SafeSEH handler table; hybrid (CHPE) images flagged |
| Exception table | x64 `RUNTIME_FUNCTION` + `UNWIND_INFO`, every unwind code decoded (incl. version-2 epilogue codes, chained fragments, handlers); ARM64 packed and `.xdata` forms with function lengths; ARMv7 packed lengths |
| Debug directory | CodeView `RSDS` (PDB GUID, age, path) and `NB10`; extended DLL characteristics (CET shadow-stack marking); VC feature counts (`/GS` objects); reproducible-build hash |
| Other | Resource tree (named and numbered types, depth and loop limits), certificate table (Authenticode entries), .NET CLR header (flagged: CIL is out of scope), COFF symbol table and long section names (`/4`), image checksum recomputed, overlay detection |
| Neutral model | `Segment` per mapped region, `Section` per header, `Symbol` for every import (`DLL!name`, `DLL!#ordinal`), delay import, export (ordinal, forwarder) and COFF symbol; IAT slots as `GotEntry` relocations and delay-load slots as `PltSlot` (so `slot_at(va)` names `call [rip+X]` for PE too); base relocations as `Relative`; `libraries`; `build_id` = PDB GUID + age as symbol servers spell it |
| Code seeds (new, both formats) | `LoadedBinary::seeds`: entry point; PE TLS callbacks, exception-table functions and fragments (with end addresses), CFG targets, SafeSEH handlers; ELF `DT_INIT` / `DT_FINI` and preinit/init/fini arrays (slot values read through their relocations) |
| Mitigations | PIE → ASLR (`DYNAMIC_BASE`, relocations, `HIGH_ENTROPY_VA`); NX → DEP (always on for 64-bit; decided by the host for DLLs; firmware for UEFI); RELRO → IAT protection (is the IAT in a read-only section; delay-load IAT protection); Canary → `/GS` (load-config cookie, VC feature counts, cookie-check and `__stack_chk_*` symbols); FORTIFY (MinGW `__*_chk`); CFI → Control Flow Guard + CET shadow stack; SepCode → no W+X section, no data directory in code, not low-alignment; LibPath → `DependentLoadFlags` vs the default DLL search order; new SafeSEH check (x86 only) |
| CLI | `fulg info` for PE (overview, memory map, data directories, table summaries); `fulg sections`, `symbols`, `relocs`, `notes` handle PE; new format-neutral commands `fulg imports`, `fulg exports`, `fulg seeds`, `fulg resources`, all with `--json` (`fulgurite.imports.v1`, `fulgurite.exports.v1`, `fulgurite.seeds.v1`, `fulgurite.resources.v1`); `fulgurite.notes.v1` gains PE-only keys (additive) |

## Decisions that avoid rebuilding later

1. **One image map for every lookup.** Imports, exports, TLS, load config, debug,
   resources and unwind data all read through `Image`, which applies Windows' mapping
   rules once. Tools that convert RVAs through section names disagree with the loader on
   crafted files; Fulgurite cannot.
2. **PE32 and PE32+ for every machine now**, like ELF32/64: only the optional header,
   thunk size, TLS and load-config layouts differ, and all are table-driven.
3. **Load-config fields by name, bounded by `Size`.** New Windows versions append
   fields; adding one is a table row, and the oracle compares every field LLVM knows.
4. **Imports are symbols in their own tables** (`Imports`, `DelayImports`, `Exports`,
   `Coff`) instead of being squeezed into ELF's dynamic table, so `SymbolRef` stays
   unambiguous and `is_import()` / `is_export()` work for both formats.
5. **Seeds are format-neutral and carry their kind.** M1's function discovery takes
   them as they are; the kind (entry, TLS callback, exception table, fragment, CFG
   target, init array...) is what the confidence system (design section 12) keys on.
   Fragments are kept separate so split functions are not mistaken for new ones.
6. **Mitigations keep their names across formats**, with PE meanings explained in the
   summary and evidence (e.g. RELRO is reported as IAT protection), so front ends show
   one table; format-specific checks are optional fields (`seh`).
7. **The oracle builds its own corpus** with whichever MinGW toolchain is installed
   (llvm-mingw or GNU), so it needs no binaries in the repository and runs on CI.

## Problems found and fixed during this step

| Found by | Problem | Fix |
|---|---|---|
| llvm-readobj oracle (an MSVC-built signed binary) | version-2 `EPILOG` unwind codes were decoded as two slots each, misaligning every following code | One slot each; the first gives the epilogue length, the others their distance from the end |
| llvm-readobj oracle | `SET_FPREG` carried no operands | Filled from the header: frame register and `FrameOffset * 16` |
| Hostile suite | ARM64 packed unwind data with the reserved flag value 3 was decoded as packed | Reported as invalid unwind data |
| Hostile suite | an unreadable debug directory was silently ignored, and entries were read as one contiguous file run | Each entry is located through the image map; `pe.debug.truncated` |
| Hostile suite | an x64 exception entry whose unwind field was unreadable ended the table silently | `pe.pdata.truncated` |
| Code review | one anomaly code (`pe.coff.truncated`) was used for two different problems | The file-header case is now `pe.file.truncated` |
| Corpus survey | every MinGW file reported an "overlay" | Zero padding to the file alignment is not an overlay |

## Verification

| Check | Result |
|---|---|
| llvm-readobj: file, optional and DOS headers, all data directories, sections, imports (name + hint / ordinal), delay imports (all descriptor fields + each slot's stored value), exports (ordinal, name, RVA or forwarder), base relocations, TLS directory, every load-config field, CFG / long-jump / EH-continuation / SafeSEH tables, debug entries and PDB info, x64 unwind info and every unwind code, ARM64 packed and `.xdata` unwind data, COFF symbols, resources | match on 62 files: 702 sections, 3,479 imports, 14,731 exports, 84,939 base relocations, 17,401 exception entries with 31,607 unwind codes, 2,306 load-config fields, 17,122 CFG targets, 54 debug entries, 58,394 COFF symbols, 44 resources |
| Corpus | 28 images built by the test with llvm-mingw for x86-64, i686, ARM64 and ARMv7 (stack protector, stripped, fixed-base, CFG + delay-load, DLL with ordinal-only / data / forwarded exports, ordinal imports, resources, CET + `DependentLoadFlags`); Go's PE test data; an MSVC-built signed executable; UEFI boot loaders for x64, IA-32, ARM64, RISC-V and LoongArch; MinGW runtime DLLs incl. ARM64EC hybrids |
| objdump -p | header fields and imported DLLs match on 38 files (objdump has no ARM64 target here) |
| Checksum | the recomputed checksum equals the stored one on every file that has one (5) |
| Real files | no structural anomaly on any real file (only TLS-callback, CLR, hybrid, overlay, directory-count and unknown-machine notes) |
| Seeds | every PE seed lies in an executable section; 86 ELF init/fini seeds land exactly on function symbols |
| Synthetic files | 23 semantics tests with exact values and spans (every table, every mitigation verdict) and a 104-case hostile suite; a meta-test scans the source and fails if any of the 96 PE anomaly codes is never triggered |
| Mutation | 10,000 mutations of a synthetic image with every directory populated + 2,000 of each real PE on the system, with overflow checks on: no panic |
| Total | 125 tests; clippy, rustdoc and rustfmt clean |

## Where Fulgurite goes beyond common tools

- RVAs are resolved the way the Windows loader maps the file (raw pointer rounding, raw
  size capped by virtual size, low-alignment images, tables inside the headers), not by
  section lookup.
- The mitigation report explains what each flag really does on Windows: DEP is always on
  for 64-bit code; `NX_COMPAT` on a DLL changes nothing; `GUARD_CF` without instrumented
  code has no effect; an IAT in a writable section (MinGW's `.idata` with GNU ld) can be
  overwritten after startup.
- `/GS` evidence comes from the VC feature debug entry (how many objects were built with
  `/GS`), not only from the cookie the C runtime always registers.
- The Rich header checksum is verified, which exposes edited or transplanted toolchain
  fingerprints.

## Known limitations

- COFF object files (`.obj`) and TE images are not loaded yet.
- Managed (.NET) code, PDB files, `VS_VERSIONINFO` / manifest contents, Authenticode
  signature validation and the dynamic-value relocation table (ARM64X) are not decoded.
- ARMv7 unwind data beyond packed function lengths, and ARM64 unwind codes, are left for
  M1 (the headers and lengths are decoded).
- Windows-loader behaviour that could not be verified without Windows (for example
  whether non-contiguous sections are refused) is reported without an "OS behaviour" note.
- The 24-hour fuzzing exit criterion is not met yet. A first run of the `load` target
  (PE and ELF) reached 3.6 hours, 1.04 million inputs and 6,071 covered edges with no
  crash, hang or out-of-memory before the machine was shut down. The second run found
  one crash after 40 minutes: an overflow reading a dynamic segment whose file offset
  is within a word of 2^64 (in release builds it wrapped and read the wrong bytes).
  Fixed with the same unchecked addition found by audit in the relocation-symbol
  count, and regression tests in `hostile.rs` and `relocs_notes.rs`; the exit run
  restarts on the fixed code.

## Next step

M0 step 5: the x86-64 decoder (`fg-arch-x86`) and `fulg disasm`, checked against
`objdump -d`, starting from the seeds both loaders now produce.
