# M0 step 2: sections, symbols and versions

Status: **done** (2026-10-10). Builds on [step 1](m0-step1.md).

## Goal

Teach `fulg` what the binary *names*: sections, symbols, imports and exports, and
their versions, plus the canary and FORTIFY verdicts that depend on them. Symbols
must still be found when section headers have been removed, because the OS loader
never reads them and malware often deletes them.

## What was added

| Area | Details |
|---|---|
| Section headers | `elf::SectionHeader` with every field's span; count escape `e_shnum == 0` (real count in section 0's `sh_size`); name-table escape `e_shstrndx == SHN_XINDEX` (real index in `sh_link`); names via `.shstrtab` |
| Sections vs segments | each loaded section is checked against the `PT_LOAD` that maps it: address mapped at all, file offset consistent, executable flag backed by an executable segment |
| String tables | `StringTable`: span clamped to the file, terminator required inside the table, name length capped |
| Symbol tables | `elf::ElfSymbolTable` / `ElfSymbol`: value, size, type, binding, visibility, section index (incl. `SHN_XINDEX` through `SHT_SYMTAB_SHNDX`), name span |
| Versions | `.gnu.version` + `.gnu.version_r` + `.gnu.version_d` (or their `DT_*` equivalents); `@` / `@@` display; copy-relocated data takes the needed version; version-marker symbols print bare |
| Dynamic-segment path | `.dynsym` located through `DT_SYMTAB` / `DT_STRTAB` / `DT_STRSZ`, addresses mapped to file offsets through `PT_LOAD` |
| Neutral model | `Section`, `Symbol`, `SymbolKind`, `SymbolBinding`, `SymbolTable`, `SymbolVersion`; `LoadedBinary::{imports, exports, file_offset_of}`; `Segment::file_offset_of` |
| Verdicts | Canary from `__stack_chk_fail` / `__stack_chk_guard` (static binaries flagged as "libc's own canary code"); FORTIFY over 88 glibc functions with fortified / partially fortified / never fortified evidence |
| CLI | `fulg sections`, `fulg symbols [--imports | --exports] [--table dynamic|static]`, `--json` schemas `fulgurite.sections.v1` and `fulgurite.symbols.v1` |

## Decisions that avoid rebuilding later

1. **`file_offset_of(va)` lives on the neutral model.** The disassembler (M1) needs exactly
   this mapping to read code bytes at an address.
2. **Raw ELF records stay next to the neutral ones.** `ElfSymbol` keeps every field's span
   for provenance; `Symbol` is what PE's import and export tables will fill too.
3. **Dynamic symbols prefer the loader's truth.** When section headers disagree with the
   dynamic segment, the dynamic segment wins and the disagreement becomes an anomaly.
4. **`MitigationReport::all()` returns a `Vec`**, so CET, stack-clash and similar checks can
   be added without breaking callers.
5. **FORTIFY counts functions, not symbols**, and shows partial protection separately.

## Problems found and fixed during this step

| Found by | Problem | Fix |
|---|---|---|
| Running on `arrays` | Dynamic count was 1, not 8: the GNU hash covered no symbols, so it is only a lower bound | Count bounded by hash tables + relocation symbol indexes (lower) and table layout (upper); section headers used when they agree |
| `/bin/cat` | 7 false `elf.version.index_invalid` | Copy-relocated data (e.g. `stdout`) uses a *needed* version; defined symbols now check both tables |
| `/bin/cat` vs checksec | FORTIFY total 9 vs 8 | `memcpy` was counted twice (plain + `__memcpy_chk`); now counted once per function |
| `readelf` oracle on ld.so | `GLIBC_2.2.5@@GLIBC_2.2.5` | Version-marker symbols print bare, as readelf does |
| `readelf` oracle on `.o` | Section symbols had empty names | Named after the section they mark |
| checksec oracle | Counts differed on `ls` / `sh` | Probes, then checksec's source: it counts a hardcoded list of 18 functions and counts symbols, not functions. The oracle compares over that list; Fulgurite keeps all 88 |

## New anomaly codes (28)

`elf.section.no_table`, `elf.section.entsize_too_small`, `elf.section.entsize`,
`elf.section.extended_count`, `elf.section.extended_shstrndx`, `elf.section.limit`,
`elf.section.table_overflow`, `elf.section.table_truncated`, `elf.section.shstrtab_type`,
`elf.section.shstrndx_invalid`, `elf.section.name_invalid`, `elf.section.past_eof`,
`elf.section.outside_segments`, `elf.section.offset_mismatch`, `elf.section.exec_mismatch`,
`elf.section.none`, `elf.symtab.limit`, `elf.symtab.truncated`, `elf.symtab.name_invalid`,
`elf.symtab.entsize`, `elf.symtab.strtab_invalid`, `elf.version.chain_invalid`,
`elf.version.index_invalid`, `elf.dynamic.unmapped`, `elf.dynamic.syment`,
`elf.gnu_hash.invalid`, `elf.dynsym.mismatch`, `elf.dynsym.count_estimated`.

## Verification

| Check | Result |
|---|---|
| `readelf -W -S`: every section's name, type, address, offset, size, entsize, link, info, alignment, flags | matches on 20 binaries with section headers |
| `readelf -W -s`: every symbol in both tables: value, size, type, binding, visibility, section index, name with version | matches on the same 20 |
| No-section-headers copy (`objcopy --strip-section-headers`) | same dynamic symbols, imports and canary as the original |
| checksec 3.2.0: PIE / NX / RELRO / canary / FORTIFY verdicts and FORTIFY counts | matches on 21 binaries |
| Hostile sections and symbols | 10 new tests; every truncation of a file with sections is safe |
| 5,000 mutations across headers and section/symbol areas | no panic |
| Total | 63 tests; clippy, rustdoc and rustfmt clean |

## Known limitations

- Canary and FORTIFY are decided from symbols. Per-function canary detection and FORTIFY in
  static binaries need disassembly (M1).
- Symbol names are not demangled yet (C++ / Rust demanglers arrive with the language frontends).
- Relocations are read only for their symbol indexes; full relocation parsing is the next step.

## Next step

M0 step 3: relocations (`REL`, `RELA`, `RELR`) with symbol binding, notes
(`.note.gnu.build-id`, `.note.gnu.property` → CET IBT/SHSTK verdict), `DT_NEEDED` /
`RPATH` / `RUNPATH`, and the remaining checksec checks.
