# M0 step 1: ELF header and program headers

Status: **done** (2026-10-10). Milestone context: design document section 23, M0 "Inspect".

## Goal

A `fulg` that opens an ELF file and correctly reports its header and program
headers, with every value traceable to the bytes it came from, without ever
crashing on malformed input.

## What exists

| Crate | Layer | Contents |
|---|---|---|
| `fg-core` | 0 | `Va`, `FileOffset`, `Span`, `Field<T>`, `ByteView`, `Endian`, `Anomaly`, `Severity`, `Evidence`, `ArchId`, `Bitness`, `Perms` |
| `fg-loader` | 1 | `load()` / `detect()`, format-neutral `LoadedBinary`, ELF loader (`elf::{ElfHeader, ProgramHeader, DynamicEntry, ElfInfo, consts}`), `MitigationReport` |
| `fg-service` | 6 | `Session::open` / `from_bytes`; re-exports the lower layers so front ends depend on this crate only |
| `fg-cli` | 7 | `fulg info [--json]` |
| `xtask` | tooling | `cargo xtask layers` |

## Decisions made so the next steps don't need a rebuild

1. **`fg-service` exists from day one.** The CLI never touches the loader directly.
   When the analysis database arrives, it goes behind `Session` and the CLI is unchanged.
2. **Format-neutral model + format-specific metadata.** `LoadedBinary` holds what any
   format has (arch, kind, entry, segments, mitigations, anomalies); ELF details sit
   in `FormatMetadata::Elf`. PE adds `FormatMetadata::Pe` without changing callers.
3. **`#[non_exhaustive]` on every public struct and enum.** Later steps add fields
   (sections, symbols, relocations) and variants (`Format::Pe`, new verdicts) without
   breaking existing code.
4. **Provenance in the core types.** `Field<T>` pairs every value with its `Span`; the
   future Fact store (design section 4) reuses `Evidence` and `Span` as-is.
5. **All ELF classes and byte orders now.** ELF32 and big-endian cost little today and
   mean new architectures need no loader changes.
6. **Stable anomaly codes.** `elf.phdr.table_truncated` etc. are machine-readable IDs
   that tests, JSON consumers and the future UI can rely on.
7. **Versioned JSON schema** (`fulgurite.info.v1`), so tools built on `--json` survive changes.
8. **Layering enforced in CI**, with a table that already lists every planned crate.
9. **Limits in `LoadOptions`**, so later callers (batch triage, the corpus pipeline) can
   tighten them without code changes.

## Hostile-input handling (anomaly codes)

`elf.ident.class`, `elf.ident.data`, `elf.ident.version`, `elf.header.truncated`,
`elf.header.version`, `elf.header.ehsize`, `elf.phdr.extended_count`,
`elf.phdr.extended_count_unreadable`, `elf.phdr.entsize_too_small`, `elf.phdr.entsize`,
`elf.phdr.limit`, `elf.phdr.table_overflow`, `elf.phdr.table_truncated`,
`elf.segment.past_eof`, `elf.segment.filesz_gt_memsz`, `elf.segment.align`,
`elf.segment.misaligned`, `elf.segment.wx`, `elf.segment.unsorted`,
`elf.segment.overlap`, `elf.entry.not_executable`, `elf.interp.multiple`,
`elf.interp.unterminated`, `elf.interp.out_of_bounds`, `elf.dynamic.multiple`,
`elf.dynamic.truncated`, `elf.dynamic.limit`, `elf.dynamic.unterminated`,
`elf.machine.unknown`.

## Verification

| Check | Result |
|---|---|
| `readelf -W -h -l -d` oracle: e_type, entry, phnum, every program-header field, dynamic flags | matches on 7 system binaries + 9 compiled variants (default, `-no-pie`, `-static`, `-static-pie`, `-z execstack`, `-z norelro`, lazy binding, `-shared`, `-c`) |
| `checksec` (Go 3.2.0) oracle: PIE / NX / RELRO | matches on the same 16 files |
| Hostile inputs | 15 tests, every anomaly path exercised |
| Every truncation of a valid file | no panic |
| 3,000 random mutations of `/bin/cat` | no panic |
| clippy `-D warnings`, rustdoc `-D warnings`, rustfmt | clean |

## Known limitations (by design for this step)

- Section headers, symbols, relocations, notes and DWARF are not parsed yet, so the
  canary verdict is `Unknown`.
- PIE is inferred from `PT_INTERP` when `DF_1_PIE` is absent. Runnable libraries such
  as libc are therefore reported as PIE, which agrees with `checksec`; the evidence
  says it is an inference.
- A missing `PT_GNU_STACK` gives NX `Unknown` (the real behaviour depends on kernel and
  architecture), where `checksec` says "NX disabled".

## Next step

M0 step 2: section headers (including the `e_shnum == 0` and `SHN_XINDEX` escapes),
string tables, `.symtab` / `.dynsym` with symbol versioning, and the canary and
FORTIFY verdicts that depend on them.
