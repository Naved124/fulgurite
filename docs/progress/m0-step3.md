# M0 step 3: relocations, notes, libraries and the remaining checks

Status: **done** (2026-10-10). Builds on [step 2](m0-step2.md).

## Goal

Teach `fulg` what the loader *does* to the file before the program runs: which
addresses it patches (relocations), which libraries it loads and from where
(`DT_NEEDED`, `RPATH`, `RUNPATH`), and what the toolchain recorded about the build
(notes: build ID, ABI tag, GNU properties). Then finish the checksec-equivalent
checks that depend on them: hardware CFI (x86 CET, AArch64 BTI/PAC), separate code
and library search paths.

## What was added

| Area | Details |
|---|---|
| Relocation tables | `elf::ElfRelocTable` / `ElfRelocation`: `REL`, `RELA` and packed `RELR`, every field with its span. Found through the dynamic segment (`DT_RELA`, `DT_REL`, `DT_JMPREL` + `DT_PLTREL`, `DT_RELR`) the way the dynamic linker finds them; section headers only supply names. Relocation sections the dynamic segment does not cover (object files, static executables, `--emit-relocs`) are read through their section headers |
| RELR | address and bitmap words decoded into individual relocations; each keeps the span of the word that produced it |
| `DT_RELASZ` overlap | when `DT_RELASZ` includes the `DT_JMPREL` table at its tail (some linkers do this), the PLT relocations are read once, as glibc does; any other overlap is an anomaly |
| Relocation types | names for x86-64, i386, AArch64, ARM and RISC-V; a format-neutral `RelocKind` (relative, absolute, GOT entry, PLT slot, copy, IFUNC, TLS, other) with a plain-language `meaning()` |
| Stored values | the word the file holds at each patched location: the implicit addend for `REL`/`RELR`, the PLT stub address for a lazily bound slot |
| Neutral model | `Relocation` with the symbol name and version resolved; `LoadedBinary::slot_at(va)` answers "which import does this GOT/PLT slot hold" (what M1 needs to name `call [rip+X]` and PLT stubs); `is_stripped()` |
| Dynamic strings | `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH` resolved through `DT_STRTAB`; `LoadedBinary::libraries` |
| Notes | `PT_NOTE` segments (4- and 8-byte alignment), then `SHT_NOTE` sections no segment covers. Decoded: build ID, ABI tag, GNU properties, gold version, FDO package metadata, Go build ID. `LoadedBinary::build_id` |
| GNU properties | every property readelf knows, described with readelf's exact wording (x86 feature/ISA used/needed incl. the superseded "compat" encodings of older binutils, AArch64, RISC-V, stack size, 1_needed, UINT32 AND/OR ranges); `ElfInfo::property_note()` prefers the note `PT_GNU_PROPERTY` points at, which is what the kernel and dynamic linker read |
| CFI verdict | x86 IBT + SHSTK, AArch64 BTI + PAC, RISC-V Zicfilp + Zicfiss: Enabled (both), Partial (one), Disabled (none, or no property note) |
| Separate-code verdict | Disabled for a writable+executable segment; Partial when an executable segment also maps the ELF headers or non-code sections (rounded to 4 KiB pages, as the kernel maps them); evidence lists the sections |
| Library-path verdict | each `RPATH`/`RUNPATH` entry classified: empty or relative (Disabled), `$ORIGIN` (Partial), absolute (Enabled); notes RPATH-vs-RUNPATH precedence |
| RELRO evidence | counts GOT/PLT slots inside and outside the `PT_GNU_RELRO` range; "full RELRO" with slots outside it is downgraded to Partial |
| Text relocations | relocations that patch a read-only segment are reported, with what the OS does depending on `DT_TEXTREL` |
| CLI | `fulg relocs [--slots] [--json]` (schema `fulgurite.relocs.v1`), `fulg notes [--json]` (schema `fulgurite.notes.v1`); `fulg info` gains libraries, SONAME, RPATH/RUNPATH, build ID, relocation and note summaries, and the three new checks |

## Decisions that avoid rebuilding later

1. **Relocations are located the loader's way.** The dynamic segment is authoritative and
   section headers only name tables, so stripped or forged section headers change nothing
   (verified: identical relocations and build ID after `objcopy --strip-section-headers`).
2. **`applied_at_load` on every table.** Link-time tables (object files, `--emit-relocs`)
   are kept for display but never checked as if the dynamic linker applied them.
3. **`slot_at(va)` on the neutral model.** M1 resolves indirect calls through it; PE's IAT
   will fill the same `Relocation`/`RelocKind::GotEntry` shape.
4. **Stored values, not guessed addends.** The model records the bytes at the location
   (with their span) and says what they mean per table format, instead of inventing an
   addend for formats where it is implicit.
5. **Mitigations are filled with builder methods** (`with_cfi`, `with_separate_code`,
   `with_library_paths`), so the PE loader can fill the same checks without a new
   constructor signature.
6. **Property descriptions match readelf byte for byte** (taken from the binutils source),
   so they can be compared automatically and users see familiar text.

## Problems found and fixed during this step

| Found by | Problem | Fix |
|---|---|---|
| Notes oracle on a 32-bit library | `x86 ISA used: <None>` vs readelf's empty value | Read binutils' `readelf.c`: an empty ISA mask prints nothing, an empty feature mask prints `<None>`, and C's `%#x` prints zero as `0`. Matched exactly, including the compat ISA encodings |
| Corpus survey (`--emit-relocs` binary) | 4 false `elf.reloc.textrel` warnings: link-time `.rela.text` sections were checked as if applied at load | Tables carry `applied_at_load`; place and text-relocation checks run only on those |
| Oracle build | the 32-bit object variant was silently skipped (no 32-bit libc headers installed) | New header-free source, so 32-bit `REL` objects (implicit addends) are always tested |
| Design review | 64-bit `RELA` objects showed 8 bytes read at instruction offsets as "stored value" | Not recorded where the addend is explicit and the field width varies |

## Where Fulgurite now goes beyond checksec 3.2.0

- CFI is read through `PT_GNU_PROPERTY` / `PT_NOTE` as the run time does, so it still works
  without section headers (checksec reports `Unknown`).
- A binary without any property note is "not marked" (Disabled), not "Unknown": the linker
  drops the marking whenever one object lacks it.
- Separate code checks what the executable segment maps, not only for a W+X segment
  (`-z noseparate-code` is Partial here; checksec reports `Enabled`).
- RELRO says how many GOT slots are actually inside the read-only range.
- Library paths are classified without touching the filesystem (absolute paths note that
  directory permissions depend on the target system).

## New anomaly codes (23)

`elf.reloc.pltrel_invalid`, `elf.reloc.entsize`, `elf.reloc.overlap`,
`elf.reloc.section_unused`, `elf.reloc.symtab_invalid`, `elf.reloc.target_invalid`,
`elf.reloc.truncated`, `elf.reloc.size`, `elf.reloc.limit`, `elf.reloc.bad_symbol`,
`elf.reloc.unknown_type`, `elf.reloc.place_unmapped`, `elf.reloc.textrel`,
`elf.relr.no_base`, `elf.note.align`, `elf.note.truncated`, `elf.note.limit`,
`elf.property.corrupt`, `elf.property.multiple`, `elf.property.segment_mismatch`,
`elf.property.no_segment`, `elf.dynamic.no_strtab`, `elf.dynamic.string_invalid`.
80 codes in total; every new one is triggered by a test.

## Verification

| Check | Result |
|---|---|
| `readelf -W -r`: every relocation's offset, info, type, symbol name with version, addend; every RELR-decoded address | 4,936 relocations match on 34 binaries (incl. libc's 1,096 RELR locations, a `-z pack-relative-relocs` build, `--emit-relocs`, 32-bit REL objects and a 32-bit text-relocation library) |
| `readelf -W -n`: every note's owner, size, type, build ID, ABI tag and full property text | matches on 35 binaries (81 notes in libc) |
| `readelf -d`: `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH` | matches on 35 binaries |
| checksec 3.2.0: CFI, separate code, RPATH, RUNPATH, symbol count (plus the step 1-2 checks) | matches on 35 binaries, incl. `-fcf-protection=full/branch/none`, RPATH, `$ORIGIN` and relative RUNPATH |
| No-section-headers copy | same relocations, build ID and CFI verdict as the original |
| Synthetic files | 16 new tests: exact values and spans, RELR bit decoding, JMPREL-in-RELASZ, text relocations with and without `DT_TEXTREL`, AArch64 BTI/PAC, hostile tables and notes, every truncation |
| Mutation | 5,000 mutations of `/bin/cat` + 600 of libc's first 256 KiB (RELR, notes, relocations): no panic |
| Total | 86 tests; clippy, rustdoc and rustfmt clean |

## Known limitations

- Relocation *application* (computing final values for each type) is not done; M1/M4
  apply them when mapping memory for disassembly and emulation.
- Android packed relocations (`DT_ANDROID_REL[A]`) and `DT_AARCH64_AUTH_RELR` are not read yet.
- Whether an absolute `RPATH`/`RUNPATH` directory is writable by others depends on the
  target system and is not checked.
- Stack-clash probes, SafeStack and sanitizer detection need disassembly or wider symbol
  heuristics and are left for M1.

## Next step

M0 step 4: the PE loader (DOS/NT headers, sections, imports/exports, base relocations,
TLS callbacks, exception data, debug directory, PE mitigations), filling the same neutral
model (`Segment`, `Section`, `Symbol`, `Relocation`, mitigations).
