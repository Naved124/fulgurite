# Fulgurite

**A disassembler and decompiler whose guesses are visible, explainable and reversible.**

*fulgurite* (n.): natural glass formed when lightning strikes sand, recording the exact path of the strike. *Lightning, frozen in glass.*

Every reverse-engineering tool shows confident-looking output built from guesses. Fulgurite
attaches a calibrated **confidence** and its **evidence** to every claim it makes, can answer
*"why does it say this?"* for any line of pseudocode, and lets you reject any inference so it
stays rejected. A **Question Mode** helps beginners know where to look.

## Status

Milestone M0 ("Inspect") done. Milestone M1 ("Functions") in progress.

- Step 1 done: ELF header and program headers ([notes](docs/progress/m0-step1.md))
- Step 2 done: sections, symbols, versions, canary and FORTIFY ([notes](docs/progress/m0-step2.md))
- Step 3 done: relocations, notes, libraries, CFI / separate-code / library-path checks ([notes](docs/progress/m0-step3.md))
- Step 4 done: the PE loader, code seeds for both formats ([notes](docs/progress/m0-step4.md))
- Step 5 done: the x86 / x86-64 decoder and `fulg disasm` ([notes](docs/progress/m0-step5.md))
- Step 6 done: the AArch64 decoder, generated from Arm's machine-readable specification ([notes](docs/progress/m0-step6.md))

M1:

- Step 1 done: the fact store, every claim with status, confidence and evidence ([notes](docs/progress/m1-step1.md))
- Step 2 done: the analysis cache in SQLite ([notes](docs/progress/m1-step2.md))
- Step 3 done: `.eh_frame` and the seed pass ([notes](docs/progress/m1-step3.md))
- Step 4 done: CFG recovery and `fulg functions` ([notes](docs/progress/m1-step4.md))
- Step 5 done: no-return analysis ([notes](docs/progress/m1-step5.md))
- Step 6 done: jump tables, register values, AArch64 address pairs and PLT stubs ([notes](docs/progress/m1-step6.md))
- Step 7 done: cross-references and `fulg xrefs` ([notes](docs/progress/m1-step7.md))
- Step 8 in progress: the corpus measurement against IDA and Binary Ninja; the tools are
  ready, the full run is next ([notes](docs/progress/m1-step8.md))

See [`CHANGELOG.md`](CHANGELOG.md).

- Architecture design: [`docs/design.md`](docs/design.md)
- v1 scope: x86-64 + ARM64, ELF + PE
- Stack: Rust core, Python API (PyO3), Tauri + React GUI

## Build and run

Requires Rust 1.88 or newer.

```sh
cargo build --release
./target/release/fulg info /bin/ls
./target/release/fulg info --json /bin/ls
./target/release/fulg sections /bin/ls
./target/release/fulg symbols --imports /bin/ls
./target/release/fulg relocs --slots /bin/ls
./target/release/fulg notes /bin/ls
./target/release/fulg seeds /bin/ls
./target/release/fulg info program.exe        # PE: Windows executables, DLLs, UEFI images
./target/release/fulg imports program.exe
./target/release/fulg exports library.dll
./target/release/fulg resources program.exe
./target/release/fulg disasm /bin/ls              # every code section, like objdump -d
./target/release/fulg disasm /bin/ls main         # one function (or `entry`, or 0xADDR -n 20)
./target/release/fulg disasm --att --json program.exe
./target/release/fulg functions /bin/ls         # recovered functions, confidence, evidence
./target/release/fulg xrefs /bin/ls main        # who calls, reads, writes or points to it
```

## Development

```sh
cargo test --workspace                                  # unit, hostile-input, oracle, mutation and CLI tests
cargo clippy --workspace --all-targets -- -D warnings   # lint
cargo xtask layers                                      # enforce crate layering
cargo +nightly fuzz run load                            # fuzz the loaders (needs cargo-fuzz)
cargo +nightly fuzz run disasm                          # fuzz the decoders and listing
cargo +nightly fuzz run functions                       # fuzz function recovery (seeds, CFG, no-return, tables)
cargo +nightly fuzz run xrefs                           # fuzz cross-references
tools/fuzz/seeds.sh                                     # rebuild the seed corpora in fuzz/corpus/
tools/measure/corpus.sh corpus                          # build the measurement corpus with its true function lists
cargo run --release -p xtask -- measure corpus          # score function recovery against them (and IDA's, Binary Ninja's)
```

The oracle tests compare against `readelf` and, when installed, `checksec`; they
also compile test binaries with `gcc`. The PE oracle compares against `llvm-readobj`
and `objdump -p`, building test images with any installed MinGW toolchain (llvm-mingw
or GNU MinGW). The disassembly oracle compares every instruction with `objdump -d`
(`FULG_DISASM_CORPUS` and `FULG_DISASM_MAX_LINES` widen it, `FULG_OBJDUMP` picks
another binutils). The AArch64 oracle compares the decoder with `llvm-mc` 23 or newer
(`FULG_LLVM_MC`, `FULG_A64_ORACLE_WORDS`, `FULG_A64_ORACLE_PER_ENCODING`,
`FULG_A64_ORACLE_SEED`) and ARM64 listings with `llvm-objdump`, building ARM64 ELF
and PE files with clang and the `rust-lld` that Rust toolchains ship. Missing tools
are skipped with a note.

The AArch64 decoder tables (`crates/fg-arch-arm64/src/tables.rs`) are generated from
Arm's A-profile Machine Readable Specification (JSON) and the A64 ISA XML, which are
not stored here; see [step 6](docs/progress/m0-step6.md#regenerating-the-tables):

```sh
python3 -I tools/arm64/gen.py --mrs AARCHMRS_DIR --xml ISA_A64_xml_DIR
```

## Layout

```
crates/fg-core      foundation types: addresses, spans, bounds-checked bytes, anomalies
crates/fg-loader    ELF and PE loaders, format-neutral model, mitigation verdicts
crates/fg-ir        architecture-neutral instruction model and the Arch trait
crates/fg-arch-x86  x86 / x86-64 decoding and formatting (iced-x86)
crates/fg-arch-arm64 AArch64 decoding and formatting, tables generated from Arm's specification
crates/fg-facts     facts: claims, confidence, evidence, the dependency graph
crates/fg-store     the analysis cache (SQLite)
crates/fg-analysis  analysis passes: seeds, CFG and function recovery
crates/fg-service   the one API every front end uses (incl. disassembly listings)
crates/fg-cli       the `fulg` command
xtask               repository tasks (layering check, function-recovery scoring)
tools/arm64         generator of the AArch64 decoder tables
tools/fuzz          seed corpora for the fuzz targets
tools/measure       the measurement corpus, IDA Free export, server setup
fuzz                libFuzzer targets
docs                design document and progress notes
```

## Licence

Proprietary. Copyright © 2026 Naved. All rights reserved.
No licence is granted to use, copy, modify or distribute this repository's contents.
The licensing model (e.g. open core) will be decided before any public release.
