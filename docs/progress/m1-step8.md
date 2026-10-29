# M1 step 8: measuring function recovery

Status: **in progress** (2026-10-29). The tools are ready; the full run on the
measurement server is next. Builds on [step 7](m1-step7.md).

The M1 exit criterion (design §23) is function-boundary recall ≥ 95% on a stripped
`-O2` gcc/clang corpus against symbol ground truth. This step builds that corpus and
much more around it, and scores Fulgurite, IDA Free and Binary Ninja Free on it, so
each tool's numbers are measured the same way against the same truth (design §1.5).

## The corpus

`tools/measure/corpus.sh OUT` downloads 12 pinned open-source programs (SHA-256
checked) and builds them in 36 configs:

| Programs | Language | Built in |
|---|---|---|
| GNU coreutils 9.5, grep 3.11, sed 4.9, diffutils 3.10, findutils 4.10.0, gawk 5.3.1, jq 1.7.1 | C (autotools) | every Linux config |
| groff 1.23.0 | C++ (autotools) | every Linux config but AArch64 (its build runs what it built) |
| SQLite 3.46.1, Lua 5.4.7, zlib 1.3.1, bzip2 1.0.8 | C | every config, Windows too |
| Lua 5.4.7 compiled as C++ | C++ (errors are exceptions) | every config, Windows too |
| `fulg` (this repository) | Rust | `rust-O0`, `rust-O3`, `rust-O3-lto` |
| `gofmt`, `addr2line`, `nm`, `objdump` from the Go distribution | Go | `go-amd64`, `go-386`, `go-arm64` |

| Configs | What they exercise |
|---|---|
| `gcc-O0` … `gcc-Os`, `clang-O0` … `clang-Os`, `clang-Oz` | every optimisation level; `gcc-O2` and `clang-O2` are the M1 gate |
| `gcc-O2-static`, `clang-O2-static` | static glibc: IFUNCs, hand-written assembly |
| `gcc-O2-lto`, `clang-O2-lto` | whole-program inlining, cloning, reordering |
| `gcc-O2-nounwind`, `clang-O2-nounwind` | no `.eh_frame`: no FDE seeds |
| `gcc-O2-nopie`, `clang-O2-nopie` | fixed-address executables |
| `gcc-O2-sections` | `-ffunction-sections` with `--gc-sections` |
| `gcc-O2-nocet`, `clang-O2-cet` | no `endbr64` at function entries, and `endbr64` with clang |
| `gcc-O2-m32`, `clang-O2-m32`, `gcc-O0-m32` | 32-bit x86, PIC through the GOT pointer |
| `aarch64-clang-O0`, `aarch64-clang-O2` | AArch64 (clang only: Ubuntu's gcc cross compilers conflict with `gcc-multilib`) |
| `mingw64-O0`, `mingw64-O2`, `mingw32-O2` | PE, 64- and 32-bit |

Every binary is kept three ways:

```
OUT/bin/<config>/<program>-<binary>         stripped: what every tool analyses
OUT/debug/<config>/<program>-<binary>       the same build with its symbols
OUT/truth/<config>/<program>-<binary>.txt   the true functions, "0xVA name"
```

### Ground truth

The true list comes from the unstripped build's symbol table, read by GNU binutils
(`readelf -sW`, and `objdump -t` with `nm` for PE), not by Fulgurite's own loader:

- ELF: every defined `FUNC` or `IFUNC` symbol in a section with the `X` flag;
- PE: every COFF symbol of type 0x20 (function) defined in a code section;
- aliases at one address count once;
- `*.cold` symbols are left out: gcc's hot/cold splitting makes them, and they are
  parts of another function (Fulgurite reports them as fragments);
- Go's `runtime.etext`, a function symbol marking the end of the code, is left out.

Stripping (`llvm-strip --strip-all`) must not move anything: each stripped copy's
loaded segments (ELF) or section addresses (PE) are compared with the unstripped
build's, and a binary that differs, or has no function symbols, is dropped and logged.

What symbol truth does not see: code no symbol names. PLT stubs are the main case, and
the scorer leaves PLT sections out of every tool's list. Compiler or linker stubs with
no symbol count against every tool's precision alike.

## Scoring

`cargo run --release -p xtask -- measure OUT` (also `cargo xtask measure`, in a debug
build):

- runs Fulgurite (`Session::functions`) on every stripped binary, in parallel, and writes
  its list next to the binary (`.fulg.txt`);
- reads IDA's list from `<binary>.ida.txt` and Binary Ninja's from `<binary>.bn.txt`
  where they exist (one function per line, entry address first);
- leaves out of every list entries outside executable segments (IDA's import stubs in
  `extern`) and in PLT sections;
- counts a function when its entry address is a true entry.

It writes `OUT/results.md` and `OUT/results.csv` (one row per binary and tool):

- recall and precision per config, for the M1 gate (`gcc-O2` and `clang-O2`) and
  overall;
- Fulgurite against each other tool, on the binaries that tool has a list for. "Of
  IDA's" there is the share of the true functions IDA found that Fulgurite found too;
- the 25 binaries where Fulgurite misses most, with the first names missed.

## IDA Free

IDA Free 9.4 SP1 (build 9.4.260915) has no batch mode (`-A` says "This version of IDA
does not support the batch mode"), no `-S` scripts and no IDAPython. It has no ARM
decoders either. `tools/measure/ida-export.sh OUT/bin` drives the GUI instead:

- each IDA runs on its own invisible X screen (Xvfb), `JOBS` at once;
- xdotool presses Enter at the load dialog (default options: PIE files load at image
  base 0, as the true lists have them);
- it then types `fulg_export.idc`'s code, on one line, into IDA's IDC command line.
  File > Script file opens a dialog that Xvfb draws black, so that route is not used;
- the code waits for auto-analysis, writes `<binary>.ida.txt` and closes IDA;
- AArch64 binaries are skipped;
- a binary that has not finished after `TIMEOUT` seconds is killed, listed in
  `ida-export-failed.txt`, and screenshotted.

Checked on the user's machine: two test binaries, 126 functions each, 9 s each.

## Binary Ninja Free

Binary Ninja Free has no API and no headless mode, so its lists are made by hand on a
subset of the x86 binaries. The scorer reads `<binary>.bn.txt` in the same format
(entry address first). How to get the function list out of the Free GUI is still to be
settled.

## Running it

On an Ubuntu 24.04 server (`c7i.8xlarge`, 32 vCPU and 64 GB, 100 GB disk was the plan):

```sh
git clone https://github.com/Naved124/fulgurite && cd fulgurite
tools/measure/setup-ubuntu.sh && . ~/.cargo/env
tools/measure/corpus.sh ~/corpus                         # builds and true lists
# install IDA Free (its .run file) and copy ~/.idapro/ida.hexlic from a licensed machine
JOBS=32 tools/measure/ida-export.sh ~/corpus/bin         # IDA's lists
cargo run --release -p xtask -- measure ~/corpus         # ~/corpus/results.md
```

## Sample run

A sample was built and scored in a development container (4 cores): 1668 binaries in
18 configs, not all programs in each. Fulgurite only:

| config | binaries | true functions | recall | precision |
|---|--:|--:|--:|--:|
| M1 gate (gcc-O2, clang-O2) | 164 | 33755 | 99.94% | 99.98% |
| gcc-O0, gcc-O1, clang-O0 | 448 | 108209 | 100.00% | 100.00% |
| gcc-O3 | 154 | 27942 | 100.00% | 99.94% |
| gcc-Os | 154 | 33082 | 99.93% | 100.00% |
| gcc-O2-lto | 148 | 11069 | 100.00% | 99.95% |
| clang-O2-lto | 148 | 9820 | 100.00% | 99.99% |
| gcc-O2-static | 146 | 198011 | 99.92% | 99.92% |
| gcc-O2-m32 | 10 | 5463 | 100.00% | 99.82% |
| aarch64-clang-O2 | 125 | 20829 | 96.69% | 95.36% |
| **clang-O2-nounwind** | 148 | 25128 | **63.16%** | 98.35% |
| mingw64-O2 | 9 | 6614 | 99.70% | 94.19% |
| mingw32-O2 | 9 | 6679 | 90.85% | 76.47% |
| go-386 | 4 | 12282 | 90.91% | 85.00% |
| rust-O3 | 1 | 3825 | 100.00% | 100.00% |

What it shows before the full run:

- With `.eh_frame`, Fulgurite finds nearly every function: the FDEs name them.
- **Without unwind tables it misses a third of them.** Functions reached only through
  pointers or tail calls have no other seed (`sed`: 161 of 196 missed). This is the
  first thing to fix; the gcc `-fno-asynchronous-unwind-tables` builds will show the
  same.
- 32-bit PE, Go and AArch64 are weaker too; why is not looked into yet.

These numbers are not the measurement; the full corpus run, with IDA's lists, replaces
them.
