# M0 step 5: the x86 decoder and `fulg disasm`

Status: **done** (2026-10-10). Builds on [step 4](m0-step4.md).

## Goal

Decode x86-64 (and 32-bit x86) machine code behind the architecture-neutral `Arch`
trait the design calls for (§7.1), and give Fulgurite a disassembly listing that can
replace `objdump -d`, checked against it instruction by instruction. The listing starts
from what the loaders already know (sections, symbols, code seeds, import slots), so its
output is already annotated.

## What was added

| Area | Details |
|---|---|
| `fg-ir` (new crate, layer 1) | The neutral instruction model: `Insn` (address, bytes, mode, `Flow`, explicit memory operand, first immediate, padding flag), `Flow` (next, jump, branch, call with targets; indirect jump/call; return; interrupt; trap), `MemRef` (resolved address for PC-relative and absolute operands, displacement, size, access, conditional, segment-based), `DecodeError` (truncated, invalid, unsupported mode), typed display `Token`s and `Syntax`. The `Arch` trait with `id`, `max_insn_len`, `insn_alignment`, `decode`, `format`. The lifted IR joins this crate in M2 |
| `fg-arch-x86` (new crate, layer 2) | x86 and x86-64 through `iced-x86` (design §22.4), in 16-, 32- and 64-bit modes. Formatting options fixed so Intel syntax reads like `objdump -M intel` (`0x` hex, `[rip+0x2f1a]`, `qword ptr`, `*1` scales, zero displacements, ignored prefixes such as `cs` on padding); AT&T available. Corrections over iced's output: far pointers as `selector:offset`, `F2`/`F3` shown once when they mean `xacquire`/`xrelease` |
| Listing (`fg-service::disasm`) | Linear sweep of every executable section (segments when a file has no sections), one section, a function by name (to its symbol size or exception-table end), `count` instructions from an address, or an address range. Decoding restarts at every label and seed, so padding or data before a function cannot misalign it; an instruction a label starts inside is shown whole and flagged. Invalid bytes are skipped one at a time; an instruction cut off by the end of the code is reported as such. Object files list each section from 0 |
| Names | Labels from defined symbols (function and static-table names first) and code seeds (entry point, constructors, TLS callbacks, exception-table functions...); `name@plt` for ELF PLT stubs (`.plt`, `.plt.sec`, `.plt.got`), found by decoding each stub's jump and reading which import slot it uses; branch targets as `<sym>` / `<sym+0x10>`; memory operands that reach an import slot as `[puts@GLIBC_2.2.5]` / `[KERNEL32.dll!ExitProcess]`, other known addresses as `<obj+0x8>` |
| Streaming | `Session::disassemble_each` produces the listing one line at a time; `fulg disasm` prints as it goes. All of `libLLVM` (172 MB) is listed in 28 s with 286 MB peak memory, most of it the file itself |
| CLI | `fulg disasm FILE [FUNCTION \| entry \| 0xADDR] [-s SECTION] [-n COUNT] [--end 0xADDR] [--att] [--json]`; JSON schema `fulgurite.disasm.v1` (one object per line: region, label with seeds, instruction with its tokens and text, bad bytes with the reason). Every command now ends quietly when its output pipe closes (`fulg ... \| head`) instead of panicking |
| Fuzzing | New libFuzzer target `disasm`: raw bytes decoded and formatted in all three modes, then the input loaded as a file and every code section listed |

## Decisions that avoid rebuilding later

1. **The instruction model is neutral, and text is produced on demand.** `Insn` holds only
   facts that analyses need (flow, targets, the memory address an operand reaches), and
   stores its bytes so `format` can re-decode. Listings, CFG recovery (M1) and the lifter
   (M2) all share it; nothing stores strings per instruction.
2. **Tokens, not strings.** Mnemonic, register, number, address, symbol and comment tokens
   carry values, so the GUI can link addresses and colour registers, and names can be
   swapped without parsing text.
3. **The listing is an API of the service layer.** Front ends call
   `Session::disassemble(_each)` with a `Target`; M1 replaces the sweep with recursive
   descent behind the same `Line` type.
4. **Streaming from the start.** A library can have tens of millions of instructions; the
   listing never needs to exist in memory as a whole.
5. **Hardware behaviour wins over tool convention.** Where objdump and the CPU disagree on
   what an instruction is, the listing follows the CPU (see below), and the oracle accepts
   only those documented cases.

## Problems found and fixed during this step

| Found by | Problem | Fix |
|---|---|---|
| Decoder tests | an invalid opcode at the very end of the input (`06` in 64-bit mode) was reported as "truncated": iced asks for more bytes before rejecting it | Re-decode with zero padding to tell cut-off from invalid |
| Decoder tests | `syscall` was classified as an indirect call | System calls are interrupts: control returns to the next instruction |
| Decoder tests | `hlt` fell through | `Trap`: it faults in user mode |
| Decoder tests | sign-extended immediates of 32-bit instructions were extended to 64 bits (`push -0x10` gave `0xfffffffffffffff0`) | Immediates are kept at their operand size |
| Decoder tests | AT&T text printed `(%rbx,)` (scale option without an index register) | The scale is forced only in Intel syntax |
| objdump oracle | `xacquire lock repne add`: the `F2` byte named twice | One word per prefix byte |
| objdump oracle | far pointers printed as `far 0x1000,0x10` | `far 0x10:0x1000` |
| Listing tests | a PLT stub label landed on the padding before the stub, so calls read `<puts@plt+0x6>` | A stub starts at its first instruction that is not padding |
| Listing tests | an address with no file bytes produced an empty listing | `DisasmError::Unmapped` |
| A run on `libLLVM` | the first oracle held objdump's whole output and the whole listing in memory: several GB on a 172 MB library, enough to stall the machine | objdump is read line by line with a per-file cap, the listing is streamed and only the overlapping part kept (94 MB peak); the CLI streams too |
| objdump oracle | where debuginfod is configured (Arch Linux), objdump downloaded separate debug files during the test and used symbols the file does not contain | The oracle runs objdump with `DEBUGINFOD_URLS` empty: offline, file symbols only |
| First CI run | Ubuntu's binutils 2.42 spells things differently (`eiz`/`riz`, `retf`, `iret`, `fneni(8087 only)`), does not know SALC or the undocumented x87 aliases, already decodes APX, and its libcrypto has data in `.text` that exercises #UD encodings | Reproduced in a container; each case classified, every one but APX in iced's (the CPU's) favour |

## Verification

| Check | Result |
|---|---|
| objdump oracle (`objdump -d -M intel`), every instruction: address, bytes and normalised text | 4,996,181 instructions from libavcodec (AVX-512, VNNI), libLLVM, libstdc++, libcrypto (SHA, AES, AVX-512 IFMA), libc, libm, libgcc_s, bash and ls (first 1.5 million per file), no difference. The default run in `cargo test` (fixtures + system binaries, 150,000 lines per file) compares 622,601 |
| Fixtures | Two assembly files covering every instruction family: system, string, x87, SSE–SSE4, AES/SHA/CLMUL, AVX/AVX2/FMA, AVX-512 (masking, zeroing, broadcast, rounding, compressed disp8), AVX-VNNI, TSX, CET, MPX `bnd`, BMI, far pointers, the 32-bit-only instructions, and byte sequences decoders disagree on. Each built as an ELF object, an ELF shared library and (with MinGW) a PE32/PE32+ executable |
| Two binutils versions | Local binutils 2.47 and CI's Ubuntu 2.42 (reproduced in an Ubuntu 24.04 container with GNU MinGW): 592,230 instructions on CI's files, no unexplained difference. `FULG_OBJDUMP` selects another objdump |
| Accepted objdump differences | Each checked byte by byte, all cases where iced follows the CPU: `wait` + x87 pairs objdump prints as one macro (`fstcw`); redundant REX prefixes objdump prints as separate lines; instructions objdump cuts at a label (`.byte`); encodings that raise #UD (LOCK on a register or `mov`, nonexistent segment registers, `mov cs`) which objdump still decodes; the realignment after invalid bytes. One is a gap on our side: Intel APX (REX2, r16–r31), decoded by binutils 2.42+ and not by iced 1.21. Spelling rules (case, `movabs`, `pushfq`, `retf`, `iret`, x87 `st` operands, `eiz`/`riz`, string-instruction suffixes, broadcast and rounding notation, ignored prefixes...) are listed in `normalise` |
| Decoder semantics | 9 tests: exact Intel and AT&T text, typed tokens, every `Flow` kind, memory operands (RIP-relative, absolute, `moffs`, `fs:`, AVX-512 disp8×N, 32/16-bit widths, access kinds, masked stores), immediates, padding, errors and modes |
| Decoder sweeps | Every two-byte prefix (65,536) in 16-, 32- and 64-bit mode, and 120,000 random inputs biased to EVEX/VEX/0F: length bounds, bytes echoed, end address, text in both syntaxes, decoding the instruction's own bytes gives the same result |
| Listing semantics | 6 tests: labels and seeds, an overlapping label, invalid and cut-off bytes, operand names, `puts@plt` in lazy-binding binaries with and without IBT, every target kind, object files, unsupported architecture, early stop |
| CLI | text, `-n`, `--att`, `--json` (schema, lines, tokens), errors with exit code 1, closed pipes, a PE |
| Total | 146 tests; clippy, rustdoc and rustfmt clean; layering checked |

## Where Fulgurite goes beyond common tools

- Decoding follows the CPU: a redundant REX prefix is part of the instruction, and `wait`
  is its own instruction.
- A symbol inside an instruction does not hide the instruction: objdump prints
  `.byte 0xb8` and moves on; Fulgurite shows the real instruction, flags the overlap, then
  decodes from the label too.
- Calls and jumps through import slots are named on every line (`[KERNEL32.dll!Sleep]`),
  not only where a symbol table happens to cover the slot.
- Code seeds are visible in the listing (entry point, constructors, TLS callbacks,
  exception-table functions, CFG targets).

## Known limitations

- After an instruction that a label starts inside, the listing continues from the label;
  the other decoding is not continued in parallel (M1 keeps both as facts).
- Object files are listed without labels or names: their symbols are section-relative.
- i386 PIC PLT stubs (`jmp [ebx+n]`) are not named yet.
- No ARM64 decoder yet (added in [step 6](m0-step6.md)); other architectures report "no decoder".
- Intel APX (REX2 prefix, extended registers r16–r31) is not decoded: iced 1.21 predates
  it. Such bytes are listed as invalid until iced (or a newer decoder) supports APX.
- The 24-hour fuzzing exit criterion is still open (see step 4): the loader target ran
  3.6 hours with no crash before the machine was shut down; a new 24-hour run is in
  progress. The `disasm` target has not been run long yet.

## Next step

M0 step 6: the ARM64 decoder (`fg-arch-arm64`), checked exhaustively against `llvm-mc` /
objdump as §21.1 describes, then the M0 exit run (24-hour fuzzing of both loaders and both
decoders).
