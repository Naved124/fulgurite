# M0 step 6: the AArch64 decoder

Status: **done** (2026-10-11), including the exhaustive 2³² comparison (see "Verification"). Builds on [step 5](m0-step5.md).

## Goal

Decode AArch64 (A64) machine code behind the same `Arch` trait as x86, with the
decoder **generated from Arm's machine-readable specification** (design §7.3, §22).
The aim is that coverage keeps up with new architecture extensions by regenerating.
Check it against LLVM's disassembler, and make `fulg disasm` list ARM64 ELF and PE files.

## What was added

| Area | Details |
|---|---|
| Generator (`tools/arm64/gen.py`) | Standard-library Python. Reads Arm's A-profile **Machine Readable Specification** (open-source JSON build, BSD-3-Clause) and the **A64 ISA XML** of the same release (2026-09), and writes `crates/fg-arch-arm64/src/tables.rs`. Neither input is stored in the repository. The script stops with a list of problems if a new release contains something it does not understand |
| From the JSON | The decode tree (groups, encodings, fixed and should-be bits, field conditions), every encoding's assembler grammar, alias conditions and preferences, and the system register encodings (`Registers.json`) for MRS/MSR names |
| From the XML | What each operand means: which fields encode it and how ("encoded as `Zn` times 4 plus 1", "a multiple of 8 in the range −512 to 504", value tables, `RESERVED` values, "When option<0> is set to 1"). Also the decode and post-decode pseudocode, translated to Rust by a small ASL translator (let/var, if/elsif/else, case, expressions over fields): 1,800 checks for UNDEFINED encodings and for CONSTRAINED UNPREDICTABLE cases. Plus the `SysOp()` tables that decide the DC/IC/AT/TLBI aliases, completed from `Registers.json` (see decision 6) |
| `fg-arch-arm64` (new crate, layer 2) | Interprets the tables: walks the decode tree, applies the UNDEFINED checks, picks the preferred alias, renders the template into typed tokens. 4,393 encodings, 314 aliases, every architecture feature enabled. Also: `is_unpredictable(word)`, `encodings()`, `encoding_name(word)`, `system_register(enc, write)` / `system_register_names()`, and the `adrp` / `load_offset` helpers for address pairs |
| Listing | `fulg disasm` on AArch64 ELF and PE (`arch_for(Aarch64)`). PLT stubs are named `name@plt` from their `adrp x16` + `ldr x17, [x16, #off]` pair. Arm mapping symbols (`$x`, `$d`) are no longer used as names. Instructions that print their own address (`adrp`, `adr`, literal loads) get only `<name>` after it |
| Fuzzing | The `disasm` target also decodes and formats the input as A64 words |

### Text

The text is Arm assembler syntax in lower case, as `llvm-mc` prints it:
- immediates are in decimal, except logical (bitmask) immediates and the 16-bit operands of `svc`/`hvc`/`smc`/`brk`/`hlt`/`dcps`, which are hexadecimal;
- branch, `adr`/`adrp` and literal targets are absolute addresses;
- optional parts are left out at their default (`ldr x0, [x1]`, `ret`, `add x0, sp, x1` when the LSL shift is zero);
- aliases follow Arm's preferred disassembly (`mov`, `cmp`, `lsl`, `ubfx`, `cinc`, `dc civac`...);
- an alias whose condition is a special case of another's comes first (most specific first);
- system instructions never hide their register. `{, <Xt>}` is left out at XZR only for an operation that reads no register (`tlbi vmalle1`, `ic iallu`, `gic cdeoi`); one that does shows it (`tlbi vae1, xzr`, `ic ivau, xzr`). An alias without a register operand (`gcspushx`, `brb iall`, `gsb ack`) is used only when Rt is 31; otherwise the word prints as `sys ..., xN`;
- MRS/MSR name a register defined only in the other direction (`msr icc_ppi_hmr0_el1, x0`, a write to a read-only register, which is UNDEFINED but has a known target).

## Decisions that avoid rebuilding later

1. **Generated, not hand-written.** Every encoding, alias rule, value table and reserved-value check comes from Arm's data. A new release is a regeneration. The few things the data leaves to prose are hand-written in the generator, listed by name (`OVERRIDES`, the operand patterns), and checked by the oracle:
   - bitfield-alias operands;
   - `mov` wide immediates;
   - ISB's option;
   - SME `zero` tile lists.
2. **The XML stays outside the repository.** Only the derived Rust is committed. The JSON's BSD notice is reproduced in the generated file.
3. **Encodings the XML does not describe yet are left out, not guessed.** 61 encodings in the 2026-09 JSON (FEAT_FPv2, MOPS_GO, TEV, SME F16F8F16...) have no XML pages:
   - 24 have only plain register operands and every other bit fixed, so they are compiled from the JSON alone;
   - the other 37 are reported invalid (`encodings_not_decoded()`) until Arm publishes their pages.
4. **CONSTRAINED UNPREDICTABLE encodings decode.** This covers should-be bits that differ, overlapping registers in load pairs and MOPS, and writeback to a loaded register. These words decode as the instruction they name, as most hardware does, and `is_unpredictable` reports them. LLVM rejects many of them.
5. **Where Arm's pseudocode and its own description disagree, the description wins, documented.** `MoveWidePreferred()`'s halfword test misses some rotations: for `0xf801ffff`, which `movn w0, #0x7fe, lsl #16` builds, it says no. Fulgurite tests what the function says it tests, as GNU and LLVM do.

6. **Two specification sources for system instructions, checked against each other.** The 2026-09 XML's `SysOp()` leaves out operations that `Registers.json` defines (DC ZGBVA, GBVA, CVAOC, CGDVAOC, CIVAOC, CIGDVAOC; TLBI VMALLWS2E1*; every PLBI), so their aliases never applied. The generator adds them from `Registers.json` and stops if the two sources give an operation different kinds. Whether an operation reads its register also comes from `Registers.json` (a named field outside any feature condition). PLBI has no XML page; its alias is compiled from the JSON grammar, whose rule names carry each operation's encoding.
7. **No alias hides an encoded bit.** Arm marks some system aliases preferred "unconditionally" although their template has no register; for other Rt values the text would lose bits. Such an alias applies only at Rt 31.

## Problems found and fixed during this step

| Found by | Problem | Fix |
|---|---|---|
| Oracle | Template operands that the XML explains only in prose: `<Zn2>` "encoded in the Zn field" is really Zn+1 mod 32 (16 for predicates); SVE shifts and indexes depend on the element size in `tsz`; `<W(s+1)>` register pairs; SME2 narrowing shifts | List-member, `tsz` and register-pair rules; shifts are taken from the decode pseudocode's own `shift` expression when it has one |
| Oracle | Reserved encodings decoded (`size = 11` arrangements, 32-bit forms with bit 5 of a shift set, `sdot` with the wrong size...) | Value-table `RESERVED` rows, prose ranges as validity constraints, and the translated decode pseudocode |
| Oracle | LDP with equal registers, post-index writeback to the loaded register: not flagged | The XML's shared "Postdecode" sections are part of each encoding's decode; an assigned `c = ConstrainUnpredictable(...)` counts |
| Oracle | MOPS overlapping registers: the check is in the execute pseudocode, through a shared function | Those calls are inlined with their parameters bound to the encoding fields |
| Oracle | `add wsp, w1, w2, uxtw` printed as `lsl` for the flag-setting forms too | The XML's rule text decides: LSL when Rd or Rn is SP, or only Rn for ADDS/SUBS (Rd 31 is the zero register there) |
| Tests | Arm mapping symbols named data (`adr x0, 0x3b8 <$d>`) | Not used as names |
| Exhaustive comparison | `msr pm, #2` / `#3`: PM's immediate is CRm<0> ("Restricted to the range 0 to 1, encoded in CRm<0>, when <pstatefield> is ... PM"), not the whole CRm | The prose rule is read: the operand's encoding depends on the row the other operand's table gives |
| Exhaustive comparison | DC ZGBVA/GBVA/CVAOC/CGDVAOC/CIVAOC/CIGDVAOC, TLBI VMALLWS2E1* and PLBI printed as `sys` | Decision 6 |
| Exhaustive comparison | `gcspushx`, `gcspopx`, `gcspopcx`, `brb iall/inj`, `gsb sys/ack` dropped Rt when it was not 31 | Decision 7 |
| Exhaustive comparison | `tlbi vae1`, `ic ivau`, `gic cdaff`... with XZR printed without the register they read | Registers.json decides whether an operation reads it (see "Text") |
| Exhaustive comparison | The oracle test matched llvm-mc's output by re-encoded bytes, so a word llvm-mc decodes as a different encoding was never compared; it also ignored llvm-mc's "potentially undefined" decodes | Output lines are matched by position, using llvm-mc's per-line diagnostics |

## Verification

| Check | Result |
|---|---|
| LLVM oracle (`llvm-mc 23 --disassemble -mattr=+all`), committed test `fg-arch-arm64/tests/llvm_oracle.rs` | 60,000 random words, 3 words from inside every encoding, every SYS/SYSP operation of CRn 7 to 12 (Rt 0 and 31) and every MRS/MSR register encoding (163,179 words) on every `cargo test`; 0 unexplained differences. System register and system operation rules are checked against the specification's names (`system_register_names()`) and our own Rt 31 text, not string patterns |
| Exhaustive 2³² | Every 32-bit word compared with LLVM 23 (in process, `MCDisassembler`, including its SoftFail decodes) and GNU binutils 2.47 (`libopcodes`). 4,294,967,296 words: 99.70% same text or both invalid; every other word in an accepted category below, each checked against Arm's specification; the 4,357 that were not found the bugs listed above, now fixed, and re-comparing the changed regions gives 0 unexplained |
| Before/after fingerprint | A hash of (encoding, UNPREDICTABLE flag, text) for every word, per 2¹⁶-word chunk, before and after each generator fix: the PM fix changed exactly 2 words; the system instruction fixes changed exactly 8 of 65,536 chunks, all in the SYS/SYSP space |
| Hidden-bit audit | Every word of the 262 encodings with aliases (284 million), each free bit flipped: two words with the same encoding and the same text occur only for bits Arm's own decode ignores (`immr` bits above the element size in `DecodeBitMasks()`, `DUP`/`INS` index bits below the element size) |
| Accepted differences (counted by category) | Same text after normalising number spelling (decimal vs hexadecimal, `#a, lsl #8` vs the product, register ranges `{z1.d - z3.d}`) · should-be bits that LLVM rejects and accepts once corrected to the same text · bits the table marks "x" that LLVM requires to be zero (verified by clearing them) · CONSTRAINED UNPREDICTABLE words · mnemonics LLVM 23 does not know (checked by assembling) · encodings newer than the XML · op0 = 0/1 system space that LLVM prints as generic `msr s0_...` and Arm leaves unallocated · system register names LLVM knows but `Registers.json` does not list (trace registers that are now external-only), and registers newer than LLVM 23 · a register shown on a system operation that reads none (`tlbi alle3, x0`; LLVM prints `sys`) · writes naming a read-only register (policy, counted separately) · alias choices where LLVM departs from Arm's preferred form (`bfi wzr` for `bfc`, `sshll #0` for `sxtl`, `bti r`, `dfb`, `subps xzr` for `cmpp`) |
| Listing vs `llvm-objdump -d` | Every instruction in an ARM64 shared library (lazy PLT), a static executable and a PE32+ ARM64 DLL, built in the test with clang and the LLD that Rust toolchains ship (`rust-lld`): same address, encoding and mnemonic |
| Decoder semantics | 11 tests: exact text (65 encodings), absolute targets, typed tokens, every `Flow` kind, memory operands (`adr`, `adrp`, literal loads with sizes, `prfm`), immediates, truncated/invalid/reserved/UNDEFINED words, CONSTRAINED UNPREDICTABLE, address pairs, a sweep of 400,000 words (deterministic, four bytes, always printable), every encoding reachable |
| Listing semantics | 4 tests: `puts@plt`/`abort@plt` stubs and calls, functions, flow and mapping symbols, object file, PE ARM64 |
| Total | 167 tests (19 new); clippy, rustdoc and rustfmt clean; layering checked |

## Known limitations

- 37 encodings newer than the 2026-09 XML are not decoded. FEAT_FPv2 and MOPS_GO are among them; LLVM 23 decodes SETGO*.
- The listing decodes data inside code sections (`$d` regions, literal pools) as instructions. Using mapping symbols to show data is an analysis step (M1).
- `adrp` + `add`/`ldr` pairs are resolved only in PLT stubs; the general pair fusion (design §7.3) is part of M1.
- A function named by an export without size or exception-table entry (leaf functions in PE) is listed to the end of its section.
- The oracle needs LLVM 23 or newer (Ubuntu 24.04's packaged LLVM 18 predates the 2026 extensions); CI installs LLVM 23 from apt.llvm.org, so it runs there too.

## Regenerating the tables

Download the two inputs from Arm's A-profile exploration tools, unpack them anywhere, and run:

```
python3 -I tools/arm64/gen.py --mrs AARCHMRS_DIR --xml ISA_A64_xml_A_profile-VERSION_DIR
```

`AARCHMRS_DIR` holds `Instructions.json` and `Registers.json`; the XML directory holds `shared_pseudocode.xml` and one XML file per instruction.

## Fuzzing result

Both libFuzzer targets ran for 24 hours each on commit b8dbf6a: `load` (both loaders)
for about 10.6 million inputs and `disasm` (both decoders, the formatter and the
section listing) for about 0.46 million, with no crashes, timeouts or out-of-memory
reports.

A second 24-hour run on commit d6c890e started from larger seeds (real ELF, PE and
UEFI files up to 1 MB) with inputs up to 1 MB: `load` ran about 11.5 million inputs
and `disasm` about 1.4 million, reaching 15% and 13% more coverage than the first run.
It found no crash that reproduces, but three ways for a crafted file to make loading
slow or use gigabytes of memory, all fixed: PE import descriptors sharing one long
lookup table (now bounded by a limit on imports in all), ELF files with many
relocation tables over the same bytes (a limit on relocations in all), and relocation
places looked up by scanning every program header (now an index built once).

## Next step

The M0 exit: 24-hour fuzzing of both loaders and both decoders, and the exhaustive A64 comparison.
