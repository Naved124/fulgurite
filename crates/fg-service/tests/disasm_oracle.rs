// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Cross-checks the disassembly listing against GNU `objdump -d -M intel`.
//!
//! For every instruction objdump prints, the listing must have an instruction at
//! the same address with the same bytes, and the same text once both are
//! normalised (case, number prefixes, symbol annotations, and the documented
//! spelling differences in `normalise`). Inputs: objects compiled here from
//! inline assembly covering every instruction family (64- and 32-bit), programs
//! built with gcc and any installed MinGW toolchain, and system binaries.
//!
//! Memory stays bounded however large an input is: objdump's output is read
//! line by line and capped per file, and our listing is streamed with only the
//! overlapping part kept. A missing tool skips its part with a note.

use fg_service::Session;
use fg_service::disasm::{Line, Options, Target};
use fg_service::ir::{Syntax, tokens_text};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One objdump instruction line.
struct Theirs {
    section: String,
    va: u64,
    bytes: Vec<u8>,
    text: String,
}

/// Most objdump lines compared per file, unless `FULG_DISASM_MAX_LINES` says
/// otherwise (memory grows with it: about 150 bytes per line).
const MAX_LINES_PER_FILE: usize = 150_000;

fn max_lines() -> usize {
    std::env::var("FULG_DISASM_MAX_LINES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_LINES_PER_FILE)
}

/// The objdump to compare with: `FULG_OBJDUMP` if set (another binutils
/// version, or a wrapper that runs CI's), else `objdump` from `PATH`.
fn objdump_command() -> String {
    std::env::var("FULG_OBJDUMP").unwrap_or_else(|_| "objdump".into())
}

fn objdump(path: &Path) -> Option<Vec<Theirs>> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = Command::new(objdump_command())
        .args(["-d", "-w", "-z", "-M", "intel"])
        // Offline and with the file's own symbols only: where debuginfod is
        // configured, objdump would download separate debug files and list
        // symbols the file does not contain.
        .env("DEBUGINFOD_URLS", "")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let reader = BufReader::new(child.stdout.take()?);
    let mut v = Vec::new();
    let mut section = String::new();
    for line in reader.lines() {
        let Ok(line) = line else {
            break;
        };
        if v.len() >= max_lines() {
            break;
        }
        if let Some(name) = line
            .strip_prefix("Disassembly of section ")
            .and_then(|r| r.strip_suffix(':'))
        {
            section = name.to_string();
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let (Some(addr), Some(hex)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(addr) = addr.trim().strip_suffix(':') else {
            continue;
        };
        let Ok(va) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .filter_map(|b| u8::from_str_radix(b, 16).ok())
            .collect();
        v.push(Theirs {
            section: section.clone(),
            va,
            bytes,
            text: parts.next().unwrap_or("").to_string(),
        });
    }
    let _ = child.kill();
    let _ = child.wait();
    (!v.is_empty()).then_some(v)
}

/// Prefix words that change nothing for the instruction that follows: objdump
/// writes them as words, iced as a segment on the operand (`cs nop [x]` /
/// `nop cs:[x]`), as a hint (`hint-taken jne`) or not at all (`addr32 call`).
fn ignored_prefix(w: &str) -> bool {
    matches!(
        w,
        "data16" | "addr32" | "cs" | "ds" | "ss" | "es" | "hint-taken" | "hint-not-taken" | "{vex}"
    ) || w.starts_with("rex")
}

/// Prefix words that matter and stay in the normalised form.
fn kept_prefix(w: &str) -> bool {
    matches!(
        w,
        "lock"
            | "rep"
            | "repz"
            | "repe"
            | "repnz"
            | "repne"
            | "bnd"
            | "notrack"
            | "xacquire"
            | "xrelease"
            | "fs"
            | "gs"
            | "data64"
    )
}

/// Brings both spellings to one form. Each rule is a known spelling difference
/// between iced's and binutils' Intel syntax; none hides a decoding difference
/// (bytes and lengths are compared separately).
fn normalise(text: &str, objdump: bool) -> String {
    let mut s = text.to_lowercase();
    // Annotations: `<sym>` and `# comment`.
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    while let (Some(a), Some(b)) = (s.find('<'), s.find('>')) {
        if a >= b {
            break;
        }
        s.replace_range(a..=b, "");
    }
    let mut s = s.replace("0x", "");
    // Notes binutils appends to obsolete x87 names: `fneni(8087 only)`.
    while let (Some(a), Some(b)) = (s.find('('), s.find(" only)")) {
        if a >= b {
            break;
        }
        s.replace_range(a..b + " only)".len(), "");
    }
    // binutils before 2.43 names a SIB byte without an index `eiz` / `riz`:
    // `[esi+eiz*1+0]` is `[esi+0]`.
    for pseudo in ["+eiz*", "+riz*"] {
        while let Some(i) = s.find(pseudo) {
            let end = i + pseudo.len() + 1;
            s.replace_range(i..end.min(s.len()), "");
        }
    }
    for pseudo in ["[eiz*", "[riz*"] {
        while let Some(i) = s.find(pseudo) {
            // `[riz*8+0x1000]` is `[0x1000]`.
            let end = i + pseudo.len() + 2;
            s.replace_range(i + 1..end.min(s.len()), "");
        }
    }
    let mut words: Vec<&str> = s.split_whitespace().collect();
    let mut prefixes: Vec<String> = Vec::new();
    while words.len() > 1 && (ignored_prefix(words[0]) || kept_prefix(words[0])) {
        let w = words.remove(0);
        if kept_prefix(w) {
            // f3 is rep / repe / repz and f2 is repne / repnz, whatever follows.
            prefixes.push(match w {
                "repz" | "repe" => "rep".into(),
                "repnz" => "repne".into(),
                _ => w.to_string(),
            });
        }
    }
    if words.is_empty() || (words.len() == 1 && ignored_prefix(words[0])) {
        return String::new();
    }
    let mut mnemonic = words.remove(0).to_string();
    let mut ops = words.join(" ");
    // iced `ret far` / `iretd`, binutils `retf` / `iret`.
    if mnemonic == "ret" && (ops == "far" || ops.starts_with("far ")) {
        mnemonic = "retf".into();
        ops = ops["far".len()..].trim().to_string();
    }
    if mnemonic == "iretd" {
        mnemonic = "iret".into();
    }
    // iced writes a far return with REX.W as `data64 ret far`.
    if mnemonic == "retf" && prefixes.iter().any(|p| p == "data64") {
        mnemonic = "retfq".into();
    }
    prefixes.retain(|p| p != "data64");
    // A prefix repeated (`f3 f3`, `64 64`) is named once per byte by objdump and
    // once by iced; a segment prefix already shown on the operand is not repeated.
    prefixes.dedup();
    prefixes.retain(|p| !(matches!(p.as_str(), "fs" | "gs") && ops.contains(&format!("{p}:"))));
    // `movabs` is objdump's name for `mov` with a 64-bit immediate or address;
    // `pushf` / `popf` in 64-bit code are iced's `pushfq` / `popfq`.
    match mnemonic.as_str() {
        "movabs" => mnemonic = "mov".into(),
        "pushfq" => mnemonic = "pushf".into(),
        "popfq" | "popfd" => mnemonic = "popf".into(),
        "pushfd" => mnemonic = "pushf".into(),
        "pushad" => mnemonic = "pusha".into(),
        "popad" => mnemonic = "popa".into(),
        _ => {}
    }
    // String instructions with explicit operands: objdump writes `movs`, iced
    // `movsd`; the operand sizes carry the width in both.
    let string_operand = ["[rdi]", "[rsi]", "[edi]", "[esi]", "[di]", "[si]"]
        .iter()
        .any(|r| ops.contains(r));
    for base in ["movs", "stos", "lods", "scas", "cmps", "ins", "outs"] {
        if string_operand && mnemonic.len() == base.len() + 1 && mnemonic.starts_with(base) {
            mnemonic.truncate(base.len());
        }
    }
    if objdump {
        // Segment registers on absolute operands: objdump `fs:28` / `ds:404028`,
        // iced `fs:[28]` / `[404028]`.
        for seg in ["cs", "ds", "es", "ss", "fs", "gs"] {
            let pat = format!("{seg}:");
            let mut out = String::new();
            let mut rest = ops.as_str();
            while let Some(i) = rest.find(&pat) {
                out.push_str(&rest[..i]);
                let after = &rest[i + pat.len()..];
                let n = after
                    .find(|c: char| !c.is_ascii_hexdigit())
                    .unwrap_or(after.len());
                if n > 0 {
                    if seg != "ds" {
                        out.push_str(&pat);
                    }
                    out.push('[');
                    out.push_str(&after[..n]);
                    out.push(']');
                } else {
                    out.push_str(&pat);
                }
                rest = &after[n..];
            }
            out.push_str(rest);
            ops = out;
        }
        // objdump prints negative RIP displacements as 64-bit two's complement.
        if let Some(i) = ops.find("rip+") {
            let after = &ops[i + 4..];
            let n = after
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(after.len());
            if let Ok(v) = u64::from_str_radix(&after[..n], 16)
                && v > u64::from(u32::MAX)
            {
                let neg = format!("rip-{:x}", v.wrapping_neg());
                ops = format!("{}{neg}{}", &ops[..i], &after[n..]);
            }
        }
    }
    // Segment overrides that have no effect (flat segments), shown on the
    // operand by iced and by objdump in 32-bit code.
    for seg in ["cs:", "ds:", "es:", "ss:"] {
        ops = ops.replace(seg, "");
    }
    // AVX-512 broadcast: iced (and binutils before 2.39) `dword ptr [x]{1to8}`,
    // newer binutils `dword bcst [x]`.
    if let Some(i) = ops.find("{1to") {
        let j = ops[i..].find('}').map_or(ops.len(), |j| i + j + 1);
        ops.replace_range(i..j, "");
        ops = ops.replacen(" ptr [", " bcst [", 1);
    }
    // AVX-512 rounding: iced writes it after the destination (`zmm0{rne-sae}`),
    // objdump after the last operand (`zmm2{rn-sae}`); drop it from both
    // after checking they agree on the mode.
    let rounding = [
        "{rn-sae}",
        "{rne-sae}",
        "{rd-sae}",
        "{rz-sae}",
        "{ru-sae}",
        "{sae}",
    ]
    .iter()
    .find(|r| ops.contains(*r))
    .map(|r| r.replace("rne", "rn"));
    for r in [
        "{rn-sae}",
        "{rne-sae}",
        "{rd-sae}",
        "{rz-sae}",
        "{ru-sae}",
        "{sae}",
    ] {
        ops = ops.replace(r, "");
    }
    if let Some(r) = rounding {
        ops.push_str(&format!(" {r}"));
    }
    let mut list: Vec<String> = if ops.is_empty() {
        Vec::new()
    } else {
        ops.split(',').map(str::to_string).collect()
    };
    match mnemonic.as_str() {
        // stos / lods / scas: objdump also lists the implicit accumulator.
        "stos" | "lods" | "scas" => {
            list.retain(|o| !matches!(o.as_str(), "al" | "ax" | "eax" | "rax"));
        }
        // `imul r, r, imm`: iced writes the two-operand alias when both match.
        "imul" if list.len() == 3 && list[0] == list[1] => {
            list.remove(1);
        }
        // Implicit xmm0 operand of the legacy-SSE blends and SHA-256 rounds.
        "sha256rnds2" | "pblendvb" | "blendvps" | "blendvpd" if list.len() == 3 => {
            if list[2] == "xmm0" {
                list.pop();
            }
        }
        // MOVMSK with REX.W: the result is zero-extended either way; iced names
        // the 32-bit register, objdump the 64-bit one.
        "movmskps" | "movmskpd" | "pmovmskb" if !list.is_empty() => {
            if let Some(r) = list[0].strip_prefix('r') {
                if !r.starts_with(|c: char| c.is_ascii_digit()) {
                    list[0] = format!("e{r}");
                } else if !r.ends_with('d') {
                    list[0] = format!("r{r}d");
                }
            }
        }
        // ARPL takes a 16-bit register; objdump names the 32-bit one.
        "arpl" if objdump && list.len() == 2 && list[1].starts_with('e') => {
            list[1].remove(0);
        }
        // Far pointers: iced `jmp far 10:1000`, objdump `jmp 10:1000`.
        "jmp" | "call" if !objdump && list.len() == 1 => {
            if let Some(p) = list[0].strip_prefix("far ") {
                list[0] = p.to_string();
            }
        }
        // objdump omits the operand size of the descriptor-table instructions.
        "sgdt" | "sidt" | "lgdt" | "lidt" if list.len() == 1 => {
            list[0] = strip_sizes(&list[0].replace("fword ptr ", "").replace("tbyte ptr ", ""));
        }
        // objdump omits the operand size of `lddqu` (always 16 bytes).
        "lddqu" if list.len() == 2 => {
            list[1] = list[1].replace("xmmword ptr ", "");
        }
        // Reserved hint NOPs (`0f 19..1e /r`) carry a register operand that iced
        // shows and objdump drops.
        "nop" if list.len() == 2 && !list[1].contains('[') => {
            list.pop();
        }
        _ => {}
    }
    // x87: iced spells out the implicit `st` operand (`fld st,tbyte ptr [x]`,
    // `fstp st(1),st`) and omits the default `st(1)` (`fxch`), objdump the reverse.
    if mnemonic.starts_with('f') {
        list.retain(|o| o != "st");
        if list.len() == 1 && list[0] == "st(1)" {
            list.clear();
        }
    }
    prefixes.push(mnemonic);
    let head = prefixes.join(" ");
    if list.is_empty() {
        head
    } else {
        format!("{head} {}", list.join(","))
    }
}

/// Whether our normalised text `a` and objdump's `b` say the same for `bytes`.
fn same_text(a: &str, b: &str, bytes: &[u8]) -> bool {
    a == b
        // `d6` raises #UD in 64-bit mode: objdump names it `udb`.
        || (a == "(bad)" && b == "udb")
        // `d6` in 32-bit mode is SALC, undocumented but executed by Intel and
        // AMD CPUs; binutils before 2.43 rejects it.
        || (a == "salc" && b == "(bad)" && bytes == [0xd6])
        // Undocumented x87 aliases (`d9 d8+i` fstp1, `df d0+i` / `df d8+i`
        // fstp8 / fstp9...) that CPUs execute; binutils 2.42 rejects them.
        || (b == "(bad)"
            && a.starts_with('f')
            && bytes.len() == 2
            && (0xd8..=0xdf).contains(&bytes[0])
            && bytes[1] >= 0xc0)
        || (is_moffs(bytes) && strip_sizes(a) == strip_sizes(b))
}

/// Text objdump prints for encodings that raise #UD on the CPU.
fn raises_ud(normalised: &str) -> bool {
    normalised.starts_with("lock ")
        || normalised.contains(" lock ")
        || normalised.contains('?')
        || normalised.starts_with("mov cs,")
}

/// Intel APX encodings (REX2 prefix, extended registers r16-r31), which
/// binutils 2.42+ decodes and iced 1.21 does not.
fn is_apx(text: &str) -> bool {
    text.contains("{rex2")
        || (16..32).any(|n| {
            text.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| {
                w == format!("r{n}")
                    || w == format!("r{n}d")
                    || w == format!("r{n}w")
                    || w == format!("r{n}b")
            })
        })
}

/// `mov` between the accumulator and an absolute address (`a0`..`a3`), whose
/// operand size objdump does not print.
fn is_moffs(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .find(|&&b| {
            !matches!(
                b,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                    ..=0x4f
            )
        })
        .is_some_and(|&b| (0xa0..=0xa3).contains(&b))
}

fn strip_sizes(s: &str) -> String {
    let mut out = s.to_string();
    for size in ["qword", "dword", "word", "byte"] {
        out = out.replace(&format!("{size} ptr "), "");
    }
    out
}

/// Our listing by (section, address): object-file sections all start at 0.
/// Value: bytes, text, and whether a label starts inside the instruction.
type Ours = BTreeMap<(String, u64), (Vec<u8>, String, bool)>;

/// Our listing, keeping only what lies within the part objdump printed.
fn ours(path: &Path, theirs: &[Theirs]) -> Option<Ours> {
    use std::ops::ControlFlow;
    let session = Session::open(path).ok()?;
    let mut last: HashMap<&str, u64> = HashMap::new();
    for t in theirs {
        let e = last.entry(t.section.as_str()).or_insert(0);
        *e = (*e).max(t.va);
    }
    let final_section = theirs.last().map(|t| t.section.clone());
    let mut m = BTreeMap::new();
    let mut section = String::new();
    session
        .disassemble_each(
            &Target::CodeSections,
            Options::with_syntax(Syntax::Intel),
            &mut |l| {
                let (va, entry) = match l {
                    Line::Region { name, .. } => {
                        section = name;
                        return ControlFlow::Continue(());
                    }
                    Line::Insn(i) => (
                        i.insn.va.0,
                        (
                            i.insn.bytes.as_slice().to_vec(),
                            tokens_text(&i.tokens),
                            i.overlaps_label,
                        ),
                    ),
                    Line::Bad { va, bytes, .. } => (va.0, (bytes, "(bad)".to_string(), false)),
                    _ => return ControlFlow::Continue(()),
                };
                let Some(&max) = last.get(section.as_str()) else {
                    return ControlFlow::Continue(());
                };
                if va > max {
                    // Past what objdump printed; nothing later is needed if this
                    // is the last section it reached.
                    return if final_section.as_deref() == Some(section.as_str()) {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    };
                }
                m.entry((section.clone(), va)).or_insert(entry);
                ControlFlow::Continue(())
            },
        )
        .ok()?;
    Some(m)
}

/// Every instruction family in 64-bit mode, plus byte sequences decoders
/// disagree on: redundant REX prefixes, invalid EVEX, `d6`, ignored prefixes.
const ALL64: &str = r#".intel_syntax noprefix
.text
.globl fg_all
.type fg_all, @function
fg_all:
    endbr64
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    mov rax, qword ptr fs:0x28
    mov qword ptr [rbp-8], rax
    lea rdi, [rip+fg_data]
    lea rsi, [rip-0x40]
    mov eax, dword ptr [rdi+rcx*4+0x10]
    mov r8d, dword ptr [r13+0]
    movabs rax, 0x1122334455667788
    movabs eax, dword ptr [0x1122334455667788]
    mov eax, dword ptr [0x404028]
    imul rdx, rdx, 0xd0
    imul eax, dword ptr [rbx], 7
    xchg rax, rbx
    lock cmpxchg qword ptr [rdi], rsi
    lock xadd dword ptr [rdi], eax
    xacquire lock add dword ptr [rdi], 1
    rep movsq
    rep stosb
    repne scasb
    repe cmpsb
    lodsb
    rep stosd
    cpuid
    rdtsc
    rdtscp
    pause
    lfence
    mfence
    sfence
    pushfq
    popfq
    bswap rax
    movbe eax, dword ptr [rsi]
    crc32 eax, byte ptr [rsi]
    popcnt rax, rbx
    lzcnt eax, ebx
    tzcnt eax, ebx
    bt eax, 3
    bts dword ptr [rdi], eax
    adcx rax, rbx
    adox rax, rbx
    mulx rax, rbx, rcx
    shlx rax, rbx, rcx
    andn rax, rbx, rcx
    pdep rax, rbx, rcx
    setne al
    cmovg eax, ebx
    cqo
    cdq
    cwde
    movsx rax, byte ptr [rsi]
    movzx eax, word ptr [rsi]
    movsxd rax, dword ptr [rsi]
    jrcxz 1f
    loop 1f
1:  call 2f
2:  jmp qword ptr [rip+fg_data]
    notrack jmp rax
    .byte 0xf2, 0xff, 0xe0
    call qword ptr [rax+0x18]
    jmp rax
    enter 0x10, 0
    leave
    fld tbyte ptr [rsi]
    fild qword ptr [rsi]
    fadd st, st(2)
    faddp
    fxch st(3)
    fxch
    fstp st(1)
    fistp qword ptr [rsi]
    fstcw word ptr [rsi]
    fnstsw ax
    fcomi st, st(1)
    fucomip st, st(1)
    fdivp st(1), st
    fsqrt
    fsincos
    fldz
    fld1
    movaps xmm0, xmmword ptr [rsi]
    movups xmmword ptr [rdi+rdx*1], xmm1
    addps xmm0, xmm1
    mulsd xmm1, qword ptr [rsi]
    cvtsi2sd xmm0, rax
    cvttsd2si eax, xmm1
    pshufd xmm0, xmm1, 0x1b
    pxor xmm0, xmm0
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    movmskps eax, xmm1
    ptest xmm0, xmm1
    pblendvb xmm1, xmm2, xmm0
    blendvps xmm1, xmm2, xmm0
    roundsd xmm0, xmm1, 4
    insertps xmm0, xmm1, 0x10
    pinsrq xmm0, rax, 1
    pextrd eax, xmm0, 2
    lddqu xmm4, [rsi]
    movntdq xmmword ptr [rdi], xmm0
    palignr xmm0, xmm1, 3
    pclmulqdq xmm0, xmm1, 0x11
    aesenc xmm0, xmm1
    aesdeclast xmm0, xmm1
    sha256rnds2 xmm1, xmm2, xmm0
    sha1rnds4 xmm1, xmm2, 3
    cmpltps xmm0, xmm1
    vmovdqu ymm0, ymmword ptr [rsi]
    vpaddd ymm0, ymm1, ymm2
    vfmadd231ps ymm0, ymm1, ymm2
    vbroadcastss ymm0, dword ptr [rsi]
    vpermq ymm0, ymm1, 0x4e
    vpgatherdd ymm0, [rdi+ymm1*4], ymm2
    vcmpltps ymm0, ymm1, ymm2
    vpshufb ymm0, ymm1, ymm2
    vinserti128 ymm0, ymm1, xmm2, 1
    vextracti128 xmm0, ymm1, 1
    vpmaskmovd ymm0, ymm1, ymmword ptr [rsi]
    vzeroupper
    {vex} vpdpbusd ymm0, ymm1, ymm2
    vmovdqu64 zmm0, zmmword ptr [rsi]
    vpaddd zmm0{k1}{z}, zmm1, dword bcst [rsi]
    vpaddd zmm30, zmm29, zmmword ptr [rsi+0x1000]
    vpaddd ymm16, ymm18, dword bcst [rax+0x98]
    kmovw k1, eax
    vpternlogd zmm0, zmm1, zmm2, 0x96
    vpcompressd zmmword ptr [rdi]{k1}, zmm0
    vaddps zmm0, zmm1, zmm2, {rn-sae}
    vcvtps2ph ymmword ptr [rdi], zmm0, 4
    xbegin 3f
    xend
    xabort 1
3:  syscall
    int3
    int 0x80
    xgetbv
    rdrand eax
    rdseed rax
    clflush byte ptr [rdi]
    prefetchnta byte ptr [rdi]
    hlt
    nop
    nop dword ptr [rax+rax*1+0]
    .byte 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0
    .byte 0x67, 0xe8, 0, 0, 0, 0
    .byte 0x3e, 0x75, 0x00
    .byte 0x0f, 0x1e, 0xfa
    ret 8
    ud2
    ret
.size fg_all, .-fg_all
.globl fg_junk
fg_junk:
    .byte 0x47, 0x46, 0x28, 0x32
    .byte 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x74, 0x72, 0x61
    .byte 0xd6
    .byte 0x43, 0x61
    .byte 0x4d, 0x75, 0x00
    ret
.data
fg_data: .quad 0
"#;

/// 32-bit mode: the legacy instructions 64-bit mode removed, far pointers,
/// `gs:` TLS, `ds:` absolute addresses.
const ALL32: &str = r#".intel_syntax noprefix
.text
.globl fg_all32
.type fg_all32, @function
fg_all32:
    endbr32
    push ebp
    mov ebp, esp
    sub esp, 0x40
    call 1f
1:  pop ebx
    mov eax, dword ptr gs:0x14
    mov eax, dword ptr [ebx+fg_data32@GOTOFF]
    mov eax, dword ptr ds:0x404028
    mov dword ptr ds:0x404028, eax
    mov eax, dword ptr [ebp-4]
    mov ecx, dword ptr [esi+edi*8+0x100]
    lea eax, [eax+eax*1+0]
    pusha
    popa
    pushfd
    popfd
    daa
    das
    aaa
    aas
    aam
    aad
    into
    bound eax, qword ptr [esi]
    les eax, fword ptr [esi]
    push cs
    pop es
    jecxz 2f
    loop 2f
2:  jmp dword ptr [ebx+0x10]
    call dword ptr [eax+0x18]
    ljmp 0x10:0x1000
    lcall 0x10:0x1000
    rep movsd
    repne scasb
    lock inc dword ptr [eax]
    xlatb
    cmpxchg8b qword ptr [esi]
    fld qword ptr [esi]
    fstp st(1)
    fnstcw word ptr [esi]
    fstsw ax
    movaps xmm0, xmmword ptr [esi]
    cvtsi2sd xmm0, eax
    vpaddd ymm0, ymm1, ymm2
    vpaddd zmm0{k1}, zmm1, dword bcst [esi]
    int 0x80
    sysenter
    arpl word ptr [eax], cx
    .byte 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0
    .byte 0xd6
    ret 4
    ret
.size fg_all32, .-fg_all32
.data
fg_data32: .long 0
"#;

fn run_ok(cmd: &mut Command) -> bool {
    cmd.output().is_ok_and(|o| o.status.success())
}

/// MinGW C compilers for x86-64 and i686 (llvm-mingw or GNU), if installed.
fn mingw() -> Vec<(PathBuf, &'static str)> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/opt/llvm-mingw") {
        dirs.extend(rd.flatten().map(|e| e.path().join("bin")));
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    let mut out = Vec::new();
    for (triple, sym) in [
        ("x86_64-w64-mingw32", "fg_all"),
        ("i686-w64-mingw32", "_fg_all"),
    ] {
        let cc = dirs.iter().find_map(|d| {
            [format!("{triple}-clang"), format!("{triple}-gcc")]
                .into_iter()
                .map(|n| d.join(n))
                .find(|p| p.is_file())
        });
        out.extend(cc.map(|c| (c, sym)));
    }
    out
}

/// Builds the fixtures: each assembly file as an ELF object and a shared
/// library (GNU as), and the same machine code embedded in PE executables.
fn fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("disasm-oracle");
    let _ = std::fs::create_dir_all(&dir);
    let mut out = Vec::new();
    for (name, src, m32) in [("all64", ALL64, false), ("all32", ALL32, true)] {
        let s = dir.join(format!("{name}.s"));
        std::fs::write(&s, src).unwrap();
        let obj = dir.join(format!("{name}.o"));
        let so = dir.join(format!("{name}.so"));
        let flag = if m32 { "-m32" } else { "-m64" };
        if !run_ok(
            Command::new("gcc")
                .arg(flag)
                .arg("-c")
                .arg(&s)
                .arg("-o")
                .arg(&obj),
        ) {
            eprintln!("note: gcc could not assemble {name}.s; skipped");
            continue;
        }
        out.push(obj.clone());
        if run_ok(
            Command::new("gcc")
                .args([flag, "-shared", "-nostdlib"])
                .arg(&s)
                .arg("-o")
                .arg(&so),
        ) {
            out.push(so);
        }
        // The same bytes inside a PE image: other assemblers do not all accept
        // GNU syntax, so the code is embedded with `.incbin`.
        let bin = dir.join(format!("{name}.bin"));
        if !run_ok(
            Command::new("objcopy")
                .args(["-O", "binary", "--only-section=.text"])
                .arg(&obj)
                .arg(&bin),
        ) {
            continue;
        }
        let main_c = dir.join("main.c");
        std::fs::write(&main_c, "int main(void) { return 0; }\n").unwrap();
        for (cc, sym) in mingw() {
            if m32 != cc.to_string_lossy().contains("i686") {
                continue;
            }
            let pe_s = dir.join(format!("{name}-pe.s"));
            std::fs::write(
                &pe_s,
                format!(
                    ".text\n.globl {sym}\n{sym}:\n.incbin \"{}\"\n",
                    bin.display()
                ),
            )
            .unwrap();
            let exe = dir.join(format!("{name}.exe"));
            if run_ok(
                Command::new(&cc)
                    .arg(&main_c)
                    .arg(&pe_s)
                    .arg("-o")
                    .arg(&exe),
            ) {
                out.push(exe);
            } else {
                eprintln!("note: {} could not build {name}.exe", cc.display());
            }
        }
    }
    out
}

/// System files to compare when present (capped by `MAX_LINES_PER_FILE`).
const SYSTEM: &[&str] = &[
    "/usr/bin/ls",
    "/bin/ls",
    "/usr/bin/bash",
    "/usr/lib/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/libm.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
    "/usr/lib/libcrypto.so.3",
    "/lib/x86_64-linux-gnu/libcrypto.so.3",
];

fn corpus() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("FULG_DISASM_CORPUS") {
        return list.split(':').map(PathBuf::from).collect();
    }
    let mut v = fixtures();
    let mut seen = std::collections::HashSet::new();
    for p in SYSTEM {
        let p = PathBuf::from(p);
        if let Ok(real) = std::fs::canonicalize(&p)
            && seen.insert(real)
        {
            v.push(p);
        }
    }
    v
}

#[test]
fn matches_objdump() {
    if Command::new(objdump_command())
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("note: objdump not installed; disassembly oracle skipped");
        return;
    }
    let mut categories: HashMap<String, (usize, Vec<String>)> = HashMap::new();
    let mut total = 0usize;
    let mut bad = 0usize;
    let mut accepted_wait = 0usize;
    let mut accepted_prefix = 0usize;
    let mut accepted_resync = 0usize;
    let mut accepted_cut = 0usize;
    let mut accepted_newer = 0usize;
    let mut accepted_ud = 0usize;
    for path in corpus() {
        let Some(theirs) = objdump(&path) else {
            eprintln!("note: {} skipped (objdump)", path.display());
            continue;
        };
        let Some(ours) = ours(&path, &theirs) else {
            eprintln!("note: {} skipped", path.display());
            continue;
        };
        let mut file_total = 0;
        // End of an instruction of ours that objdump split into several lines.
        let mut inside_until = 0u64;
        let mut resyncing = false;
        // End of an instruction of ours that objdump cut at a label.
        let mut cut_until = 0u64;
        for (idx, t) in theirs.iter().enumerate() {
            file_total += 1;
            let ctx = format!("{} {:#x}", path.display(), t.va);
            if t.va < inside_until {
                continue;
            }
            let key = |va: u64| (t.section.clone(), va);
            let mine = ours.get(&key(t.va));
            // After bytes both reject, the two sweeps restart at different
            // offsets (iced skips one byte, objdump the bytes it examined) and
            // fall back into step a few instructions later.
            if resyncing {
                if mine.is_none() {
                    accepted_resync += 1;
                    continue;
                }
                resyncing = false;
            }
            let problem = match mine {
                // Intel APX (REX2 `d5`, extended GPRs r16-r31) is decoded by
                // newer binutils; iced 1.21 predates it and rejects the bytes.
                _ if is_apx(&t.text) => {
                    accepted_newer += 1;
                    resyncing = true;
                    None
                }
                // The rest of an instruction objdump cut at a label: bytes it
                // prints as `.byte` or as a lone prefix before the label.
                None if t.va < cut_until
                    && (t.text.trim_start().starts_with(".byte")
                        || normalise(&t.text, true).is_empty()) =>
                {
                    None
                }
                None => Some((
                    "missing".to_string(),
                    format!("{ctx}: objdump {:?}", t.text),
                )),
                // objdump joins `wait` (9b) with the x87 instruction after it into
                // the assembler macro (`fstcw` = `wait; fnstcw`). They are two
                // instructions to the CPU, and iced decodes them as such.
                Some((bytes, _, _))
                    if bytes.as_slice() == [0x9b]
                        && t.bytes.first() == Some(&0x9b)
                        && ours.get(&key(t.va + 1)).is_some_and(|(b2, text2, _)| {
                            b2.as_slice() == &t.bytes[1..]
                                && normalise(text2, false)
                                    == normalise(&t.text, true).replacen('f', "fn", 1)
                        }) =>
                {
                    accepted_wait += 1;
                    None
                }
                // A label starts inside the instruction: objdump stops at the
                // label and prints the bytes before it as `.byte`; the listing
                // shows the whole instruction, flags it, and decodes from the
                // label too (where objdump continues as well).
                Some((bytes, _, true))
                    if bytes.len() > t.bytes.len() && bytes.starts_with(&t.bytes) =>
                {
                    accepted_cut += 1;
                    cut_until = t.va + bytes.len() as u64;
                    None
                }
                // objdump prints a redundant prefix (a REX that is not directly
                // before the opcode) as an instruction of its own. The CPU
                // ignores it and decodes one instruction, as iced does: the
                // objdump lines covered must add up to our bytes, and the last
                // one must read like ours.
                Some((bytes, text, _))
                    if bytes.len() > t.bytes.len()
                        && text != "(bad)"
                        && normalise(&t.text, true).is_empty() =>
                {
                    let end = t.va + bytes.len() as u64;
                    let covered: Vec<&Theirs> =
                        theirs[idx..].iter().take_while(|u| u.va < end).collect();
                    let joined: Vec<u8> = covered.iter().flat_map(|u| u.bytes.clone()).collect();
                    let last = covered.last().map_or("", |u| u.text.as_str());
                    if joined == *bytes
                        && same_text(&normalise(text, false), &normalise(last, true), bytes)
                    {
                        inside_until = end;
                        accepted_prefix += 1;
                        None
                    } else {
                        Some((
                            "length".to_string(),
                            format!(
                                "{ctx}: ours {bytes:02x?} {text:?} theirs {:02x?} {:?}",
                                t.bytes, t.text
                            ),
                        ))
                    }
                }
                // Both reject the bytes (objdump: `(bad)`, `.byte` before a
                // label or the section end, or a lone prefix); how many they
                // group as one is a matter of display.
                Some((_, text, _))
                    if text == "(bad)"
                        && (t.text.contains("(bad)")
                            || t.text.trim_start().starts_with(".byte")
                            || normalise(&t.text, true).is_empty()) =>
                {
                    resyncing = true;
                    None
                }
                // Encodings the CPU rejects with #UD that objdump still decodes:
                // LOCK on an instruction that cannot take it, a segment register
                // number that does not exist (objdump prints `?`), `mov cs, x`.
                Some((_, text, _)) if text == "(bad)" && raises_ud(&normalise(&t.text, true)) => {
                    accepted_ud += 1;
                    resyncing = true;
                    None
                }
                Some((bytes, _, _)) if *bytes != t.bytes && t.text.trim() != "(bad)" => Some((
                    "length".to_string(),
                    format!(
                        "{ctx}: ours {bytes:02x?} theirs {:02x?} {:?}",
                        t.bytes, t.text
                    ),
                )),
                Some((_, text, _)) => {
                    let (a, b) = (normalise(text, false), normalise(&t.text, true));
                    let same = same_text(&a, &b, &t.bytes);
                    (!same).then(|| {
                        let key = b.split(' ').next().unwrap_or("").to_string();
                        (
                            format!("text:{key}"),
                            format!("{ctx}: ours {a:?} theirs {b:?} [{:02x?}]", t.bytes),
                        )
                    })
                }
            };
            if let Some((cat, sample)) = problem {
                bad += 1;
                let e = categories.entry(cat).or_default();
                e.0 += 1;
                if e.1.len() < 3 {
                    e.1.push(sample);
                }
            }
        }
        total += file_total;
        eprintln!("{}: {file_total} instructions", path.display());
    }
    let mut cats: Vec<_> = categories.into_iter().collect();
    cats.sort_by_key(|c| std::cmp::Reverse(c.1.0));
    for (cat, (n, samples)) in &cats {
        eprintln!("{n:>8}  {cat}");
        for s in samples {
            eprintln!("            {s}");
        }
    }
    eprintln!(
        "{total} instructions compared, {bad} differ; accepted: {accepted_wait} wait + x87 \
         pairs and {accepted_prefix} redundant-prefix runs decoded as the CPU does, \
         {accepted_cut} instructions objdump cut at a label, {accepted_newer} APX \
         instructions iced does not know yet, {accepted_ud} #UD encodings (misplaced LOCK, \
         bad segment registers) iced rejects like the CPU, {accepted_resync} lines realigning after invalid bytes"
    );
    assert_eq!(bad, 0, "disassembly differs from objdump");
}
