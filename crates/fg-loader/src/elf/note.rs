//! Notes (`PT_NOTE` segments and `SHT_NOTE` sections): build ID, ABI tag, and
//! GNU properties, which record the hardware control-flow protections (x86 CET
//! IBT/SHSTK, AArch64 BTI/PAC) every linked object was compiled for.

use super::consts::*;
use super::phdr::ProgramHeader;
use super::section::SectionHeader;
use fg_core::{Anomaly, Bitness, ByteView, Field, Severity, Span};
use serde::Serialize;

/// Where a note was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum NoteSource {
    /// Inside a `PT_NOTE` program header (index given): what the OS can see.
    Segment(u32),
    /// Inside an `SHT_NOTE` section not covered by any `PT_NOTE` (index given).
    Section(u32),
}

/// What a note says, decoded for the note types Fulgurite knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum NoteContent {
    /// `NT_GNU_BUILD_ID`: the build ID as lowercase hex.
    BuildId(String),
    /// `NT_GNU_ABI_TAG`: the oldest kernel the file supports.
    AbiTag {
        /// Operating system, e.g. `Linux`.
        os: String,
        /// Version, e.g. `3.2.0`.
        version: String,
    },
    /// `NT_GNU_PROPERTY_TYPE_0`: program properties.
    Properties(Vec<GnuProperty>),
    /// `NT_GNU_GOLD_VERSION`: the gold linker's version string.
    GoldVersion(String),
    /// `NT_FDO_PACKAGING_METADATA`: distribution package metadata (JSON).
    Package(String),
    /// Go toolchain build ID.
    GoBuildId(String),
    /// Not decoded.
    Other,
}

/// One GNU property.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct GnuProperty {
    /// Property type (`GNU_PROPERTY_*`).
    pub pr_type: Field<u32>,
    /// The property's data bytes.
    pub data: Span,
    /// The 4-byte bitmask, for bitmask properties with valid data.
    pub bits: Option<Field<u32>>,
    /// Description as `readelf -n` prints it, e.g. `x86 feature: IBT, SHSTK`.
    pub text: String,
}

/// One note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfNote {
    /// Where it was found.
    pub source: NoteSource,
    /// Section header whose bytes contain the note, if any (used for its name).
    pub section: Option<u32>,
    /// The whole note's bytes.
    pub span: Span,
    /// Owner name, e.g. `GNU`.
    pub owner: Field<String>,
    /// Note type, meaningful per owner.
    pub n_type: Field<u32>,
    /// The descriptor (payload) bytes.
    pub desc: Span,
    /// Decoded payload.
    pub content: NoteContent,
}

impl ElfNote {
    /// The GNU properties, if this is a property note.
    pub fn properties(&self) -> &[GnuProperty] {
        match &self.content {
            NoteContent::Properties(p) => p,
            _ => &[],
        }
    }
}

pub(crate) struct Ctx<'a, 'b> {
    pub view: &'b ByteView<'a>,
    pub bitness: Bitness,
    pub machine: u16,
    pub phdrs: &'b [ProgramHeader],
    pub sections: &'b [SectionHeader],
    pub max_notes: u32,
}

/// Reads notes from every `PT_NOTE` segment, then from note sections no segment covers.
pub(crate) fn read_all(ctx: &Ctx<'_, '_>, anomalies: &mut Vec<Anomaly>) -> Vec<ElfNote> {
    let mut out = Vec::new();
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for p in ctx.phdrs.iter().filter(|p| p.p_type.value == PT_NOTE) {
        let range = p.file_range();
        covered.push((range.offset.0, range.offset.0.saturating_add(range.len)));
        let label = format!("PT_NOTE #{}", p.index);
        read_container(
            ctx,
            NoteSource::Segment(p.index),
            &label,
            range,
            p.p_align.value,
            Some(p.p_align.span),
            &mut out,
            anomalies,
        );
    }
    for s in ctx.sections.iter().filter(|s| s.sh_type.value == SHT_NOTE) {
        let range = s.file_range();
        let (a, b) = (range.offset.0, range.offset.0.saturating_add(range.len));
        if range.len == 0 || covered.iter().any(|&(x, y)| x <= a && b <= y) {
            continue;
        }
        let label = format!("section #{} {}", s.index, s.name_str());
        read_container(
            ctx,
            NoteSource::Section(s.index),
            &label,
            range,
            s.sh_addralign.value,
            Some(s.sh_addralign.span),
            &mut out,
            anomalies,
        );
    }
    for n in &mut out {
        let (a, b) = (n.span.offset.0, n.span.offset.0.saturating_add(n.span.len));
        n.section = ctx
            .sections
            .iter()
            .find(|s| {
                let r = s.file_range();
                s.sh_type.value == SHT_NOTE
                    && r.offset.0 <= a
                    && b <= r.offset.0.saturating_add(r.len)
            })
            .map(|s| s.index);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn read_container(
    ctx: &Ctx<'_, '_>,
    source: NoteSource,
    label: &str,
    range: Span,
    align_field: u64,
    align_span: Option<Span>,
    out: &mut Vec<ElfNote>,
    anomalies: &mut Vec<Anomaly>,
) {
    let view = ctx.view;
    // The gABI says 4 for both classes, but 64-bit property notes use 8; 0 and 1 mean 4.
    let align = match align_field {
        0..=4 => 4u64,
        8 => 8,
        other => {
            let mut a = Anomaly::new(
                Severity::Warning,
                "elf.note.align",
                format!("{label}: alignment {other} is neither 4 nor 8; reading with 4"),
            );
            if let Some(s) = align_span {
                a = a.at(s);
            }
            anomalies.push(a);
            4
        }
    };
    let up = |n: u64| n.checked_add(align - 1).map(|v| v & !(align - 1));
    let start = range.offset.0;
    let Some(end) = start.checked_add(range.len) else {
        return;
    };
    let end = end.min(view.len());
    let mut at = start;
    let mut count = 0u32;
    while at < end {
        if end - at < 12 {
            truncated(anomalies, label, Span::new(at, end - at));
            return;
        }
        if count >= ctx.max_notes {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.note.limit",
                    format!(
                        "{label}: more than {} notes; stopped reading",
                        ctx.max_notes
                    ),
                )
                .at(range),
            );
            return;
        }
        let (Ok(namesz), Ok(descsz), Ok(n_type)) =
            (view.u32(at), view.u32(at + 4), view.field_u32(at + 8))
        else {
            return;
        };
        let name_at = at + 12;
        let desc_at = up(name_at + u64::from(namesz));
        let next = desc_at.and_then(|d| d.checked_add(u64::from(descsz)).and_then(up));
        let (Some(desc_at), Some(next)) = (desc_at, next) else {
            truncated(anomalies, label, Span::new(at, end - at));
            return;
        };
        // The last note's padding may be cut off; its data may not.
        if desc_at + u64::from(descsz) > end {
            truncated(anomalies, label, Span::new(at, end - at));
            return;
        }
        let owner = view
            .bytes(name_at, u64::from(namesz))
            .map(|b| {
                let b = b.strip_suffix(&[0]).unwrap_or(b);
                String::from_utf8_lossy(b).into_owned()
            })
            .unwrap_or_default();
        let owner = Field::new(owner, Span::new(name_at, u64::from(namesz)));
        let desc = Span::new(desc_at, u64::from(descsz));
        let content = decode(ctx, &owner.value, n_type.value, desc, label, anomalies);
        out.push(ElfNote {
            source,
            section: None,
            span: Span::new(at, next.min(end) - at),
            owner,
            n_type,
            desc,
            content,
        });
        count += 1;
        at = next;
    }
}

fn truncated(anomalies: &mut Vec<Anomaly>, label: &str, span: Span) {
    anomalies.push(
        Anomaly::new(
            Severity::Warning,
            "elf.note.truncated",
            format!("{label}: a note runs past the end of its container"),
        )
        .at(span),
    );
}

fn decode(
    ctx: &Ctx<'_, '_>,
    owner: &str,
    n_type: u32,
    desc: Span,
    label: &str,
    anomalies: &mut Vec<Anomaly>,
) -> NoteContent {
    let view = ctx.view;
    let Ok(bytes) = view.bytes(desc.offset.0, desc.len) else {
        return NoteContent::Other;
    };
    let text = |b: &[u8]| {
        let b = b.split(|&c| c == 0).next().unwrap_or(b);
        String::from_utf8_lossy(b).into_owned()
    };
    match (owner, n_type) {
        ("GNU", NT_GNU_BUILD_ID) => NoteContent::BuildId(hex(bytes)),
        ("GNU", NT_GNU_ABI_TAG) if bytes.len() >= 16 => {
            let word = |i: u64| view.u32(desc.offset.0 + 4 * i).unwrap_or(0);
            let os = match word(0) {
                0 => "Linux".to_string(),
                1 => "Hurd".to_string(),
                2 => "Solaris".to_string(),
                3 => "FreeBSD".to_string(),
                4 => "NetBSD".to_string(),
                5 => "Syllable".to_string(),
                6 => "NaCl".to_string(),
                n => format!("Unknown OS {n}"),
            };
            NoteContent::AbiTag {
                os,
                version: format!("{}.{}.{}", word(1), word(2), word(3)),
            }
        }
        ("GNU", NT_GNU_GOLD_VERSION) => NoteContent::GoldVersion(text(bytes)),
        ("GNU", NT_GNU_PROPERTY_TYPE_0) => {
            NoteContent::Properties(properties(ctx, desc, label, anomalies))
        }
        ("FDO", NT_FDO_PACKAGING_METADATA) => NoteContent::Package(text(bytes)),
        ("Go", NT_GO_BUILDID) => NoteContent::GoBuildId(text(bytes)),
        _ => NoteContent::Other,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// C's `%#x`: `0` for zero, `0x..` otherwise.
fn c_hex(v: u64) -> String {
    if v == 0 {
        "0".to_string()
    } else {
        format!("{v:#x}")
    }
}

/// Names of the set bits, in bit order, as readelf joins them. `empty` is what
/// readelf prints for a zero mask (it differs between property types).
fn bit_names(bits: u32, names: &[(u32, &str)], empty: &str) -> String {
    if bits == 0 {
        return empty.to_string();
    }
    let mut parts = Vec::new();
    let mut rest = bits;
    while rest != 0 {
        let bit = rest & rest.wrapping_neg();
        rest &= !bit;
        match names.iter().find(|(b, _)| *b == bit) {
            Some((_, n)) => parts.push((*n).to_string()),
            None => parts.push(format!("<unknown: {bit:x}>")),
        }
    }
    parts.join(", ")
}

/// How readelf describes one property (binutils `print_gnu_property_note`).
fn property_text(
    machine: u16,
    t: u32,
    datasz: u32,
    bits: Option<u32>,
    word: Option<u64>,
    data: &[u8],
) -> String {
    let corrupt = format!("<corrupt length: {}> ", c_hex(u64::from(datasz)));
    let mask = |prefix: &str, names: &[(u32, &str)], empty: &str| match bits {
        Some(b) => format!("{prefix}{}", bit_names(b, names, empty)),
        None => format!("{prefix}{corrupt}"),
    };
    if (GNU_PROPERTY_LOPROC..=GNU_PROPERTY_HIPROC).contains(&t) {
        let known = match machine {
            EM_X86_64 | EM_386 => match t {
                GNU_PROPERTY_X86_ISA_1_USED => Some(mask("x86 ISA used: ", X86_ISA_1_NAMES, "")),
                GNU_PROPERTY_X86_ISA_1_NEEDED => {
                    Some(mask("x86 ISA needed: ", X86_ISA_1_NAMES, ""))
                }
                GNU_PROPERTY_X86_FEATURE_1_AND => {
                    Some(mask("x86 feature: ", X86_FEATURE_1_NAMES, "<None>"))
                }
                GNU_PROPERTY_X86_FEATURE_2_USED => {
                    Some(mask("x86 feature used: ", X86_FEATURE_2_NAMES, "<None>"))
                }
                GNU_PROPERTY_X86_FEATURE_2_NEEDED => {
                    Some(mask("x86 feature needed: ", X86_FEATURE_2_NAMES, "<None>"))
                }
                GNU_PROPERTY_X86_COMPAT_ISA_1_USED => {
                    Some(mask("x86 ISA used: ", X86_COMPAT_ISA_1_NAMES, ""))
                }
                GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED => {
                    Some(mask("x86 ISA needed: ", X86_COMPAT_ISA_1_NAMES, ""))
                }
                GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED => {
                    Some(mask("x86 ISA used: ", X86_COMPAT_2_ISA_1_NAMES, "<None>"))
                }
                GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED => {
                    Some(mask("x86 ISA needed: ", X86_COMPAT_2_ISA_1_NAMES, "<None>"))
                }
                _ => None,
            },
            EM_AARCH64 if t == GNU_PROPERTY_AARCH64_FEATURE_1_AND => {
                Some(mask("AArch64 feature: ", AARCH64_FEATURE_1_NAMES, ""))
            }
            EM_RISCV if t == GNU_PROPERTY_RISCV_FEATURE_1_AND => {
                Some(mask("RISC-V AND feature: ", RISCV_FEATURE_1_NAMES, ""))
            }
            _ => None,
        };
        if let Some(k) = known {
            return k;
        }
    } else {
        match t {
            GNU_PROPERTY_STACK_SIZE => {
                return match word {
                    Some(v) => format!("stack size: {}", c_hex(v)),
                    None => format!("stack size: {corrupt}"),
                };
            }
            GNU_PROPERTY_NO_COPY_ON_PROTECTED | GNU_PROPERTY_MEMORY_SEAL => {
                let name = if t == GNU_PROPERTY_MEMORY_SEAL {
                    "memory seal "
                } else {
                    "no copy on protected "
                };
                return if datasz == 0 {
                    name.to_string()
                } else {
                    format!("{name}{corrupt}")
                };
            }
            GNU_PROPERTY_1_NEEDED => return mask("1_needed: ", GNU_1_NEEDED_NAMES, ""),
            GNU_PROPERTY_UINT32_AND_LO..=GNU_PROPERTY_UINT32_OR_HI => {
                let label = if t <= GNU_PROPERTY_UINT32_AND_HI {
                    "UINT32_AND"
                } else {
                    "UINT32_OR"
                };
                return match bits {
                    Some(b) => format!("{label} ({t:#x}): {}", c_hex(u64::from(b))),
                    None => format!("{label} ({t:#x}): {corrupt}"),
                };
            }
            _ => {}
        }
    }
    let class = if t < GNU_PROPERTY_LOPROC {
        "unknown"
    } else if t < GNU_PROPERTY_LOUSER {
        "processor-specific"
    } else {
        "application-specific"
    };
    let bytes: String = data.iter().map(|x| format!("{x:02x} ")).collect();
    format!("<{class} type {t:#x} data: {bytes}>")
}
fn properties(
    ctx: &Ctx<'_, '_>,
    desc: Span,
    label: &str,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<GnuProperty> {
    let view = ctx.view;
    let align: u64 = match ctx.bitness {
        Bitness::Bits32 => 4,
        Bitness::Bits64 => 8,
    };
    let end = desc.offset.0 + desc.len; // within the file: checked by the caller
    let mut at = desc.offset.0;
    let mut out = Vec::new();
    while end - at >= 8 && out.len() < 1024 {
        let (Ok(pr_type), Ok(datasz)) = (view.field_u32(at), view.u32(at + 4)) else {
            break;
        };
        let data_at = at + 8;
        if u64::from(datasz) > end - data_at {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.property.corrupt",
                    format!(
                        "{label}: property {:#x} claims {datasz} data bytes, past the end of the note",
                        pr_type.value
                    ),
                )
                .at(Span::new(at, end - at)),
            );
            break;
        }
        let data = Span::new(data_at, u64::from(datasz));
        let bits = (datasz == 4)
            .then(|| view.field_u32(data_at).ok())
            .flatten();
        let word = (u64::from(datasz) == align)
            .then(|| view.uint(data_at, ctx.bitness.word_size()).ok())
            .flatten();
        let bytes = view.bytes(data_at, u64::from(datasz)).unwrap_or(&[]);
        let text = property_text(
            ctx.machine,
            pr_type.value,
            datasz,
            bits.as_ref().map(|b| b.value),
            word,
            bytes,
        );
        out.push(GnuProperty {
            pr_type,
            data,
            bits,
            text,
        });
        let Some(next) = (u64::from(datasz) + align - 1)
            .checked_div(align)
            .map(|n| data_at + n * align)
        else {
            break;
        };
        if next <= at {
            break;
        }
        at = next.min(end);
    }
    out
}
