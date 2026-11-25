// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! `.eh_frame` and `.eh_frame_hdr`: the unwind tables every C++ exception and
//! every stack trace depends on (Linux Standard Base, "Exception Frames";
//! DWARF 4 §6.4.1 for the record layout). Each FDE names the code range it
//! describes, so on a stripped binary they are the best declared source of
//! function starts and ends.
//!
//! Only what locates code is read: CIE augmentations (for the FDE pointer
//! encoding), each FDE's `pc_begin` and `pc_range`, and whether its call-frame
//! instructions change the unwind state at `pc_begin` (a range that starts
//! mid-frame is part of a function, not a function). The rest of the
//! call-frame program is left for the stack analysis.

use super::ElfInfo;
use super::consts::PT_GNU_EH_FRAME;
use crate::model::{Seed, SeedKind, Segment};
use fg_core::{Anomaly, ByteView, Severity, Span, Va};
use std::collections::{BTreeMap, HashMap};

/// Most records read from one `.eh_frame` (a hostile file cannot make the walk
/// unbounded; the largest system libraries have about 10^5).
const MAX_RECORDS: usize = 1 << 22;

const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_DATAREL: u8 = 0x30;
const DW_EH_PE_INDIRECT: u8 = 0x80;

/// Where `.eh_frame` was found and what it declares.
pub(crate) struct EhFrame {
    /// One seed per FDE whose range lies in executable memory.
    pub seeds: Vec<Seed>,
}

/// Counts problems per code, so a damaged table gives one anomaly per kind of
/// damage (with the first location and the count), not one per record.
#[derive(Default)]
struct Report {
    seen: BTreeMap<&'static str, (Severity, String, Option<Span>, u64)>,
}

impl Report {
    fn add(&mut self, sev: Severity, code: &'static str, msg: String, at: Option<Span>) {
        self.seen.entry(code).or_insert((sev, msg, at, 0)).3 += 1;
    }

    fn finish(self, out: &mut Vec<Anomaly>) {
        for (code, (sev, msg, at, n)) in self.seen {
            let msg = if n > 1 {
                format!("{msg} (and {} more like it)", n - 1)
            } else {
                msg
            };
            let a = Anomaly::new(sev, code, msg);
            out.push(match at {
                Some(s) => a.at(s),
                None => a,
            });
        }
    }
}

/// Reads the unwind table of a loaded (non-relocatable) file.
pub(crate) fn read(
    view: &ByteView<'_>,
    info: &ElfInfo,
    word: u8,
    segments: &[Segment],
    anomalies: &mut Vec<Anomaly>,
) -> EhFrame {
    let mut rep = Report::default();
    let mask = if word == 8 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let hdr = read_hdr(view, info, word, mask, &mut rep);
    let section = info
        .section_headers
        .iter()
        .find(|s| s.name_str() == ".eh_frame" && s.is_alloc() && !s.is_nobits());

    // The run time follows `.eh_frame_hdr`; the section header is the fallback.
    let located = match (&hdr, section) {
        (Some(h), sec) => {
            if let Some(s) = sec.filter(|s| s.sh_addr.value != h.eh_frame) {
                rep.add(
                    Severity::Warning,
                    "elf.eh_frame_hdr.mismatch",
                    format!(
                        ".eh_frame_hdr points at {:#x} but the .eh_frame section is at {:#x}; \
                         the run time uses the header's address",
                        h.eh_frame, s.sh_addr.value
                    ),
                    Some(s.sh_addr.span),
                );
            }
            let sec = sec.filter(|s| s.sh_addr.value == h.eh_frame);
            locate(view, segments, h.eh_frame, sec.map(|s| s.sh_size.value))
        }
        (None, Some(s)) => locate(view, segments, s.sh_addr.value, Some(s.sh_size.value)),
        (None, None) => None,
    };
    let Some((base_va, base_off, data)) = located else {
        if hdr.is_some() || section.is_some() {
            rep.add(
                Severity::Warning,
                "elf.eh_frame.unmapped",
                "the .eh_frame address is not backed by file bytes of any LOAD segment".into(),
                None,
            );
        }
        rep.finish(anomalies);
        return EhFrame { seeds: Vec::new() };
    };

    let fdes = walk(data, base_va, base_off, word, mask, view.endian(), &mut rep);

    if let Some(h) = &hdr {
        cross_check(h, &fdes, base_va, &mut rep);
    }

    let mut seeds = Vec::new();
    for f in &fdes {
        if f.range == 0 {
            continue;
        }
        let end = f.begin.checked_add(f.range);
        let Some(end) = end.filter(|&e| mask == u64::MAX || e <= mask + 1) else {
            rep.add(
                Severity::Warning,
                "elf.eh_frame.range_overflow",
                format!(
                    "FDE range {:#x} + {:#x} overflows the address space",
                    f.begin, f.range
                ),
                Some(f.span),
            );
            continue;
        };
        let in_code = segments.iter().any(|s| {
            s.perms.execute
                && f.begin >= s.va.0
                && s.va.0.checked_add(s.mem_size).is_some_and(|e| end <= e)
        });
        if !in_code {
            rep.add(
                Severity::Info,
                "elf.eh_frame.outside_code",
                format!(
                    "FDE for {:#x}..{:#x} does not lie inside one executable segment",
                    f.begin, end
                ),
                Some(f.span),
            );
            continue;
        }
        seeds.push(Seed::new(
            Va(f.begin),
            Some(Va(end)),
            if f.signal {
                SeedKind::UnwindSignal
            } else if f.mid_frame {
                SeedKind::UnwindFragment
            } else {
                SeedKind::UnwindTable
            },
            f.span,
        ));
    }
    rep.finish(anomalies);
    EhFrame { seeds }
}

struct Hdr {
    /// Address of `.eh_frame`.
    eh_frame: u64,
    /// Lookup table: (initial location, FDE address), with the entry's bytes.
    table: Vec<(u64, u64, Span)>,
    /// The table's declared length could not be read in full.
    table_cut: bool,
}

/// One FDE: the code range and the record's bytes.
struct Fde {
    /// Address of the FDE record (its length field).
    at: u64,
    begin: u64,
    range: u64,
    span: Span,
    /// The unwind state at `begin` is not the CIE's (a function's entry state):
    /// the range starts in the middle of a frame, as a compiler-split `.cold`
    /// part does.
    mid_frame: bool,
    /// The CIE marks a signal-handler trampoline (`S`).
    signal: bool,
}

fn read_hdr(
    view: &ByteView<'_>,
    info: &ElfInfo,
    word: u8,
    mask: u64,
    rep: &mut Report,
) -> Option<Hdr> {
    let ph = info.headers_of(PT_GNU_EH_FRAME).next()?;
    let off = ph.p_offset.value;
    let va = ph.p_vaddr.value;
    let Ok(data) = view.bytes(off, ph.p_filesz.value) else {
        rep.add(
            Severity::Warning,
            "elf.eh_frame_hdr.bad",
            "PT_GNU_EH_FRAME extends past the end of the file".into(),
            Some(ph.span),
        );
        return None;
    };
    let bad = |rep: &mut Report, why: String| {
        rep.add(
            Severity::Warning,
            "elf.eh_frame_hdr.bad",
            why,
            Some(Span::new(off, data.len() as u64)),
        );
    };
    let mut c = Cursor::new(data, va, view.endian());
    let (Some(version), Some(ptr_enc), Some(count_enc), Some(table_enc)) =
        (c.u8(), c.u8(), c.u8(), c.u8())
    else {
        bad(
            rep,
            ".eh_frame_hdr is shorter than its 4-byte header".into(),
        );
        return None;
    };
    if version != 1 {
        bad(
            rep,
            format!(".eh_frame_hdr version {version}; only version 1 is defined"),
        );
        return None;
    }
    let eh_frame = match c.encoded(ptr_enc, word, mask, Some(va)) {
        Ok(Some(v)) => v,
        Ok(None) => {
            bad(rep, ".eh_frame_hdr omits the .eh_frame pointer".into());
            return None;
        }
        Err(why) => {
            bad(rep, format!(".eh_frame_hdr's .eh_frame pointer: {why}"));
            return None;
        }
    };
    let mut hdr = Hdr {
        eh_frame,
        table: Vec::new(),
        table_cut: false,
    };
    if count_enc == DW_EH_PE_OMIT || table_enc == DW_EH_PE_OMIT {
        return Some(hdr);
    }
    let count = match c.encoded(count_enc, word, u64::MAX, Some(va)) {
        Ok(Some(n)) => n,
        Ok(None) => return Some(hdr),
        Err(why) => {
            bad(rep, format!(".eh_frame_hdr's FDE count: {why}"));
            return Some(hdr);
        }
    };
    for _ in 0..count.min(MAX_RECORDS as u64) {
        let start = c.pos;
        let loc = c.encoded(table_enc, word, mask, Some(va));
        let fde = c.encoded(table_enc, word, mask, Some(va));
        match (loc, fde) {
            (Ok(Some(l)), Ok(Some(f))) => {
                hdr.table
                    .push((l, f, Span::new(off + start as u64, (c.pos - start) as u64)));
            }
            (Err(why), _) | (_, Err(why)) => {
                bad(rep, format!(".eh_frame_hdr table entry: {why}"));
                hdr.table_cut = true;
                return Some(hdr);
            }
            _ => {
                bad(
                    rep,
                    ".eh_frame_hdr table entry with an omitted value".into(),
                );
                hdr.table_cut = true;
                return Some(hdr);
            }
        }
    }
    if count > MAX_RECORDS as u64 {
        hdr.table_cut = true;
    }
    Some(hdr)
}

/// File bytes of `.eh_frame` at `va`: the section's size when known, else the
/// rest of the LOAD segment (the walk stops at the zero terminator).
fn locate<'a>(
    view: &ByteView<'a>,
    segments: &[Segment],
    va: u64,
    size: Option<u64>,
) -> Option<(u64, u64, &'a [u8])> {
    let seg = segments
        .iter()
        .find(|s| va.checked_sub(s.va.0).is_some_and(|d| d < s.file_size))?;
    let delta = va - seg.va.0;
    let off = seg.file_offset.0.checked_add(delta)?;
    let avail = seg.file_size - delta;
    let len = size.map_or(avail, |s| s.min(avail));
    Some((va, off, view.bytes(off, len).ok()?))
}

struct Cie {
    fde_enc: u8,
    /// FDEs carry an augmentation-data length (`z`).
    has_z: bool,
    /// Signal-handler trampolines (`S`): their unwind state at the start is the
    /// interrupted code's, by design, yet they are functions.
    signal: bool,
}

#[allow(clippy::too_many_arguments)]
fn walk(
    data: &[u8],
    base_va: u64,
    base_off: u64,
    word: u8,
    mask: u64,
    endian: fg_core::Endian,
    rep: &mut Report,
) -> Vec<Fde> {
    let mut cies: HashMap<u64, Result<Cie, String>> = HashMap::new();
    let mut fdes = Vec::new();
    let mut pos: u64 = 0;
    let len = data.len() as u64;
    let span = |a: u64, b: u64| Span::new(base_off + a, b - a);
    for _ in 0..MAX_RECORDS {
        if pos >= len {
            break;
        }
        let mut c = Cursor::new(data, base_va, endian);
        c.pos = pos as usize;
        let Some(l32) = c.u32() else {
            rep.add(
                Severity::Warning,
                "elf.eh_frame.truncated",
                "record length cut off by the end of .eh_frame".into(),
                Some(span(pos, len)),
            );
            break;
        };
        if l32 == 0 {
            break; // terminator
        }
        let length = if l32 == u32::MAX {
            match c.u64() {
                Some(l) => l,
                None => {
                    rep.add(
                        Severity::Warning,
                        "elf.eh_frame.truncated",
                        "64-bit record length cut off".into(),
                        Some(span(pos, len)),
                    );
                    break;
                }
            }
        } else {
            u64::from(l32)
        };
        let body = c.pos as u64;
        let Some(end) = body.checked_add(length).filter(|e| *e <= len) else {
            rep.add(
                Severity::Warning,
                "elf.eh_frame.truncated",
                format!(
                    "record at {:#x} claims {length} bytes, past the end of .eh_frame",
                    base_va + pos
                ),
                Some(span(pos, len)),
            );
            break;
        };
        let rec = span(pos, end);
        let mut r = Cursor::new(&data[..end as usize], base_va, endian);
        r.pos = body as usize;
        let Some(id) = r.u32() else {
            rep.add(
                Severity::Warning,
                "elf.eh_frame.truncated",
                "record too short for its CIE id".into(),
                Some(rec),
            );
            pos = end;
            continue;
        };
        if id == 0 {
            cies.insert(pos, parse_cie(&mut r, word));
        } else {
            let cie_at = body.checked_sub(u64::from(id));
            let cie = cie_at.and_then(|a| {
                if let std::collections::hash_map::Entry::Vacant(v) = cies.entry(a) {
                    v.insert(parse_cie_at(data, a, base_va, endian, word)?);
                }
                cies.get(&a)
            });
            match cie {
                None => rep.add(
                    Severity::Warning,
                    "elf.eh_frame.bad_cie_pointer",
                    format!("FDE at {:#x} does not point at a CIE", base_va + pos),
                    Some(rec),
                ),
                Some(Err(why)) => rep.add(
                    Severity::Warning,
                    "elf.eh_frame.bad_cie",
                    format!(
                        "CIE used by the FDE at {:#x}: {why}; its FDEs are skipped",
                        base_va + pos
                    ),
                    Some(rec),
                ),
                Some(Ok(cie)) => {
                    let begin = r.encoded(cie.fde_enc, word, mask, None);
                    // pc_range uses the value format only, never an application.
                    let range = r.encoded(cie.fde_enc & 0x0f, word, mask, None);
                    let aug_ok = !cie.has_z
                        || r.uleb()
                            .and_then(|n| usize::try_from(n).ok())
                            .is_some_and(|n| r.take(n).is_some());
                    match (begin, range) {
                        (Ok(Some(b)), Ok(Some(n))) if aug_ok => fdes.push(Fde {
                            at: base_va.wrapping_add(pos) & mask,
                            begin: b,
                            range: n,
                            span: rec,
                            mid_frame: !cie.signal && changes_state_at_start(&r.data[r.pos..]),
                            signal: cie.signal,
                        }),
                        (Err(why), _) | (_, Err(why)) => rep.add(
                            Severity::Warning,
                            "elf.eh_frame.bad_pointer",
                            format!("FDE at {:#x}: {why}", base_va + pos),
                            Some(rec),
                        ),
                        _ => rep.add(
                            Severity::Warning,
                            "elf.eh_frame.truncated",
                            format!(
                                "FDE at {:#x} is too short for its code range",
                                base_va + pos
                            ),
                            Some(rec),
                        ),
                    }
                }
            }
        }
        pos = end;
    }
    fdes
}

/// Whether call-frame instructions change the unwind state before the first
/// `DW_CFA_advance_loc*`, i.e. at the FDE's first address (DWARF 5 §6.4.2).
fn changes_state_at_start(insns: &[u8]) -> bool {
    for &op in insns {
        match op {
            0x00 => continue,                  // DW_CFA_nop
            0x02..=0x04 => return false,       // DW_CFA_advance_loc1/2/4
            _ if op >> 6 == 1 => return false, // DW_CFA_advance_loc
            _ => return true,
        }
    }
    false
}

fn parse_cie_at(
    data: &[u8],
    at: u64,
    base_va: u64,
    endian: fg_core::Endian,
    word: u8,
) -> Option<Result<Cie, String>> {
    let mut c = Cursor::new(data, base_va, endian);
    c.pos = usize::try_from(at).ok()?;
    let l32 = c.u32()?;
    let length = if l32 == u32::MAX {
        c.u64()?
    } else {
        u64::from(l32)
    };
    let end = (c.pos as u64).checked_add(length)?;
    if end > data.len() as u64 || c.u32()? != 0 {
        return None;
    }
    let mut r = Cursor::new(&data[..end as usize], base_va, endian);
    r.pos = c.pos;
    Some(parse_cie(&mut r, word))
}

/// Reads a CIE body after its id, up to the augmentation data.
fn parse_cie(c: &mut Cursor<'_>, word: u8) -> Result<Cie, String> {
    let cut = || "the CIE is cut off".to_string();
    let version = c.u8().ok_or_else(cut)?;
    if !matches!(version, 1 | 3 | 4) {
        return Err(format!("CIE version {version} is not 1, 3 or 4"));
    }
    let aug = c.cstr().ok_or_else(cut)?;
    if version == 4 {
        let addr_size = c.u8().ok_or_else(cut)?;
        let _segment_size = c.u8().ok_or_else(cut)?;
        if addr_size != word {
            return Err(format!(
                "CIE address size {addr_size}, file word size {word}"
            ));
        }
    }
    c.uleb().ok_or_else(cut)?; // code alignment
    c.sleb().ok_or_else(cut)?; // data alignment
    if version == 1 {
        c.u8().ok_or_else(cut)?;
    } else {
        c.uleb().ok_or_else(cut)?;
    } // return address register
    let mut cie = Cie {
        fde_enc: 0,
        has_z: false,
        signal: false,
    };
    let Some(rest) = aug.strip_prefix(b"z") else {
        // Without `z` the FDE layout is only known for no augmentation at all.
        return if aug.is_empty() {
            Ok(cie)
        } else {
            Err(format!(
                "augmentation \"{}\" without 'z' cannot be skipped",
                String::from_utf8_lossy(aug)
            ))
        };
    };
    cie.has_z = true;
    let aug_len = c.uleb().ok_or_else(cut)?;
    let aug_end = (c.pos as u64)
        .checked_add(aug_len)
        .filter(|e| *e <= c.data.len() as u64)
        .ok_or_else(cut)?;
    for &ch in rest {
        match ch {
            b'R' => cie.fde_enc = c.u8().ok_or_else(cut)?,
            b'L' => {
                c.u8().ok_or_else(cut)?;
            }
            b'P' => {
                let enc = c.u8().ok_or_else(cut)?;
                // The personality routine's address is not needed, only its
                // size, which the value format alone gives.
                c.encoded(enc & 0x0f, word, u64::MAX, None)
                    .map_err(|e| format!("personality pointer: {e}"))?;
            }
            b'S' => cie.signal = true,
            // BTI-protected / MTE-tagged frames: no data.
            b'B' | b'G' => {}
            // Unknown letters stop the parse; `z`'s length tells where the
            // data ends, so earlier letters' values are still right.
            _ => break,
        }
    }
    if c.pos as u64 > aug_end {
        return Err("augmentation data longer than its declared length".into());
    }
    Ok(cie)
}

fn cross_check(h: &Hdr, fdes: &[Fde], base_va: u64, rep: &mut Report) {
    if h.eh_frame != base_va {
        return;
    }
    let by_addr: HashMap<u64, &Fde> = fdes.iter().map(|f| (f.at, f)).collect();
    let mut listed = std::collections::HashSet::new();
    for &(loc, fde, span) in &h.table {
        listed.insert(fde);
        match by_addr.get(&fde) {
            Some(f) if f.begin == loc => {}
            Some(f) => rep.add(
                Severity::Warning,
                "elf.eh_frame_hdr.mismatch",
                format!(
                    ".eh_frame_hdr says the FDE at {fde:#x} starts at {loc:#x}; the FDE says {:#x}",
                    f.begin
                ),
                Some(span),
            ),
            None => rep.add(
                Severity::Warning,
                "elf.eh_frame_hdr.mismatch",
                format!(".eh_frame_hdr lists an FDE at {fde:#x} for {loc:#x}; there is none"),
                Some(span),
            ),
        }
    }
    if !h.table_cut && !h.table.is_empty() {
        for f in fdes
            .iter()
            .filter(|f| !listed.contains(&f.at) && f.range != 0)
        {
            rep.add(
                Severity::Info,
                "elf.eh_frame_hdr.unlisted_fde",
                format!(
                    "the FDE for {:#x} is not in .eh_frame_hdr's table, so the run time cannot unwind through it",
                    f.begin
                ),
                Some(f.span),
            );
        }
    }
}

/// A bounds-checked reader over one table, knowing the address of byte 0 (for
/// PC-relative pointers).
struct Cursor<'a> {
    data: &'a [u8],
    va: u64,
    pos: usize,
    endian: fg_core::Endian,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], va: u64, endian: fg_core::Endian) -> Cursor<'a> {
        Cursor {
            data,
            va,
            pos: 0,
            endian,
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    fn uint(&mut self, n: usize) -> Option<u64> {
        let b = self.take(n)?;
        let mut v = 0u64;
        for (i, &x) in b.iter().enumerate() {
            let shift = match self.endian {
                fg_core::Endian::Little => 8 * i,
                fg_core::Endian::Big => 8 * (n - 1 - i),
            };
            v |= u64::from(x) << shift;
        }
        Some(v)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.uint(4).map(|v| v as u32)
    }

    fn u64(&mut self) -> Option<u64> {
        self.uint(8)
    }

    fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        self.pos += n + 1;
        Some(&rest[..n])
    }

    /// LEB128 values longer than 10 bytes, or with bits beyond 64, are refused.
    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let bits = u64::from(b & 0x7f);
            if i == 9 && bits > 1 {
                return None;
            }
            v |= bits << (7 * i);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift == 63 && !matches!(b, 0x00 | 0x7f) {
                return None;
            }
            v |= i64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift > 63 {
                return None;
            }
        }
    }

    /// A `DW_EH_PE_*`-encoded pointer. `Ok(None)` for `DW_EH_PE_omit`.
    /// `datarel` is relative to `data_base` (the start of `.eh_frame_hdr`, the
    /// only table where the run time defines it).
    fn encoded(
        &mut self,
        enc: u8,
        word: u8,
        mask: u64,
        data_base: Option<u64>,
    ) -> Result<Option<u64>, String> {
        if enc == DW_EH_PE_OMIT {
            return Ok(None);
        }
        if enc & DW_EH_PE_INDIRECT != 0 {
            return Err(format!(
                "indirect pointer encoding {enc:#04x} for a code address"
            ));
        }
        let field_va = self.va.wrapping_add(self.pos as u64);
        let cut = || "pointer cut off".to_string();
        let raw = match enc & 0x0f {
            0x00 => self.uint(usize::from(word)).ok_or_else(cut)?,
            0x01 => self.uleb().ok_or_else(cut)?,
            0x02 => self.uint(2).ok_or_else(cut)?,
            0x03 => self.uint(4).ok_or_else(cut)?,
            0x04 => self.uint(8).ok_or_else(cut)?,
            0x09 => self.sleb().ok_or_else(cut)? as u64,
            0x0a => self.uint(2).ok_or_else(cut)? as u16 as i16 as i64 as u64,
            0x0b => self.uint(4).ok_or_else(cut)? as u32 as i32 as i64 as u64,
            0x0c => self.uint(8).ok_or_else(cut)?,
            f => {
                return Err(format!(
                    "unknown pointer format {f:#x} in encoding {enc:#04x}"
                ));
            }
        };
        let v = match enc & 0x70 {
            0x00 => raw,
            DW_EH_PE_PCREL => field_va.wrapping_add(raw),
            DW_EH_PE_DATAREL => match data_base {
                Some(b) => b.wrapping_add(raw),
                None => {
                    return Err(format!(
                        "data-relative encoding {enc:#04x} outside .eh_frame_hdr"
                    ));
                }
            },
            a => {
                return Err(format!(
                    "pointer application {a:#04x} (encoding {enc:#04x}) is not supported for code addresses"
                ));
            }
        };
        Ok(Some(v & mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cur(b: &[u8]) -> Cursor<'_> {
        Cursor::new(b, 0x1000, fg_core::Endian::Little)
    }

    #[test]
    fn leb128() {
        assert_eq!(cur(&[0xe5, 0x8e, 0x26]).uleb(), Some(624_485));
        assert_eq!(cur(&[0xc0, 0xbb, 0x78]).sleb(), Some(-123_456));
        assert_eq!(cur(&[0x7f]).sleb(), Some(-1));
        assert_eq!(cur(&[0x80, 0x7f]).sleb(), Some(-128));
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(cur(&max).uleb(), Some(u64::MAX));
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(cur(&over).uleb(), None);
        assert_eq!(cur(&[0x80; 11]).uleb(), None);
        assert_eq!(cur(&[0x80]).uleb(), None);
        let min = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
        assert_eq!(cur(&min).sleb(), Some(i64::MIN));
        assert_eq!(cur(&[0x80; 11]).sleb(), None);
    }

    #[test]
    fn pointer_encodings() {
        // pcrel sdata4: field at 0x1000, value -0x10.
        let b = (-0x10i32).to_le_bytes();
        assert_eq!(cur(&b).encoded(0x1b, 8, u64::MAX, None), Ok(Some(0xff0)));
        // The same in a 32-bit file wraps at 2^32.
        let b = (-0x2000i32).to_le_bytes();
        assert_eq!(
            cur(&b).encoded(0x1b, 4, 0xffff_ffff, None),
            Ok(Some(0xffff_f000))
        );
        // datarel sdata4 needs a base.
        let b = 8i32.to_le_bytes();
        assert_eq!(
            cur(&b).encoded(0x3b, 8, u64::MAX, Some(0x500)),
            Ok(Some(0x508))
        );
        assert!(cur(&b).encoded(0x3b, 8, u64::MAX, None).is_err());
        // absptr is the word size; udata2; omit; indirect and textrel refused.
        let b = 0x1122_3344_5566_7788u64.to_le_bytes();
        assert_eq!(
            cur(&b).encoded(0x00, 8, u64::MAX, None),
            Ok(Some(0x1122_3344_5566_7788))
        );
        assert_eq!(
            cur(&b).encoded(0x00, 4, 0xffff_ffff, None),
            Ok(Some(0x5566_7788))
        );
        assert_eq!(cur(&b).encoded(0x02, 8, u64::MAX, None), Ok(Some(0x7788)));
        assert_eq!(cur(&b).encoded(0xff, 8, u64::MAX, None), Ok(None));
        assert!(cur(&b).encoded(0x9b, 8, u64::MAX, None).is_err());
        assert!(cur(&b).encoded(0x2b, 8, u64::MAX, None).is_err());
        assert!(cur(&b).encoded(0x07, 8, u64::MAX, None).is_err());
        assert!(cur(&[1, 2]).encoded(0x03, 8, u64::MAX, None).is_err());
    }

    /// A CIE with augmentation `aug` (and its data), then `fdes`, then the terminator.
    fn table(aug: &[u8], aug_data: &[u8], fdes: &[Vec<u8>]) -> Vec<u8> {
        let mut cie = vec![0, 0, 0, 0, 1];
        cie.extend_from_slice(aug);
        cie.extend_from_slice(&[0, 1, 0x78, 16]);
        if aug.first() == Some(&b'z') {
            cie.push(aug_data.len() as u8);
            cie.extend_from_slice(aug_data);
        }
        let mut out = (cie.len() as u32).to_le_bytes().to_vec();
        out.extend(cie);
        for f in fdes {
            out.extend_from_slice(&(f.len() as u32 + 4).to_le_bytes());
            out.extend_from_slice(&(out.len() as u32).to_le_bytes()); // back to offset 0
            out.extend_from_slice(f);
        }
        out.extend_from_slice(&[0; 4]);
        out
    }

    fn run(data: &[u8]) -> (Vec<(u64, u64)>, Vec<&'static str>) {
        let mut rep = Report::default();
        let f = walk(
            data,
            0x2000,
            0,
            8,
            u64::MAX,
            fg_core::Endian::Little,
            &mut rep,
        );
        (
            f.iter().map(|f| (f.begin, f.range)).collect(),
            rep.seen.keys().copied().collect(),
        )
    }

    #[test]
    fn walks_pc_relative_fdes() {
        // FDE fields start 8 bytes into the record; pc_begin is pcrel sdata4.
        let fde = |field_off: u32, target: u64, len: u32| {
            let rel = (target as i64 - (0x2000 + i64::from(field_off))) as i32;
            let mut v = rel.to_le_bytes().to_vec();
            v.extend_from_slice(&len.to_le_bytes());
            v.push(0); // augmentation data length
            v
        };
        // CIE is 4 + 13 bytes; first FDE's pc_begin is at 17 + 8 = 25.
        let fdes = vec![fde(25, 0x1000, 0x40), fde(25 + 17, 0x1100, 0x10)];
        let (got, codes) = run(&table(b"zR", &[0x1b], &fdes));
        assert_eq!(got, vec![(0x1000, 0x40), (0x1100, 0x10)]);
        assert!(codes.is_empty(), "{codes:?}");
    }

    #[test]
    fn damaged_tables_are_reported_not_trusted() {
        let abs = |v: u64| {
            let mut b = v.to_le_bytes().to_vec();
            b.extend_from_slice(&8u64.to_le_bytes());
            b
        };
        // No augmentation: absptr FDEs.
        let (got, _) = run(&table(b"", &[], &[abs(0x1234)]));
        assert_eq!(got, vec![(0x1234, 8)]);
        // An augmentation without 'z' cannot be skipped: the FDE is not trusted.
        let (got, codes) = run(&table(b"eh", &[], &[abs(0x1234)]));
        assert!(got.is_empty());
        assert_eq!(codes, vec!["elf.eh_frame.bad_cie"]);
        // An FDE whose CIE pointer leads outside the table.
        let mut t = table(b"", &[], &[abs(0x1234)]);
        let at = t.len() - 4 - 16 - 4;
        t[at..at + 4].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
        let (got, codes) = run(&t);
        assert!(got.is_empty());
        assert_eq!(codes, vec!["elf.eh_frame.bad_cie_pointer"]);
        // A record longer than the table.
        let mut t = table(b"", &[], &[abs(0x1234)]);
        let at = t.len() - 4 - 16 - 8;
        t[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let (got, codes) = run(&t);
        assert!(got.is_empty());
        assert_eq!(codes, vec!["elf.eh_frame.truncated"]);
        // Text-relative pc_begin is not resolvable without more context.
        let (got, codes) = run(&table(b"zR", &[0x2b], &[vec![0; 9]]));
        assert!(got.is_empty());
        assert_eq!(codes, vec!["elf.eh_frame.bad_pointer"]);
    }
}
