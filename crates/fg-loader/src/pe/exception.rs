// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Exception directory (`.pdata`): one `RUNTIME_FUNCTION` per function that
//! needs unwinding, with the unwind data that describes its prologue.

use super::consts::*;
use super::section::Image;
use fg_core::{Anomaly, Field, Severity, Span};
use serde::Serialize;

/// One exception-table entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuntimeFunction {
    /// RVA of the first instruction.
    pub begin: Field<u32>,
    /// RVA just past the last instruction, when known (x64 stores it; ARM
    /// derives it from the unwind data's function length).
    pub end: Option<u32>,
    /// The unwind field as stored: an RVA of unwind data, or packed unwind data
    /// (ARM, low two bits non-zero).
    pub unwind: Field<u32>,
    /// Decoded unwind data.
    pub info: Option<UnwindInfo>,
    /// The entry's bytes.
    pub span: Span,
}

impl RuntimeFunction {
    /// True if this entry describes a fragment of another function (x64 chained
    /// unwind info) rather than a function start.
    pub fn is_fragment(&self) -> bool {
        match &self.info {
            Some(UnwindInfo::X64(u)) => u.flags.value & UNW_FLAG_CHAININFO != 0,
            Some(UnwindInfo::Arm64Packed(p)) => p.flag == 2,
            _ => false,
        }
    }
}

/// Unwind data, per architecture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum UnwindInfo {
    /// x64 `UNWIND_INFO`.
    X64(X64Unwind),
    /// ARM64 packed unwind data (stored in the entry itself).
    Arm64Packed(Arm64Packed),
    /// ARM64 `.xdata` record header.
    Arm64Xdata(Arm64Xdata),
}

/// x64 `UNWIND_INFO`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct X64Unwind {
    /// Format version (1, or 2 with epilogue codes).
    pub version: u8,
    /// `UNW_FLAG_*`: exception handler, termination handler, chained.
    pub flags: Field<u8>,
    /// Length of the prologue in bytes.
    pub prolog_size: Field<u8>,
    /// Number of 2-byte unwind-code slots.
    pub code_count: Field<u8>,
    /// Frame pointer register number (0 = none).
    pub frame_register: u8,
    /// Frame pointer offset from RSP, in 16-byte units.
    pub frame_offset: u8,
    /// Decoded unwind codes, in stored order (reverse prologue order).
    pub codes: Vec<UnwindCode>,
    /// Exception or termination handler RVA.
    pub handler: Option<Field<u32>>,
    /// Chained parent entry (begin, end, unwind) for fragments.
    pub chained: Option<(u32, u32, u32)>,
    /// The record's bytes.
    pub span: Span,
}

/// One decoded x64 unwind operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct UnwindCode {
    /// Prologue offset just after the instruction this code describes.
    pub offset: u8,
    /// Operation, e.g. `PUSH_NONVOL`.
    pub op: &'static str,
    /// Register, when the operation involves one (x64 numbering).
    pub register: Option<u8>,
    /// Size or offset operand in bytes, when the operation has one.
    pub value: Option<u32>,
    /// The code's bytes (2, 4 or 6).
    pub span: Span,
}

/// ARM64 packed unwind data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Arm64Packed {
    /// 1 = packed function, 2 = packed fragment without prologue.
    pub flag: u8,
    /// Function length in bytes.
    pub function_length: u32,
    /// Saved floating-point register count field.
    pub reg_f: u8,
    /// Saved integer register count field.
    pub reg_i: u8,
    /// Homes parameter registers.
    pub h: bool,
    /// Chained-return field (CR).
    pub cr: u8,
    /// Frame size in bytes.
    pub frame_size: u32,
}

/// ARM64 `.xdata` record header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Arm64Xdata {
    /// Function length in bytes.
    pub function_length: u32,
    /// Format version.
    pub version: u8,
    /// Has exception data (a handler).
    pub exception_data: bool,
    /// Single packed epilogue.
    pub epilogue_packed: bool,
    /// Epilogue count (or, if packed, the epilogue's start index).
    pub epilogue_count: u32,
    /// Unwind code words.
    pub code_words: u32,
    /// The header word(s).
    pub span: Span,
}

pub(crate) fn read(
    image: &Image<'_>,
    machine: u16,
    rva: u64,
    size: u64,
    max: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<RuntimeFunction> {
    let entry_size: u64 = match machine {
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64EC => 12,
        IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_ARM64X => 8,
        _ => {
            anomalies.push(Anomaly::new(
                Severity::Info,
                "pe.pdata.unsupported",
                "exception table format of this machine is not decoded",
            ));
            return Vec::new();
        }
    };
    if !size.is_multiple_of(entry_size) {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.pdata.size",
            format!("exception directory size {size:#x} is not a multiple of the {entry_size}-byte entry"),
        ));
    }
    let count = size / entry_size;
    if count > u64::from(max) {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.pdata.limit",
            format!("exception table has {count} entries; only {max} are read"),
        ));
    }
    let mut out: Vec<RuntimeFunction> = Vec::new();
    let mut bad_unwind = 0u32;
    for i in 0..count.min(u64::from(max)) {
        let at = rva + i * entry_size;
        let third = (entry_size == 12).then(|| image.u32(at + 8));
        let (Ok(begin), Ok(second), None | Some(Ok(_))) =
            (image.u32(at), image.u32(at + 4), &third)
        else {
            anomalies.push(Anomaly::new(
                Severity::Error,
                "pe.pdata.truncated",
                format!("exception table entry {i} at RVA {at:#x} cannot be read"),
            ));
            break;
        };
        let span = Span::new(begin.span.offset.0, entry_size);
        let rf = if let Some(Ok(unwind)) = third {
            let info = x64_unwind(image, u64::from(unwind.value));
            if info.is_none() {
                bad_unwind += 1;
            }
            RuntimeFunction {
                end: Some(second.value),
                begin,
                unwind,
                info: info.map(UnwindInfo::X64),
                span,
            }
        } else if machine == IMAGE_FILE_MACHINE_ARMNT {
            let flag = second.value & 3;
            // Packed ARM: function length in 2-byte units, bits 2..12.
            let end = (flag != 0)
                .then(|| (begin.value & !1).wrapping_add(((second.value >> 2) & 0x7ff) * 2));
            RuntimeFunction {
                end,
                begin,
                unwind: second,
                info: None,
                span,
            }
        } else {
            let info = arm64_unwind(image, second.value);
            if info.is_none() {
                bad_unwind += 1;
            }
            let len = match &info {
                Some(UnwindInfo::Arm64Packed(p)) => Some(p.function_length),
                Some(UnwindInfo::Arm64Xdata(x)) => Some(x.function_length),
                _ => None,
            };
            RuntimeFunction {
                end: len.map(|l| begin.value.wrapping_add(l)),
                begin,
                unwind: second,
                info,
                span,
            }
        };
        if let Some(e) = rf.end
            && e < rf.begin.value
        {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.pdata.range",
                    format!(
                        "exception entry {i} ends ({e:#x}) before it begins ({:#x})",
                        rf.begin.value
                    ),
                )
                .at(rf.span),
            );
        }
        out.push(rf);
    }
    if out.windows(2).any(|w| w[0].begin.value > w[1].begin.value) {
        anomalies.push(
            Anomaly::new(Severity::Warning, "pe.pdata.unsorted", "exception table is not sorted by address")
                .os("RtlLookupFunctionEntry binary-searches the table, so exceptions in some functions cannot be unwound"),
        );
    }
    if bad_unwind > 0 {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.pdata.unwind_invalid",
            format!(
                "{bad_unwind} exception entries have unwind data that cannot be read or decoded"
            ),
        ));
    }
    out
}

fn x64_unwind(image: &Image<'_>, rva: u64) -> Option<X64Unwind> {
    let b0 = image.uint(rva, 1).ok()?;
    let version = (b0.value & 7) as u8;
    if !(1..=2).contains(&version) {
        return None;
    }
    let flags = Field::new((b0.value >> 3) as u8, b0.span);
    let prolog_size = image.uint(rva + 1, 1).ok()?.map(|v| v as u8);
    let code_count = image.uint(rva + 2, 1).ok()?.map(|v| v as u8);
    let fr = image.uint(rva + 3, 1).ok()?.value as u8;
    let n = u64::from(code_count.value);
    let mut codes = Vec::new();
    let mut i = 0u64;
    while i < n {
        let at = rva + 4 + i * 2;
        let off = image.uint(at, 1).ok()?.value as u8;
        let b = image.uint(at + 1, 1).ok()?.value as u8;
        let (op_code, info) = (b & 0xf, b >> 4);
        let slot = |k: u64| image.u16(at + k * 2).ok().map(|f| u32::from(f.value));
        let (op, register, value, slots) = match op_code {
            0 => ("PUSH_NONVOL", Some(info), None, 1),
            1 if info == 0 => ("ALLOC_LARGE", None, Some(slot(1)? * 8), 2),
            1 => ("ALLOC_LARGE", None, Some(slot(1)? | (slot(2)? << 16)), 3),
            2 => ("ALLOC_SMALL", None, Some(u32::from(info) * 8 + 8), 1),
            // Establishes the frame register at RSP + FrameOffset * 16 (from the header).
            3 => (
                "SET_FPREG",
                Some(fr & 0xf),
                Some(u32::from(fr >> 4) * 16),
                1,
            ),
            4 => ("SAVE_NONVOL", Some(info), Some(slot(1)? * 8), 2),
            5 => (
                "SAVE_NONVOL_FAR",
                Some(info),
                Some(slot(1)? | (slot(2)? << 16)),
                3,
            ),
            // Version 2: one slot per epilogue. The first gives the epilogue's
            // length; the others its distance from the function end (12 bits).
            6 if version == 2 && codes.iter().any(|c: &UnwindCode| c.op == "EPILOG") => (
                "EPILOG",
                None,
                Some(u32::from(off) | (u32::from(info) << 8)),
                1,
            ),
            6 if version == 2 => ("EPILOG", None, Some(u32::from(off)), 1),
            6 => ("SAVE_XMM", Some(info), Some(slot(1)? * 8), 2),
            7 => (
                "SAVE_XMM_FAR",
                Some(info),
                Some(slot(1)? | (slot(2)? << 16)),
                3,
            ),
            8 => ("SAVE_XMM128", Some(info), Some(slot(1)? * 16), 2),
            9 => (
                "SAVE_XMM128_FAR",
                Some(info),
                Some(slot(1)? | (slot(2)? << 16)),
                3,
            ),
            10 => ("PUSH_MACHFRAME", None, Some(u32::from(info)), 1),
            _ => return None,
        };
        codes.push(UnwindCode {
            offset: off,
            op,
            register,
            value,
            span: Span::new(image.offset(at, 2).ok()?, slots * 2),
        });
        i += slots;
    }
    // Codes occupy an even number of slots.
    let tail = rva + 4 + n.div_ceil(2) * 4;
    let mut handler = None;
    let mut chained = None;
    let mut len = tail - rva;
    if flags.value & UNW_FLAG_CHAININFO != 0 {
        let b = image.u32(tail).ok()?.value;
        let e = image.u32(tail + 4).ok()?.value;
        let u = image.u32(tail + 8).ok()?.value;
        chained = Some((b, e, u));
        len += 12;
    } else if flags.value & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        handler = image.u32(tail).ok();
        len += 4;
    }
    Some(X64Unwind {
        version,
        flags,
        prolog_size,
        code_count,
        frame_register: fr & 0xf,
        frame_offset: fr >> 4,
        codes,
        handler,
        chained,
        span: Span::new(b0.span.offset.0, len),
    })
}

fn arm64_unwind(image: &Image<'_>, word: u32) -> Option<UnwindInfo> {
    let flag = (word & 3) as u8;
    if flag == 3 {
        return None; // reserved
    }
    if flag != 0 {
        return Some(UnwindInfo::Arm64Packed(Arm64Packed {
            flag,
            function_length: ((word >> 2) & 0x7ff) * 4,
            reg_f: ((word >> 13) & 7) as u8,
            reg_i: ((word >> 16) & 0xf) as u8,
            h: (word >> 20) & 1 != 0,
            cr: ((word >> 21) & 3) as u8,
            frame_size: ((word >> 23) & 0x1ff) * 16,
        }));
    }
    let h = image.u32(u64::from(word)).ok()?;
    let v = h.value;
    let mut epilogue_count = (v >> 22) & 0x1f;
    let mut code_words = (v >> 27) & 0x1f;
    let mut len = 4;
    // Both counts zero: an extension word holds larger counts.
    if epilogue_count == 0 && code_words == 0 {
        let x = image.u32(u64::from(word) + 4).ok()?.value;
        epilogue_count = x & 0xffff;
        code_words = (x >> 16) & 0xff;
        len = 8;
    }
    Some(UnwindInfo::Arm64Xdata(Arm64Xdata {
        function_length: (v & 0x3_ffff) * 4,
        version: ((v >> 18) & 3) as u8,
        exception_data: (v >> 20) & 1 != 0,
        epilogue_packed: (v >> 21) & 1 != 0,
        epilogue_count,
        code_words,
        span: Span::new(h.span.offset.0, len),
    }))
}
