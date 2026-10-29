//! TLS directory and load-configuration directory (security cookie, Control
//! Flow Guard tables, SafeSEH handlers).

use super::consts::*;
use super::section::{Image, RvaError};
use fg_core::{Anomaly, Field, Severity, Span, Va};
use serde::Serialize;

/// The TLS directory: per-thread data template and the callbacks that run
/// before the entry point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TlsDirectory {
    /// Start of the initial data copied for each thread (a VA).
    pub start_address_of_raw_data: Field<u64>,
    /// End of that data (a VA).
    pub end_address_of_raw_data: Field<u64>,
    /// Where the loader stores the TLS slot index (a VA).
    pub address_of_index: Field<u64>,
    /// Zero-terminated array of callback addresses (a VA; 0 = none).
    pub address_of_callbacks: Field<u64>,
    /// Bytes of zeros appended after the template.
    pub size_of_zero_fill: Field<u32>,
    /// Alignment flags.
    pub characteristics: Field<u32>,
    /// The callbacks (VAs), in run order.
    pub callbacks: Vec<Field<Va>>,
    /// The directory's bytes.
    pub span: Span,
}

pub(crate) fn read_tls(
    image: &Image<'_>,
    pe32_plus: bool,
    rva: u64,
    max: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Option<TlsDirectory> {
    let p = if pe32_plus { 8 } else { 4 };
    let ptr = |o: u64| image.uint(rva + o, p);
    let (Ok(start), Ok(end), Ok(index), Ok(cbs)) = (
        ptr(0),
        ptr(u64::from(p)),
        ptr(2 * u64::from(p)),
        ptr(3 * u64::from(p)),
    ) else {
        anomalies.push(Anomaly::new(
            Severity::Error,
            "pe.tls.truncated",
            format!("TLS directory at RVA {rva:#x} cannot be read"),
        ));
        return None;
    };
    let (Ok(zero_fill), Ok(characteristics)) = (
        image.u32(rva + 4 * u64::from(p)),
        image.u32(rva + 4 * u64::from(p) + 4),
    ) else {
        anomalies.push(Anomaly::new(
            Severity::Error,
            "pe.tls.truncated",
            format!("TLS directory at RVA {rva:#x} is cut short"),
        ));
        return None;
    };
    let mut callbacks = Vec::new();
    if cbs.value != 0 {
        match image.rva_of(cbs.value) {
            Some(table) => {
                for i in 0.. {
                    if i >= max {
                        anomalies.push(Anomaly::new(
                            Severity::Warning,
                            "pe.tls.limit",
                            format!("more than {max} TLS callbacks; the rest are ignored"),
                        ));
                        break;
                    }
                    match image.uint(table + u64::from(i) * u64::from(p), p) {
                        Ok(f) if f.value == 0 => break,
                        Ok(f) => {
                            if image.rva_of(f.value).is_none_or(|r| !image.is_mapped(r)) {
                                anomalies.push(
                                    Anomaly::new(
                                        Severity::Warning,
                                        "pe.tls.callback_unmapped",
                                        format!(
                                            "TLS callback {i} at {:#x} is outside the image",
                                            f.value
                                        ),
                                    )
                                    .at(f.span),
                                );
                            }
                            callbacks.push(f.map(Va));
                        }
                        // Zero-filled memory ends the list. The array is often
                        // filled at run time (relocated data), so that is normal.
                        Err(RvaError::ZeroFill) => break,
                        Err(RvaError::Unmapped) => {
                            anomalies.push(
                                Anomaly::new(
                                    Severity::Warning,
                                    "pe.tls.callback_unmapped",
                                    format!(
                                        "TLS callback array at {:#x} is outside the image",
                                        cbs.value
                                    ),
                                )
                                .at(cbs.span),
                            );
                            break;
                        }
                    }
                }
            }
            None => anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.tls.callback_unmapped",
                    format!(
                        "TLS callback array at {:#x} is below the image base",
                        cbs.value
                    ),
                )
                .at(cbs.span),
            ),
        }
    }
    if !callbacks.is_empty() {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.tls.callbacks",
                format!(
                    "{} TLS callback(s) run before the entry point: code there runs before a debugger stops at the entry",
                    callbacks.len()
                ),
            )
            .at(cbs.span),
        );
    }
    let len = 4 * u64::from(p) + 8;
    Some(TlsDirectory {
        span: Span::new(start.span.offset.0, len),
        start_address_of_raw_data: start,
        end_address_of_raw_data: end,
        address_of_index: index,
        address_of_callbacks: cbs,
        size_of_zero_fill: zero_fill,
        characteristics,
        callbacks,
    })
}

/// One field of the load-configuration structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct LoadConfigField {
    /// Field name (as `winnt.h` and `llvm-readobj` spell it).
    pub name: &'static str,
    /// Value (zero-extended).
    pub value: Field<u64>,
}

/// An entry of a guard table (CFG targets, long-jump targets, EH continuations).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct GuardEntry {
    /// RVA of the target.
    pub rva: u32,
    /// Per-entry flag byte, when the table has one.
    pub flags: Option<u8>,
    /// The entry's bytes.
    pub span: Span,
}

/// The load-configuration directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct LoadConfig {
    /// Every field the structure's own `Size` covers, in layout order.
    pub fields: Vec<LoadConfigField>,
    /// Valid indirect-call targets (Control Flow Guard).
    pub guard_cf_functions: Vec<GuardEntry>,
    /// IAT entries whose address is taken (CFG).
    pub guard_iat_entries: Vec<GuardEntry>,
    /// Valid `longjmp` targets (CFG).
    pub guard_longjump_targets: Vec<GuardEntry>,
    /// Valid exception-handler continuation addresses (EH continuation metadata).
    pub guard_eh_continuations: Vec<GuardEntry>,
    /// SafeSEH: registered exception handlers (RVAs), 32-bit x86 only.
    pub se_handlers: Vec<Field<u32>>,
    /// The bytes the structure's `Size` covers.
    pub span: Span,
}

impl LoadConfig {
    /// Value of a field, if the structure is large enough to contain it.
    pub fn get(&self, name: &str) -> Option<&Field<u64>> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| &f.value)
    }

    /// Value of a field, or 0.
    pub fn value(&self, name: &str) -> u64 {
        self.get(name).map_or(0, |f| f.value)
    }

    /// `GuardFlags`, or 0.
    pub fn guard_flags(&self) -> u32 {
        self.value("GuardFlags") as u32
    }
}

/// (name, offset in PE32, offset in PE32+, size in PE32, size in PE32+)
const LAYOUT: &[(&str, u64, u64, u8, u8)] = &[
    ("Size", 0, 0, 4, 4),
    ("TimeDateStamp", 4, 4, 4, 4),
    ("MajorVersion", 8, 8, 2, 2),
    ("MinorVersion", 10, 10, 2, 2),
    ("GlobalFlagsClear", 12, 12, 4, 4),
    ("GlobalFlagsSet", 16, 16, 4, 4),
    ("CriticalSectionDefaultTimeout", 20, 20, 4, 4),
    ("DeCommitFreeBlockThreshold", 24, 24, 4, 8),
    ("DeCommitTotalFreeThreshold", 28, 32, 4, 8),
    ("LockPrefixTable", 32, 40, 4, 8),
    ("MaximumAllocationSize", 36, 48, 4, 8),
    ("VirtualMemoryThreshold", 40, 56, 4, 8),
    // The two layouts order these two fields differently.
    ("ProcessHeapFlags", 44, 72, 4, 4),
    ("ProcessAffinityMask", 48, 64, 4, 8),
    ("CSDVersion", 52, 76, 2, 2),
    ("DependentLoadFlags", 54, 78, 2, 2),
    ("EditList", 56, 80, 4, 8),
    ("SecurityCookie", 60, 88, 4, 8),
    ("SEHandlerTable", 64, 96, 4, 8),
    ("SEHandlerCount", 68, 104, 4, 8),
    ("GuardCFCheckFunction", 72, 112, 4, 8),
    ("GuardCFCheckDispatch", 76, 120, 4, 8),
    ("GuardCFFunctionTable", 80, 128, 4, 8),
    ("GuardCFFunctionCount", 84, 136, 4, 8),
    ("GuardFlags", 88, 144, 4, 4),
    ("CodeIntegrityFlags", 92, 148, 2, 2),
    ("CodeIntegrityCatalog", 94, 150, 2, 2),
    ("CodeIntegrityCatalogOffset", 96, 152, 4, 4),
    ("GuardAddressTakenIatEntryTable", 104, 160, 4, 8),
    ("GuardAddressTakenIatEntryCount", 108, 168, 4, 8),
    ("GuardLongJumpTargetTable", 112, 176, 4, 8),
    ("GuardLongJumpTargetCount", 116, 184, 4, 8),
    ("DynamicValueRelocTable", 120, 192, 4, 8),
    ("CHPEMetadataPointer", 124, 200, 4, 8),
    ("GuardRFFailureRoutine", 128, 208, 4, 8),
    ("GuardRFFailureRoutineFunctionPointer", 132, 216, 4, 8),
    ("DynamicValueRelocTableOffset", 136, 224, 4, 4),
    ("DynamicValueRelocTableSection", 140, 228, 2, 2),
    ("GuardRFVerifyStackPointerFunctionPointer", 144, 232, 4, 8),
    ("HotPatchTableOffset", 148, 240, 4, 4),
    ("EnclaveConfigurationPointer", 156, 248, 4, 8),
    ("VolatileMetadataPointer", 160, 256, 4, 8),
    ("GuardEHContinuationTable", 164, 264, 4, 8),
    ("GuardEHContinuationCount", 168, 272, 4, 8),
    ("GuardXFGCheckFunctionPointer", 172, 280, 4, 8),
    ("GuardXFGDispatchFunctionPointer", 176, 288, 4, 8),
    ("GuardXFGTableDispatchFunctionPointer", 180, 296, 4, 8),
    ("CastGuardOsDeterminedFailureMode", 184, 304, 4, 8),
    ("GuardMemcpyFunctionPointer", 188, 312, 4, 8),
];

pub(crate) fn read_load_config(
    image: &Image<'_>,
    pe32_plus: bool,
    rva: u64,
    dir_size: u64,
    max: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Option<LoadConfig> {
    let size = match image.u32(rva) {
        Ok(s) => s,
        Err(_) => {
            anomalies.push(Anomaly::new(
                Severity::Error,
                "pe.loadcfg.truncated",
                format!("load configuration at RVA {rva:#x} cannot be read"),
            ));
            return None;
        }
    };
    let declared = u64::from(size.value);
    if declared != dir_size && dir_size != 0 {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.loadcfg.size",
                format!(
                    "load configuration says it is {declared:#x} bytes but its directory says {dir_size:#x}"
                ),
            )
            .at(size.span),
        );
    }
    let mut fields = Vec::new();
    for &(name, o32, o64, w32, w64) in LAYOUT {
        let (o, w) = if pe32_plus { (o64, w64) } else { (o32, w32) };
        if o + u64::from(w) > declared {
            break;
        }
        match image.uint(rva + o, w) {
            Ok(value) => fields.push(LoadConfigField { name, value }),
            Err(_) => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "pe.loadcfg.truncated",
                        format!("load configuration field {name} is outside the file"),
                    )
                    .at(size.span),
                );
                break;
            }
        }
    }
    let mut lc = LoadConfig {
        fields,
        guard_cf_functions: Vec::new(),
        guard_iat_entries: Vec::new(),
        guard_longjump_targets: Vec::new(),
        guard_eh_continuations: Vec::new(),
        se_handlers: Vec::new(),
        span: Span::new(size.span.offset.0, declared),
    };
    let flags = lc.guard_flags();
    let stride = 4 + u64::from(
        (flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    );
    let table = |t: &str, n: &str, anomalies: &mut Vec<Anomaly>| -> Vec<GuardEntry> {
        read_guard_table(image, lc.value(t), lc.value(n), stride, max, t, anomalies)
    };
    let cf = table("GuardCFFunctionTable", "GuardCFFunctionCount", anomalies);
    let iat = table(
        "GuardAddressTakenIatEntryTable",
        "GuardAddressTakenIatEntryCount",
        anomalies,
    );
    let lj = table(
        "GuardLongJumpTargetTable",
        "GuardLongJumpTargetCount",
        anomalies,
    );
    let eh = table(
        "GuardEHContinuationTable",
        "GuardEHContinuationCount",
        anomalies,
    );
    if cf.windows(2).any(|w| w[0].rva >= w[1].rva) {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.cfg.unsorted",
            "Control Flow Guard function table is not sorted by address",
        ).os("Windows builds the CFG bitmap from this table; out-of-order entries suggest tampering"));
    }
    lc.guard_cf_functions = cf;
    lc.guard_iat_entries = iat;
    lc.guard_longjump_targets = lj;
    lc.guard_eh_continuations = eh;

    let seh = lc.value("SEHandlerTable");
    let seh_count = lc.value("SEHandlerCount");
    if seh != 0 && seh_count != 0 {
        match image.rva_of(seh) {
            Some(t) => {
                for i in 0..seh_count.min(u64::from(max)) {
                    match image.u32(t + i * 4) {
                        Ok(h) => lc.se_handlers.push(h),
                        Err(_) => {
                            anomalies.push(Anomaly::new(
                                Severity::Warning,
                                "pe.loadcfg.table_invalid",
                                format!("SafeSEH handler table at {seh:#x} cannot be read past entry {i}"),
                            ));
                            break;
                        }
                    }
                }
            }
            None => anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.loadcfg.table_invalid",
                format!("SafeSEH handler table at {seh:#x} is below the image base"),
            )),
        }
    }
    if lc.value("CHPEMetadataPointer") != 0 {
        anomalies.push(Anomaly::new(
            Severity::Info,
            "pe.chpe",
            "hybrid image (ARM64EC / ARM64X / CHPE): it contains code for two architectures; \
             only the header's machine is modelled",
        ));
    }
    Some(lc)
}

fn read_guard_table(
    image: &Image<'_>,
    va: u64,
    count: u64,
    stride: u64,
    max: u32,
    name: &str,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<GuardEntry> {
    let mut out = Vec::new();
    if va == 0 || count == 0 {
        return out;
    }
    let Some(start) = image.rva_of(va) else {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.loadcfg.table_invalid",
            format!("{name} at {va:#x} is below the image base"),
        ));
        return out;
    };
    if count > u64::from(max) {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.loadcfg.limit",
            format!("{name} has {count} entries; only {max} are read"),
        ));
    }
    for i in 0..count.min(u64::from(max)) {
        let at = start + i * stride;
        let Ok(r) = image.u32(at) else {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.loadcfg.table_invalid",
                format!("{name} at {va:#x} cannot be read past entry {i}"),
            ));
            break;
        };
        let flags = (stride > 4)
            .then(|| image.uint(at + 4, 1).ok().map(|f| f.value as u8))
            .flatten();
        out.push(GuardEntry {
            rva: r.value,
            flags,
            span: Span::new(r.span.offset.0, stride),
        });
    }
    out
}
