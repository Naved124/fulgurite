//! Exploit-mitigation verdicts for PE images, each with the evidence it rests on.

use super::consts::*;
use super::{DebugContent, PeInfo, SectionHeader};
use crate::mitigation::{self as mit, Mitigation, MitigationReport, Verdict};
use crate::model::{BinaryKind, Symbol, SymbolTable};
use fg_core::Evidence;

pub(crate) fn report(
    info: &PeInfo,
    kind: BinaryKind,
    symbols: &[Symbol],
    relocs: usize,
) -> MitigationReport {
    MitigationReport::new(
        aslr(info, kind, relocs),
        dep(info, kind),
        iat_protection(info),
        gs(info, symbols),
        fortify(symbols),
    )
    .with_cfi(cfi(info))
    .with_separate_code(separate_code(info))
    .with_library_paths(search_path(info))
    .with_seh(safe_seh(info))
}

fn is_efi(info: &PeInfo) -> bool {
    (10..=13).contains(&info.optional.subsystem.value)
}

fn flag_evidence(info: &PeInfo, flag: u16, name: &str) -> Evidence {
    let o = &info.optional;
    Evidence::at(
        format!(
            "DllCharacteristics {:#06x}: {name} {}",
            o.dll_characteristics.value,
            if o.has(flag) { "set" } else { "not set" }
        ),
        o.dll_characteristics.span,
    )
}

fn aslr(info: &PeInfo, kind: BinaryKind, relocs: usize) -> Mitigation {
    let o = &info.optional;
    let fh = &info.file_header;
    let mut ev = vec![flag_evidence(
        info,
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
        "DYNAMIC_BASE",
    )];
    let stripped = fh.has(IMAGE_FILE_RELOCS_STRIPPED);
    if stripped {
        ev.push(Evidence::at(
            "IMAGE_FILE_RELOCS_STRIPPED: the image cannot be moved",
            fh.characteristics.span,
        ));
    }
    match info.directory(DIR_BASERELOC) {
        Some(d) => ev.push(Evidence::at(
            format!("base relocation directory: {relocs} relocations"),
            d.rva.span,
        )),
        None => ev.push(Evidence::new("no base relocation directory")),
    }
    let plus = info.is_pe32_plus();
    if plus {
        ev.push(flag_evidence(
            info,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
            "HIGH_ENTROPY_VA",
        ));
    }
    if is_efi(info) {
        ev.push(Evidence::new(
            "UEFI image: the firmware loads it wherever it allocates memory and applies the base relocations",
        ));
    }
    let what = if kind == BinaryKind::SharedObject {
        "DLL"
    } else {
        "image"
    };
    let (verdict, summary) = if !o.has(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) || stripped {
        if !stripped && relocs > 0 {
            ev.push(Evidence::new(
                "relocations are present, so Windows' mandatory ASLR (ForceRelocateImages) can still move it when enabled",
            ));
        }
        (
            Verdict::Disabled,
            format!(
                "{what} loads at its preferred base {:#x}",
                o.image_base.value
            ),
        )
    } else if info.directory(DIR_BASERELOC).is_none() {
        (
            Verdict::Partial,
            "ASLR requested but there are no base relocations: correct only if the code uses no absolute addresses"
                .to_string(),
        )
    } else if plus && !o.has(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
        (
            Verdict::Partial,
            "ASLR without HIGH_ENTROPY_VA: the 64-bit address space is not used, so fewer load addresses are possible"
                .to_string(),
        )
    } else {
        (
            Verdict::Enabled,
            format!("{what} is relocated to a random base (ASLR)"),
        )
    };
    Mitigation::new("PIE", verdict, summary, ev, mit::WHY_PIE)
}

fn wx_notes(info: &PeInfo, ev: &mut Vec<Evidence>) {
    for s in info.sections.iter().filter(|s| s.perms().is_wx()) {
        ev.push(Evidence::at(
            format!(
                "note: section {:?} is writable and executable, so code can be injected there regardless",
                s.name
            ),
            s.characteristics.span,
        ));
    }
}

fn dep(info: &PeInfo, kind: BinaryKind) -> Mitigation {
    let mut ev = vec![flag_evidence(
        info,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        "NX_COMPAT",
    )];
    let marked = info.optional.has(IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    let (verdict, summary) = if is_efi(info) {
        (
            Verdict::Unknown,
            "UEFI image: memory protection is decided by the firmware".to_string(),
        )
    } else if info.is_pe32_plus() {
        ev.push(Evidence::new(
            "64-bit Windows always runs 64-bit code with DEP, whatever the flag says",
        ));
        (Verdict::Enabled, "64-bit: DEP is always on".to_string())
    } else if kind == BinaryKind::SharedObject {
        if marked {
            (
                Verdict::Enabled,
                "DLL marked DEP-compatible (the host program decides DEP)".to_string(),
            )
        } else {
            (
                Verdict::Unknown,
                "DEP is decided by the program that loads this DLL".to_string(),
            )
        }
    } else if marked {
        (
            Verdict::Enabled,
            "marked NX_COMPAT: runs with DEP".to_string(),
        )
    } else {
        ev.push(Evidence::new(
            "under the default OptIn policy, 32-bit programs without NX_COMPAT run without DEP",
        ));
        (
            Verdict::Disabled,
            "not marked NX_COMPAT: data can be executed".to_string(),
        )
    };
    wx_notes(info, &mut ev);
    Mitigation::new("NX", verdict, summary, ev, mit::WHY_NX)
}

fn section_label(s: Option<&SectionHeader>) -> String {
    s.map_or_else(
        || "no section".to_string(),
        |s| format!("{:?} ({})", s.name, s.perms()),
    )
}

fn iat_protection(info: &PeInfo) -> Mitigation {
    const NAME: &str = "RELRO";
    if info.imports.is_empty() && info.delay_imports.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::NotApplicable,
            "no imports: there is no import address table to protect",
            Vec::new(),
            mit::WHY_RELRO,
        );
    }
    let mut ev = vec![Evidence::new(
        "PE has no RELRO; its equivalent is the import address table (IAT) being read-only: \
         the loader fills it, then restores the protection of the section it lives in",
    )];
    let low = u64::from(info.optional.section_alignment.value) < section::PAGE_SIZE;
    let mut writable = 0;
    for d in &info.imports {
        let s = info.section_at(u64::from(d.address_table.value));
        if s.is_none_or(|s| s.perms().write) {
            writable += 1;
        }
        ev.push(Evidence::at(
            format!(
                "IAT of {} at RVA {:#x} is in {}",
                d.name.value,
                d.address_table.value,
                section_label(s)
            ),
            d.address_table.span,
        ));
    }
    let flags = info.load_config.as_ref().map_or(0, |l| l.guard_flags());
    let delay_protected = flags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT != 0
        && flags & IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION != 0;
    let mut delay_writable = 0;
    for d in &info.delay_imports {
        let s = info.section_at(u64::from(d.address_table.value));
        if s.is_none_or(|s| s.perms().write) && !delay_protected {
            delay_writable += 1;
        }
        ev.push(Evidence::at(
            format!(
                "delay-load IAT of {} at RVA {:#x} is in {}",
                d.name.value,
                d.address_table.value,
                section_label(s)
            ),
            d.address_table.span,
        ));
    }
    if !info.delay_imports.is_empty() && delay_protected {
        ev.push(Evidence::new(
            "load config: PROTECT_DELAYLOAD_IAT + DELAYLOAD_IAT_IN_ITS_OWN_SECTION: delay-load slots are read-only between resolutions",
        ));
    }
    if low {
        ev.push(Evidence::new(
            "low-alignment image: sections share pages, so the IAT cannot be protected on its own",
        ));
    }
    let (verdict, summary) = if writable > 0 || low {
        (
            Verdict::Disabled,
            "IAT is writable at run time: function pointers can be overwritten",
        )
    } else if delay_writable > 0 {
        (
            Verdict::Partial,
            "IAT is read-only, but delay-load slots stay writable",
        )
    } else {
        (Verdict::Enabled, "IAT is read-only after loading")
    };
    Mitigation::new(NAME, verdict, summary, ev, mit::WHY_RELRO)
}

use super::section;

fn gs(info: &PeInfo, symbols: &[Symbol]) -> Mitigation {
    const NAME: &str = "Canary";
    const MARKERS: [&str; 6] = [
        "__security_check_cookie",
        "__GSHandlerCheck",
        "__security_cookie",
        "__stack_chk_fail",
        "__stack_chk_guard",
        "__stack_chk_fail_local",
    ];
    let mut ev = Vec::new();
    let mut found = false;
    let lc = info.load_config.as_ref();
    let cookie = lc
        .and_then(|l| l.get("SecurityCookie"))
        .filter(|c| c.value != 0);
    let unused = lc.is_some_and(|l| l.guard_flags() & IMAGE_GUARD_SECURITY_COOKIE_UNUSED != 0);
    if let Some(c) = cookie {
        ev.push(Evidence::at(
            format!(
                "load config registers a /GS security cookie at {:#x}",
                c.value
            ),
            c.span,
        ));
    }
    for d in &info.debug {
        if let DebugContent::VcFeature {
            gs, c_cpp, span, ..
        } = &d.content
        {
            ev.push(Evidence::at(
                format!("VC feature counts: {gs} of {c_cpp} C/C++ objects compiled with /GS"),
                *span,
            ));
            found |= *gs > 0;
        }
    }
    if let Some(s) = symbols.iter().find(|s| MARKERS.contains(&s.base_name())) {
        let what = match s.table {
            SymbolTable::Imports | SymbolTable::DelayImports => "imports",
            _ => "defines",
        };
        ev.push(Evidence::at(
            format!("{what} {}", s.display_name()),
            s.defined_by,
        ));
        found = true;
    }
    let (verdict, summary) = if unused {
        ev.push(Evidence::new(
            "load config GuardFlags: SECURITY_COOKIE_UNUSED",
        ));
        (
            Verdict::Disabled,
            "the linker marked the security cookie as unused",
        )
    } else if found {
        (Verdict::Enabled, "stack cookies in use")
    } else if cookie.is_some() {
        ev.push(Evidence::new(
            "the C runtime registers the cookie; whether the program's own functions check it needs disassembly",
        ));
        (Verdict::Enabled, "/GS cookie registered")
    } else if symbols.iter().any(|s| s.table == SymbolTable::Coff) {
        ev.push(Evidence::new(format!(
            "searched {} symbols for __security_check_cookie / __stack_chk_fail",
            symbols.len()
        )));
        (
            Verdict::Disabled,
            "no canary: no function references a stack-cookie check",
        )
    } else {
        (
            Verdict::Unknown,
            "no cookie in the load configuration and no symbols to check; finding canaries needs disassembly",
        )
    };
    Mitigation::new(NAME, verdict, summary, ev, mit::WHY_CANARY)
}

fn fortify(symbols: &[Symbol]) -> Mitigation {
    let chk: Vec<&Symbol> = symbols
        .iter()
        .filter(|s| {
            let n = s.base_name();
            n.starts_with("__") && n.ends_with("_chk") && !n.starts_with("__stack_chk")
        })
        .collect();
    if chk.is_empty() {
        return Mitigation::new(
            "FORTIFY",
            Verdict::NotApplicable,
            "no __*_chk functions: FORTIFY_SOURCE is a glibc / MinGW feature, MSVC uses /GS and checked CRT functions instead",
            Vec::new(),
            mit::WHY_FORTIFY,
        );
    }
    let ev = chk
        .iter()
        .take(16)
        .map(|s| Evidence::at(s.display_name(), s.defined_by))
        .collect();
    Mitigation::new(
        "FORTIFY",
        Verdict::Enabled,
        format!("{} fortified function(s) referenced", chk.len()),
        ev,
        mit::WHY_FORTIFY,
    )
}

fn cfi(info: &PeInfo) -> Mitigation {
    let mut ev = vec![flag_evidence(
        info,
        IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        "GUARD_CF",
    )];
    let flags = info.load_config.as_ref().map_or(0, |l| l.guard_flags());
    let instrumented = flags & IMAGE_GUARD_CF_INSTRUMENTED != 0;
    let cfg = info.optional.has(IMAGE_DLLCHARACTERISTICS_GUARD_CF) && instrumented;
    match &info.load_config {
        Some(l) => {
            let names = flag_names(
                flags & !IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK,
                GUARD_FLAGS,
            );
            ev.push(Evidence::at(
                format!(
                    "load config GuardFlags {flags:#x} [{}]; {} valid call targets",
                    names.join(", "),
                    l.guard_cf_functions.len()
                ),
                l.get("GuardFlags").map_or(l.span, |f| f.span),
            ));
        }
        None => ev.push(Evidence::new("no load configuration: CFG cannot be active")),
    }
    if info.optional.has(IMAGE_DLLCHARACTERISTICS_GUARD_CF) && !instrumented {
        ev.push(Evidence::new(
            "GUARD_CF is set but the code is not CFG-instrumented, so the flag has no effect",
        ));
    }
    let x86 = matches!(
        info.file_header.machine.value,
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_I386
    );
    let shstk = info
        .ex_dll_characteristics()
        .is_some_and(|f| f.value & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT != 0);
    match info.ex_dll_characteristics() {
        Some(f) => ev.push(Evidence::at(
            format!(
                "extended DLL characteristics {:#x} [{}]",
                f.value,
                flag_names(f.value, EX_DLL_CHARACTERISTICS).join(", ")
            ),
            f.span,
        )),
        None if x86 => ev.push(Evidence::new(
            "no extended DLL characteristics: not marked CET shadow-stack compatible",
        )),
        None => {}
    }
    let (verdict, summary) = match (cfg, shstk, x86) {
        (true, true, _) => (Verdict::Enabled, "Control Flow Guard and CET shadow stack"),
        (true, false, true) => (
            Verdict::Partial,
            "Control Flow Guard (forward edges) only; not CET shadow-stack compatible",
        ),
        (true, false, false) => (Verdict::Enabled, "Control Flow Guard"),
        (false, true, _) => (
            Verdict::Partial,
            "CET shadow stack (return addresses) only; no Control Flow Guard",
        ),
        (false, false, _) => (
            Verdict::Disabled,
            "no Control Flow Guard and no shadow-stack marking",
        ),
    };
    Mitigation::new("CFI", verdict, summary, ev, mit::WHY_CFI)
}

fn separate_code(info: &PeInfo) -> Mitigation {
    const NAME: &str = "SepCode";
    let mut ev = Vec::new();
    let wx: Vec<&SectionHeader> = info.sections.iter().filter(|s| s.perms().is_wx()).collect();
    for s in &wx {
        ev.push(Evidence::at(
            format!(
                "section {:?} is writable and executable ({:#x})",
                s.name, s.characteristics.value
            ),
            s.characteristics.span,
        ));
    }
    if !wx.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::Disabled,
            "a section is both writable and executable",
            ev,
            mit::WHY_SEPARATE_CODE,
        );
    }
    if u64::from(info.optional.section_alignment.value) < section::PAGE_SIZE {
        ev.push(Evidence::at(
            format!(
                "section alignment {:#x}",
                info.optional.section_alignment.value
            ),
            info.optional.section_alignment.span,
        ));
        return Mitigation::new(
            NAME,
            Verdict::Partial,
            "low-alignment image: code and data share pages",
            ev,
            mit::WHY_SEPARATE_CODE,
        );
    }
    // Data tables the loader or the runtime reads, placed in executable sections.
    for d in &info.optional.data_directories {
        let i = usize::from(d.index);
        if !d.is_present()
            || matches!(
                i,
                DIR_SECURITY | DIR_GLOBALPTR | DIR_ARCHITECTURE | DIR_RESERVED
            )
        {
            continue;
        }
        if let Some(s) = info.section_at(u64::from(d.rva.value))
            && s.perms().execute
        {
            ev.push(Evidence::at(
                format!(
                    "{} directory is inside executable section {:?}",
                    d.name(),
                    s.name
                ),
                d.rva.span,
            ));
        }
    }
    if !ev.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::Partial,
            "data tables are mapped executable",
            ev,
            mit::WHY_SEPARATE_CODE,
        );
    }
    ev.push(Evidence::new("no writable+executable section; headers are mapped read-only; no data directory lies in code"));
    Mitigation::new(
        NAME,
        Verdict::Enabled,
        "code is kept apart from data",
        ev,
        mit::WHY_SEPARATE_CODE,
    )
}

fn search_path(info: &PeInfo) -> Mitigation {
    const NAME: &str = "LibPath";
    if info.imports.is_empty() && info.delay_imports.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::NotApplicable,
            "no imports: no DLLs are searched for",
            Vec::new(),
            mit::WHY_LIBRARY_PATHS,
        );
    }
    let flags = info
        .load_config
        .as_ref()
        .and_then(|l| l.get("DependentLoadFlags"))
        .filter(|f| f.value != 0);
    match flags {
        Some(f) => {
            let v = f.value as u16;
            let ev = vec![Evidence::at(
                format!(
                    "load config DependentLoadFlags {v:#x} [{}]",
                    flag_names(v, LOAD_FLAGS).join(", ")
                ),
                f.span,
            )];
            let app_dir = v
                & (LOAD_LIBRARY_SEARCH_APPLICATION_DIR
                    | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
                    | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
                != 0;
            if v & LOAD_LIBRARY_SEARCH_SYSTEM32 != 0 && !app_dir {
                Mitigation::new(
                    NAME,
                    Verdict::Enabled,
                    "imported DLLs are loaded from System32 only",
                    ev,
                    mit::WHY_LIBRARY_PATHS,
                )
            } else {
                Mitigation::new(
                    NAME,
                    Verdict::Partial,
                    "restricted search order that still includes the program's directory",
                    ev,
                    mit::WHY_LIBRARY_PATHS,
                )
            }
        }
        None => Mitigation::new(
            NAME,
            Verdict::Partial,
            "default DLL search order: DLLs that are not KnownDLLs are looked for in the program's own directory first",
            vec![Evidence::new(
                "no DependentLoadFlags: Windows searches the application directory, then System32, the Windows directory, \
                 the current directory and PATH (like an ELF $ORIGIN path: safe only if the program's directory is not writable by others)",
            )],
            mit::WHY_LIBRARY_PATHS,
        ),
    }
}

fn safe_seh(info: &PeInfo) -> Mitigation {
    const NAME: &str = "SafeSEH";
    if info.file_header.machine.value != IMAGE_FILE_MACHINE_I386 {
        return Mitigation::new(
            NAME,
            Verdict::NotApplicable,
            "table-based exception handling: handler addresses are not stored on the stack",
            Vec::new(),
            mit::WHY_SEH,
        );
    }
    if info.optional.has(IMAGE_DLLCHARACTERISTICS_NO_SEH) {
        return Mitigation::new(
            NAME,
            Verdict::Enabled,
            "NO_SEH: the image registers no exception handlers, so none can be hijacked",
            vec![flag_evidence(
                info,
                IMAGE_DLLCHARACTERISTICS_NO_SEH,
                "NO_SEH",
            )],
            mit::WHY_SEH,
        );
    }
    match info.load_config.as_ref().and_then(|l| {
        l.get("SEHandlerTable")
            .filter(|t| t.value != 0)
            .map(|t| (l, t))
    }) {
        Some((l, t)) => Mitigation::new(
            NAME,
            Verdict::Enabled,
            format!("SafeSEH table lists {} handler(s)", l.se_handlers.len()),
            vec![Evidence::at(
                format!("load config SEHandlerTable {:#x}", t.value),
                t.span,
            )],
            mit::WHY_SEH,
        ),
        None => Mitigation::new(
            NAME,
            Verdict::Disabled,
            "no SafeSEH table: an overwritten exception record can point anywhere in this image",
            vec![
                flag_evidence(info, IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH"),
                Evidence::new("no SEHandlerTable in the load configuration"),
            ],
            mit::WHY_SEH,
        ),
    }
}
