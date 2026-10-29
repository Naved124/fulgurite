//! PE/COFF constants and their display names (Microsoft PE/COFF specification,
//! `winnt.h`).
#![allow(missing_docs)]

/// `MZ`: DOS header magic.
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
/// `PE\0\0`: NT headers signature.
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// Size of the DOS header.
pub const DOS_HEADER_SIZE: u64 = 0x40;
/// Offset of `e_lfanew` in the DOS header.
pub const E_LFANEW_OFFSET: u64 = 0x3c;
/// Size of the COFF file header.
pub const FILE_HEADER_SIZE: u64 = 20;
/// Size of one section header.
pub const SECTION_HEADER_SIZE: u64 = 40;
/// Size of one COFF symbol record.
pub const COFF_SYMBOL_SIZE: u64 = 18;
/// Number of data directories the loader uses (`NumberOfRvaAndSizes` is clamped to it).
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: u32 = 16;

/// Optional header magic of PE32 (32-bit) images.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
/// Optional header magic of PE32+ (64-bit) images.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
/// Optional header magic of ROM images.
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

/// Machine types.
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x1c4;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x1c0;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x1c2;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x200;
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0xebc;
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
pub const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;
pub const IMAGE_FILE_MACHINE_LOONGARCH32: u16 = 0x6232;
pub const IMAGE_FILE_MACHINE_LOONGARCH64: u16 = 0x6264;

/// File characteristics.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// DLL characteristics.
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

/// Section characteristics.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00f0_0000;

/// Data directory indexes.
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_SECURITY: usize = 4;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_DEBUG: usize = 6;
pub const DIR_ARCHITECTURE: usize = 7;
pub const DIR_GLOBALPTR: usize = 8;
pub const DIR_TLS: usize = 9;
pub const DIR_LOAD_CONFIG: usize = 10;
pub const DIR_BOUND_IMPORT: usize = 11;
pub const DIR_IAT: usize = 12;
pub const DIR_DELAY_IMPORT: usize = 13;
pub const DIR_CLR: usize = 14;
pub const DIR_RESERVED: usize = 15;

/// Base relocation types.
pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
pub const IMAGE_REL_BASED_HIGH: u8 = 1;
pub const IMAGE_REL_BASED_LOW: u8 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u8 = 4;
pub const IMAGE_REL_BASED_ARM_MOV32: u8 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u8 = 7;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

/// Debug directory types.
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
pub const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;

/// Extended DLL characteristics (debug type 20).
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: u32 = 0x01;
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE: u32 = 0x02;
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: u32 = 0x04;
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC: u32 = 0x08;
pub const IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT: u32 = 0x40;
pub const IMAGE_DLLCHARACTERISTICS_EX_HOTPATCH_COMPATIBLE: u32 = 0x80;

/// Load-config `GuardFlags`.
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
pub const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
pub const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
pub const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
pub const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
pub const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
pub const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
pub const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
pub const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;
pub const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
pub const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
pub const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
pub const IMAGE_GUARD_CASTGUARD_PRESENT: u32 = 0x0100_0000;
pub const IMAGE_GUARD_MEMCPY_PRESENT: u32 = 0x0200_0000;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xf000_0000;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;

/// `LoadLibraryEx` search flags that may appear in `DependentLoadFlags`.
pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u16 = 0x0100;
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u16 = 0x0200;
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u16 = 0x0400;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x0800;
pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u16 = 0x1000;

/// x64 `UNWIND_INFO` flags.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// COFF symbol storage classes.
pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const IMAGE_SYM_CLASS_LABEL: u8 = 6;
pub const IMAGE_SYM_CLASS_FUNCTION: u8 = 101;
pub const IMAGE_SYM_CLASS_FILE: u8 = 103;
pub const IMAGE_SYM_CLASS_SECTION: u8 = 104;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;
/// COFF complex type "function" (`Type >> 4`).
pub const IMAGE_SYM_DTYPE_FUNCTION: u16 = 2;

/// Certificate types.
pub const WIN_CERT_TYPE_X509: u16 = 1;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 2;
pub const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 4;

/// Display name of a machine type, as `llvm-readobj` prints it without the prefix.
pub fn machine_name(m: u16) -> Option<&'static str> {
    Some(match m {
        IMAGE_FILE_MACHINE_UNKNOWN => "UNKNOWN",
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_ARMNT => "ARMNT",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_THUMB => "THUMB",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_ARM64EC => "ARM64EC",
        IMAGE_FILE_MACHINE_ARM64X => "ARM64X",
        IMAGE_FILE_MACHINE_IA64 => "IA64",
        IMAGE_FILE_MACHINE_EBC => "EBC",
        IMAGE_FILE_MACHINE_RISCV32 => "RISCV32",
        IMAGE_FILE_MACHINE_RISCV64 => "RISCV64",
        IMAGE_FILE_MACHINE_RISCV128 => "RISCV128",
        IMAGE_FILE_MACHINE_LOONGARCH32 => "LOONGARCH32",
        IMAGE_FILE_MACHINE_LOONGARCH64 => "LOONGARCH64",
        0x1d3 => "AM33",
        0x9041 => "M32R",
        0x266 => "MIPS16",
        0x366 => "MIPSFPU",
        0x466 => "MIPSFPU16",
        0x1f0 => "POWERPC",
        0x1f1 => "POWERPCFP",
        0x166 => "R4000",
        0x1a2 => "SH3",
        0x1a3 => "SH3DSP",
        0x1a6 => "SH4",
        0x1a8 => "SH5",
        0x169 => "WCEMIPSV2",
        _ => return None,
    })
}

/// Display name of a subsystem.
pub fn subsystem_name(s: u16) -> Option<&'static str> {
    Some(match s {
        0 => "unknown",
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        8 => "native Win9x driver",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => return None,
    })
}

/// Names of the 16 data directories, in index order.
pub const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLR",
    "Reserved",
];

/// Names of the file characteristics bits, low bit first.
pub const FILE_CHARACTERISTICS: &[(u16, &str)] = &[
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
];

/// Names of the DLL characteristics bits.
pub const DLL_CHARACTERISTICS: &[(u16, &str)] = &[
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
];

/// Names of the section characteristics bits (alignment excluded).
pub const SECTION_CHARACTERISTICS: &[(u32, &str)] = &[
    (0x0000_0008, "TYPE_NO_PAD"),
    (0x0000_0020, "CNT_CODE"),
    (0x0000_0040, "CNT_INITIALIZED_DATA"),
    (0x0000_0080, "CNT_UNINITIALIZED_DATA"),
    (0x0000_0100, "LNK_OTHER"),
    (0x0000_0200, "LNK_INFO"),
    (0x0000_0800, "LNK_REMOVE"),
    (0x0000_1000, "LNK_COMDAT"),
    (0x0000_8000, "GPREL"),
    (0x0002_0000, "MEM_PURGEABLE"),
    (0x0004_0000, "MEM_LOCKED"),
    (0x0008_0000, "MEM_PRELOAD"),
    (0x0100_0000, "LNK_NRELOC_OVFL"),
    (0x0200_0000, "MEM_DISCARDABLE"),
    (0x0400_0000, "MEM_NOT_CACHED"),
    (0x0800_0000, "MEM_NOT_PAGED"),
    (0x1000_0000, "MEM_SHARED"),
    (0x2000_0000, "MEM_EXECUTE"),
    (0x4000_0000, "MEM_READ"),
    (0x8000_0000, "MEM_WRITE"),
];

/// Names of the load-config `GuardFlags` bits (the table-size nibble excluded).
pub const GUARD_FLAGS: &[(u32, &str)] = &[
    (IMAGE_GUARD_CF_INSTRUMENTED, "CF_INSTRUMENTED"),
    (IMAGE_GUARD_CFW_INSTRUMENTED, "CFW_INSTRUMENTED"),
    (
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
        "CF_FUNCTION_TABLE_PRESENT",
    ),
    (IMAGE_GUARD_SECURITY_COOKIE_UNUSED, "SECURITY_COOKIE_UNUSED"),
    (IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, "PROTECT_DELAYLOAD_IAT"),
    (
        IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION,
        "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
    ),
    (
        IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT,
        "CF_EXPORT_SUPPRESSION_INFO_PRESENT",
    ),
    (
        IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION,
        "CF_ENABLE_EXPORT_SUPPRESSION",
    ),
    (
        IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT,
        "CF_LONGJUMP_TABLE_PRESENT",
    ),
    (IMAGE_GUARD_RF_INSTRUMENTED, "RF_INSTRUMENTED"),
    (IMAGE_GUARD_RF_ENABLE, "RF_ENABLE"),
    (IMAGE_GUARD_RF_STRICT, "RF_STRICT"),
    (IMAGE_GUARD_RETPOLINE_PRESENT, "RETPOLINE_PRESENT"),
    (
        IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,
        "EH_CONTINUATION_TABLE_PRESENT",
    ),
    (IMAGE_GUARD_XFG_ENABLED, "XFG_ENABLED"),
    (IMAGE_GUARD_CASTGUARD_PRESENT, "CASTGUARD_PRESENT"),
    (IMAGE_GUARD_MEMCPY_PRESENT, "MEMCPY_PRESENT"),
];

/// Names of the extended DLL characteristics bits.
pub const EX_DLL_CHARACTERISTICS: &[(u32, &str)] = &[
    (IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, "CET_COMPAT"),
    (
        IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE,
        "CET_COMPAT_STRICT_MODE",
    ),
    (
        IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE,
        "CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE",
    ),
    (
        IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC,
        "CET_DYNAMIC_APIS_ALLOW_IN_PROC",
    ),
    (
        IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT,
        "FORWARD_CFI_COMPAT",
    ),
    (
        IMAGE_DLLCHARACTERISTICS_EX_HOTPATCH_COMPATIBLE,
        "HOTPATCH_COMPATIBLE",
    ),
];

/// Names of the `LoadLibraryEx` search flags used in `DependentLoadFlags`.
pub const LOAD_FLAGS: &[(u16, &str)] = &[
    (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, "SEARCH_DLL_LOAD_DIR"),
    (
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
        "SEARCH_APPLICATION_DIR",
    ),
    (LOAD_LIBRARY_SEARCH_USER_DIRS, "SEARCH_USER_DIRS"),
    (LOAD_LIBRARY_SEARCH_SYSTEM32, "SEARCH_SYSTEM32"),
    (LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, "SEARCH_DEFAULT_DIRS"),
];

/// Joins the names of the bits set in `value`, plus any unnamed remainder in hex.
pub fn flag_names<T>(value: T, table: &[(T, &str)]) -> Vec<String>
where
    T: Copy + Into<u64>,
{
    let v: u64 = value.into();
    let mut known = 0u64;
    let mut out = Vec::new();
    for &(bit, name) in table {
        let b: u64 = bit.into();
        if v & b == b && b != 0 {
            out.push(name.to_string());
            known |= b;
        }
    }
    if v & !known != 0 {
        out.push(format!("{:#x}", v & !known));
    }
    out
}

/// Name of a base relocation type, as the specification spells it.
pub fn base_reloc_name(machine: u16, t: u8) -> Option<&'static str> {
    Some(match t {
        IMAGE_REL_BASED_ABSOLUTE => "IMAGE_REL_BASED_ABSOLUTE",
        IMAGE_REL_BASED_HIGH => "IMAGE_REL_BASED_HIGH",
        IMAGE_REL_BASED_LOW => "IMAGE_REL_BASED_LOW",
        IMAGE_REL_BASED_HIGHLOW => "IMAGE_REL_BASED_HIGHLOW",
        IMAGE_REL_BASED_HIGHADJ => "IMAGE_REL_BASED_HIGHADJ",
        5 => match machine {
            IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_THUMB => {
                "IMAGE_REL_BASED_ARM_MOV32"
            }
            IMAGE_FILE_MACHINE_RISCV32
            | IMAGE_FILE_MACHINE_RISCV64
            | IMAGE_FILE_MACHINE_RISCV128 => "IMAGE_REL_BASED_RISCV_HIGH20",
            _ => "IMAGE_REL_BASED_MIPS_JMPADDR",
        },
        7 => match machine {
            IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_THUMB => {
                "IMAGE_REL_BASED_THUMB_MOV32"
            }
            IMAGE_FILE_MACHINE_RISCV32
            | IMAGE_FILE_MACHINE_RISCV64
            | IMAGE_FILE_MACHINE_RISCV128 => "IMAGE_REL_BASED_RISCV_LOW12I",
            _ => return None,
        },
        8 => match machine {
            IMAGE_FILE_MACHINE_RISCV32
            | IMAGE_FILE_MACHINE_RISCV64
            | IMAGE_FILE_MACHINE_RISCV128 => "IMAGE_REL_BASED_RISCV_LOW12S",
            IMAGE_FILE_MACHINE_LOONGARCH32 | IMAGE_FILE_MACHINE_LOONGARCH64 => {
                "IMAGE_REL_BASED_LOONGARCH_MARK_LA"
            }
            _ => return None,
        },
        9 => "IMAGE_REL_BASED_MIPS_JMPADDR16",
        IMAGE_REL_BASED_DIR64 => "IMAGE_REL_BASED_DIR64",
        _ => return None,
    })
}

/// Number of bytes a base relocation of type `t` patches (0 = no effect or unknown).
pub fn base_reloc_width(t: u8) -> u8 {
    match t {
        IMAGE_REL_BASED_HIGH | IMAGE_REL_BASED_LOW | IMAGE_REL_BASED_HIGHADJ => 2,
        IMAGE_REL_BASED_HIGHLOW => 4,
        IMAGE_REL_BASED_DIR64 => 8,
        // MOV32 pairs patch two 4-byte instructions.
        IMAGE_REL_BASED_ARM_MOV32 | IMAGE_REL_BASED_THUMB_MOV32 => 8,
        _ => 0,
    }
}

/// Name of a debug directory type.
pub fn debug_type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        0 => "Unknown",
        1 => "COFF",
        2 => "CodeView",
        3 => "FPO",
        4 => "Misc",
        5 => "Exception",
        6 => "Fixup",
        7 => "OmapToSrc",
        8 => "OmapFromSrc",
        9 => "Borland",
        10 => "Reserved10",
        11 => "CLSID",
        12 => "VCFeature",
        13 => "POGO",
        14 => "ILTCG",
        15 => "MPX",
        16 => "Repro",
        17 => "EmbeddedPortablePDB",
        18 => "SPGO",
        19 => "PDBChecksum",
        20 => "ExtendedDLLCharacteristics",
        _ => return None,
    })
}

/// Name of a predefined resource type.
pub fn resource_type_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRINGTABLE",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => return None,
    })
}

/// Name of a certificate type.
pub fn certificate_type_name(t: u16) -> Option<&'static str> {
    Some(match t {
        WIN_CERT_TYPE_X509 => "X.509",
        WIN_CERT_TYPE_PKCS_SIGNED_DATA => "PKCS#7 SignedData (Authenticode)",
        3 => "reserved",
        WIN_CERT_TYPE_TS_STACK_SIGNED => "terminal server protocol stack",
        _ => return None,
    })
}
