//! Malformed and hostile inputs: the loader must report anomalies, never panic.

mod common;
use common::*;
use fg_loader::{Limits, LoadError, LoadOptions, load};

fn opts() -> LoadOptions {
    LoadOptions::default()
}

fn malformed_codes(err: LoadError) -> Vec<&'static str> {
    match err {
        LoadError::Malformed { anomalies, .. } => anomalies.iter().map(|a| a.code).collect(),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn unknown_magic_is_not_recognised() {
    let err = load(b"\xca\xfe\xba\xbe neither ELF nor PE", &opts()).unwrap_err();
    assert!(matches!(err, LoadError::NotRecognized { .. }));
    assert!(err.to_string().contains("ca fe ba be"));
}

#[test]
fn short_mz_is_a_malformed_pe() {
    // `MZ` is the PE magic: a file this short is a damaged PE, not an unknown format.
    let err = load(b"MZ\x90\x00 too short for a DOS header", &opts()).unwrap_err();
    assert_eq!(malformed_codes(err), ["pe.dos.truncated"]);
}

#[test]
fn file_ending_inside_ident() {
    assert!(matches!(
        load(b"\x7fELF\x02\x01", &opts()),
        Err(LoadError::Malformed { .. })
    ));
}

#[test]
fn invalid_class_and_data() {
    let mut b = minimal_exec().build();
    b[4] = 3;
    assert_eq!(
        malformed_codes(load(&b, &opts()).unwrap_err()),
        ["elf.ident.class"]
    );
    let mut b = minimal_exec().build();
    b[5] = 9;
    assert_eq!(
        malformed_codes(load(&b, &opts()).unwrap_err()),
        ["elf.ident.data"]
    );
}

#[test]
fn header_truncated() {
    let b = minimal_exec().build();
    assert_eq!(
        malformed_codes(load(&b[..40], &opts()).unwrap_err()),
        ["elf.header.truncated"]
    );
}

#[test]
fn lying_phnum_reads_what_fits() {
    let mut e = minimal_exec();
    e.phnum_override = Some(50);
    e.min_len = 0; // file ends right after the two real entries
    let bytes = e.build();
    let bytes = &bytes[..(e.phoff() + 2 * 56) as usize];
    let bin = load(bytes, &opts()).unwrap();
    assert_eq!(bin.elf().unwrap().program_headers.len(), 2);
    assert!(codes(&bin).contains(&"elf.phdr.table_truncated"));
}

#[test]
fn phentsize_too_small_skips_table() {
    let mut e = minimal_exec();
    e.phentsize_override = Some(20);
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(bin.elf().unwrap().program_headers.is_empty());
    assert!(codes(&bin).contains(&"elf.phdr.entsize_too_small"));
}

#[test]
fn larger_phentsize_uses_declared_stride() {
    let mut e = minimal_exec();
    e.phentsize_override = Some(64);
    let bin = load(&e.build(), &opts()).unwrap();
    let phdrs = &bin.elf().unwrap().program_headers;
    assert_eq!(phdrs.len(), 2);
    assert_eq!(
        phdrs[1].p_type.value, PT_GNU_STACK,
        "second entry read at offset +64"
    );
    assert!(codes(&bin).contains(&"elf.phdr.entsize"));
}

#[test]
fn phoff_overflow_is_caught() {
    let mut e = minimal_exec();
    e.phoff = Some(u64::MAX - 10);
    // Builder can't place entries there; write the header field by hand instead.
    e.phdrs.clear();
    e.phnum_override = Some(2);
    let mut b = e.build();
    b[32..40].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
    let bin = load(&b, &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.phdr.table_overflow"));
}

#[test]
fn extended_phnum_respects_limit_and_end_of_file() {
    let mut e = minimal_exec();
    e.phnum_override = Some(0xffff);
    e.shoff = 0x300;
    // Section header 0 with sh_info (offset 44) = 1,000,000.
    let mut sh0 = vec![0u8; 64];
    sh0[44..48].copy_from_slice(&1_000_000u32.to_le_bytes());
    e.blobs.push((0x300, sh0));
    let limits = Limits::default().with_max_program_headers(1000);
    let bin = load(&e.build(), &LoadOptions::default().with_limits(limits)).unwrap();
    let c = codes(&bin);
    assert!(c.contains(&"elf.phdr.extended_count"));
    assert!(c.contains(&"elf.phdr.limit"));
    assert!(c.contains(&"elf.phdr.table_truncated"));
    assert_eq!(bin.elf().unwrap().phnum, 1_000_000);
}

#[test]
fn extended_phnum_with_missing_section_header() {
    let mut e = minimal_exec();
    e.phnum_override = Some(0xffff);
    e.shoff = 0xdead_0000;
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.phdr.extended_count_unreadable"));
}

#[test]
fn segment_problems_are_reported() {
    let mut e = minimal_exec();
    e.phdrs = vec![
        Phdr::new(PT_LOAD, PF_R | PF_X)
            .file(0, 0x200)
            .mem(0x500000, 0x200)
            .align(0x1000),
        // Lower address than the previous LOAD, overlapping it is impossible here; next one overlaps.
        Phdr::new(PT_LOAD, PF_R)
            .file(0, 0x100)
            .mem(0x400000, 0x100)
            .align(0x1000),
        Phdr::new(PT_LOAD, PF_R | PF_W | PF_X)
            .file(0, 0x100)
            .mem(0x500080, 0x100)
            .align(0x1000),
        Phdr::new(PT_LOAD, PF_R)
            .file(0x100, 0x400)
            .mem(0x600100, 0x10)
            .align(0x1000),
        Phdr::new(PT_LOAD, PF_R)
            .file(0, 0x10_0000)
            .mem(0x700000, 0x10_0000)
            .align(3),
    ];
    e.entry = 0x500100;
    let bin = load(&e.build(), &opts()).unwrap();
    let c = codes(&bin);
    for code in [
        "elf.segment.unsorted",
        "elf.segment.overlap",
        "elf.segment.wx",
        "elf.segment.filesz_gt_memsz",
        "elf.segment.past_eof",
        "elf.segment.align",
    ] {
        assert!(c.contains(&code), "missing {code} in {c:?}");
    }
    assert!(
        bin.mitigations
            .nx
            .evidence
            .iter()
            .any(|e| e.text.contains("writable and executable"))
    );
}

#[test]
fn entry_outside_executable_code() {
    let mut e = minimal_exec();
    e.entry = 0x900000;
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.entry.not_executable"));
}

#[test]
fn interpreter_problems() {
    let mut e = minimal_exec();
    e.phdrs.push(Phdr::new(PT_INTERP, PF_R).file(0x180, 8));
    e.blobs.push((0x180, b"/lib/ldX".to_vec())); // no NUL within 8 bytes
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.interp.unterminated"));
    assert!(bin.elf().unwrap().interpreter.is_none());

    let mut e = minimal_exec();
    e.phdrs
        .push(Phdr::new(PT_INTERP, PF_R).file(0xffff_ffff, 8));
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.interp.out_of_bounds"));
}

#[test]
fn dynamic_section_problems() {
    let mut e = minimal_exec();
    let dynbytes = e.dynamic(&[(1, 0x10)], false);
    e.phdrs
        .push(Phdr::new(PT_DYNAMIC, PF_R | PF_W).file(0x180, dynbytes.len() as u64));
    e.blobs.push((0x180, dynbytes));
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.dynamic.unterminated"));

    let mut e = minimal_exec();
    e.phdrs
        .push(Phdr::new(PT_DYNAMIC, PF_R | PF_W).file(0x1f8, 0x40));
    let bin = load(&e.build(), &opts()).unwrap();
    assert!(codes(&bin).contains(&"elf.dynamic.truncated"));
}

/// Found by fuzzing (2026-10-10): a dynamic segment whose file offset is within
/// one word of 2^64. The tag's offset fits, the value's (offset + 8) does not;
/// unchecked, it wrapped to the start of the file in release builds.
#[test]
fn dynamic_segment_at_the_top_of_the_offset_range() {
    for offset in [u64::MAX - 7, u64::MAX - 15, u64::MAX] {
        let mut e = minimal_exec();
        e.phdrs
            .push(Phdr::new(PT_DYNAMIC, PF_R | PF_W).file(offset, 0x20));
        let bin = load(&e.build(), &opts()).unwrap();
        assert!(
            codes(&bin).contains(&"elf.dynamic.truncated"),
            "{offset:#x}"
        );
        assert!(bin.elf().unwrap().dynamic.is_empty());
    }
}

#[test]
fn every_truncation_of_a_valid_file_is_safe() {
    let mut e = minimal_exec();
    e.phdrs.push(Phdr::new(PT_INTERP, PF_R).file(0x180, 16));
    e.blobs.push((0x180, b"/lib/ld.so.1\0\0\0\0".to_vec()));
    let full = e.build();
    for len in 0..=full.len() {
        let _ = load(&full[..len], &opts());
    }
}
