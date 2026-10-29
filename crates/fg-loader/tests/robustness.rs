//! Mutation testing on real binaries: thousands of corrupted variants of a real
//! ELF file must all load or fail cleanly, never panic.
//!
//! This is a deterministic, stable-toolchain stand-in for coverage-guided fuzzing
//! (the `fuzz/` target runs the same entry point under libFuzzer).

use fg_loader::{LoadOptions, load};

mod common;

/// Small deterministic PRNG (xorshift64*), so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn seed_file() -> Option<Vec<u8>> {
    ["/bin/cat", "/bin/ls", "/bin/sh"]
        .iter()
        .find_map(|p| std::fs::read(p).ok())
}

#[test]
fn mutated_real_binaries_never_panic() {
    let Some(original) = seed_file() else {
        eprintln!("note: no seed binary found, skipped");
        return;
    };
    // Headers, program headers, notes and the dynamic tables live at the start;
    // section headers, symbol and string tables usually sit near the end.
    mutate(&original, 0x0f17_9a17_e5ee_d001, 4096, 5000);
}

/// libc has packed RELR relocations, dozens of notes and over a thousand
/// relocations: mutate its first 256 KiB, where all of those live.
#[test]
fn mutated_libc_never_panics() {
    let Some(original) = ["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"]
        .iter()
        .find_map(|p| std::fs::read(p).ok())
    else {
        eprintln!("note: libc not found, skipped");
        return;
    };
    mutate(&original, 0x11bc_5eed_0000_0003, 256 * 1024, 600);
}

fn mutate(original: &[u8], seed: u64, head: u64, iterations: u32) {
    let mut rng = Rng(seed);
    let len = original.len() as u64;
    let head = len.min(head);
    let tail_start = len.saturating_sub(8192);
    let interesting: [u64; 8] = [0, 1, 0x7f, 0x80, 0xff, 0xffff, 0xffff_ffff, u64::MAX];
    for i in 0..iterations {
        let mut bytes = original.to_vec();
        for _ in 0..1 + rng.below(8) {
            let at = match rng.below(3) {
                0 => rng.below(head),
                1 => tail_start + rng.below(len - tail_start),
                _ => rng.below(len),
            } as usize;
            match rng.below(3) {
                0 => bytes[at] = rng.next() as u8,
                1 => {
                    let v = interesting[rng.below(8) as usize].to_le_bytes();
                    let n = (1 << rng.below(4)) as usize; // 1, 2, 4 or 8 bytes
                    let end = (at + n).min(bytes.len());
                    bytes[at..end].copy_from_slice(&v[..end - at]);
                }
                _ => bytes[at] ^= 1 << rng.below(8),
            }
        }
        if rng.below(10) == 0 {
            bytes.truncate(rng.below(bytes.len() as u64) as usize);
        }
        let result = std::panic::catch_unwind(|| load(&bytes, &LoadOptions::default()));
        assert!(result.is_ok(), "panic on mutation #{i} (seed {seed:#x})");
    }
}

/// A synthetic PE with every data directory populated: every table parser sees
/// corrupted input.
#[test]
fn mutated_pe_kitchen_sink_never_panics() {
    let original = common::pe::kitchen_sink();
    let b = load(&original, &LoadOptions::default()).expect("the seed loads");
    let pe = b.pe().unwrap();
    assert!(!pe.imports.is_empty() && !pe.delay_imports.is_empty() && pe.exports.is_some());
    assert!(pe.tls.is_some() && pe.load_config.is_some() && !pe.exception.is_empty());
    assert!(!pe.debug.is_empty() && !pe.resources.is_empty() && !pe.certificates.is_empty());
    assert!(!b.relocations.is_empty());
    let len = original.len() as u64;
    mutate(&original, 0x9e5e_ed00_0000_0004, len, 10_000);
}

/// Real PE files, when the system has some (UEFI boot loaders, MinGW DLLs).
#[test]
fn mutated_real_pe_never_panics() {
    let candidates = [
        "/usr/share/limine/BOOTX64.EFI",
        "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
        "/usr/lib/vmware/resources/storePwd.exe",
    ];
    let mut any = false;
    for (i, p) in candidates.iter().enumerate() {
        let Ok(original) = std::fs::read(p) else {
            continue;
        };
        any = true;
        mutate(&original, 0x5eed_0000_0000_0100 + i as u64, 4096, 2000);
    }
    if !any {
        eprintln!("note: no PE files on this system, skipped");
    }
}
