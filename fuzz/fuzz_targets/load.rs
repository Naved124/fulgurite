#![no_main]
//! Any byte string must load or fail cleanly: no panics, no hangs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fg_loader::load(data, &fg_loader::LoadOptions::default());
});
