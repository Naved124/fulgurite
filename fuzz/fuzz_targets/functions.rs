// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes function recovery: the input is loaded as a file, then seeds,
//! `.eh_frame`, CFG recovery, no-return analysis, jump tables and register
//! values run over it. Nothing may panic, whatever the bytes.

#![no_main]

use fg_service::Session;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(session) = Session::from_bytes("fuzz", data.to_vec().into(), &Default::default()) {
        let _ = session.functions();
    }
});
