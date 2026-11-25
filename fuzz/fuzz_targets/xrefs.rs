// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes cross-references: the input is loaded as a file, its functions
//! recovered, then every reference listed and named. Nothing may panic,
//! whatever the bytes.

#![no_main]

use fg_service::Session;
use fg_service::xrefs::XrefTarget;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(session) = Session::from_bytes("fuzz", data.to_vec().into(), &Default::default()) {
        let _ = session.xrefs(&XrefTarget::All);
    }
});
