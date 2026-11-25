// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the x86 and AArch64 decoders and the disassembly listing: raw bytes
//! in every x86 mode and as A64 words, then the input as a whole file (loaded,
//! then every code section listed). Nothing may panic, whatever the bytes.

#![no_main]

use fg_service::Session;
use fg_service::core::Va;
use fg_service::disasm::{Options, Target};
use fg_service::ir::{Mode, Syntax};
use libfuzzer_sys::fuzz_target;
use std::ops::ControlFlow;

fuzz_target!(|data: &[u8]| {
    let x86 = fg_service::disasm::arch_for(fg_service::core::ArchId::X86_64).unwrap();
    for mode in [Mode::X86_16, Mode::X86_32, Mode::X86_64] {
        let mut at = 0;
        while at < data.len().min(4096) {
            match x86.decode(&data[at..], Va(at as u64), mode) {
                Ok(insn) => {
                    let _ = x86.format(&insn, Syntax::Intel);
                    let _ = x86.format(&insn, Syntax::Att);
                    at += insn.len() as usize;
                }
                Err(_) => at += 1,
            }
        }
    }
    let a64 = fg_service::disasm::arch_for(fg_service::core::ArchId::Aarch64).unwrap();
    for (i, word) in data.chunks(4).take(4096).enumerate() {
        let va = Va((i as u64) * 4);
        if let Ok(insn) = a64.decode(word, va, Mode::Native) {
            let _ = a64.format(&insn, Syntax::Intel);
        }
    }
    if let Ok(session) = Session::from_bytes("fuzz", data.to_vec().into(), &Default::default()) {
        let mut budget = 100_000u32;
        let _ = session.disassemble_each(&Target::CodeSections, Options::default(), &mut |_| {
            budget -= 1;
            if budget == 0 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
    }
});
