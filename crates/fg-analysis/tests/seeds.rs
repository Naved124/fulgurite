//! The seed pass on a real binary: this test program itself (an ELF with
//! symbols and `.eh_frame` when built on Linux).

use fg_analysis::seeds::{PASS, add_seed_facts, seed_facts};
use fg_facts::{Bucket, Claim, FactStore, Slot, Status, Verdict};
use fg_loader::{LoadOptions, SeedKind, SymbolKind};

fn me() -> Option<fg_loader::LoadedBinary> {
    let bytes = std::fs::read(std::env::current_exe().ok()?).ok()?;
    let bin = fg_loader::load(&bytes, &LoadOptions::default()).ok()?;
    (bin.format == fg_loader::Format::Elf).then_some(bin)
}

#[test]
fn every_declared_function_becomes_an_accepted_fact_with_evidence() {
    let Some(bin) = me() else {
        eprintln!("note: not an ELF test binary; skipped");
        return;
    };
    let facts = seed_facts(&bin).unwrap();
    let mut store = FactStore::new();
    assert_eq!(add_seed_facts(&bin, &mut store), Ok(facts.len()));
    // Running the pass again changes nothing.
    assert_eq!(add_seed_facts(&bin, &mut store), Ok(0));

    for f in &facts {
        assert_eq!(f.status(), Status::Declared);
        assert_eq!(f.provenance().pass, PASS);
        assert!(
            f.evidence().iter().all(|e| e.evidence.span.is_some()),
            "{f:?}"
        );
    }

    let entry = bin.entry.as_ref().unwrap().value;
    let r = store.resolve(&Slot::IsFunction { entry });
    let Verdict::Accepted(id) = r.verdict else {
        panic!("entry: {r:?}")
    };
    assert_eq!(
        store.get(id).unwrap().confidence().bucket(),
        Bucket::Certain
    );

    // Every defined function symbol is a function, named.
    let funcs: Vec<_> = bin
        .symbols
        .iter()
        .filter(|s| s.defined && s.kind == SymbolKind::Function && s.va.0 != 0)
        .collect();
    assert!(funcs.len() > 100);
    for s in &funcs {
        assert!(matches!(
            store.resolve(&Slot::IsFunction { entry: s.va }).verdict,
            Verdict::Accepted(_)
        ));
        let named = store.resolve(&Slot::Name { entity: s.va });
        let Verdict::Accepted(n) = named.verdict else {
            panic!("{}: {named:?}", s.name)
        };
        let Claim::Name { name, .. } = store.get(n).unwrap().claim() else {
            unreachable!()
        };
        // Aliases: the chosen name is one of the symbols at that address.
        assert!(
            bin.symbols
                .iter()
                .any(|t| t.va == s.va && t.display_name() == *name)
        );
    }

    // FDEs are code, never functions by themselves.
    let fdes: Vec<_> = bin
        .seeds
        .iter()
        .filter(|s| s.kind == SeedKind::UnwindTable)
        .collect();
    assert!(!fdes.is_empty());
    for s in fdes {
        let code = Slot::IsCode {
            start: s.va,
            end: s.end.unwrap(),
        };
        assert!(matches!(store.resolve(&code).verdict, Verdict::Accepted(_)));
        let only_fde = store
            .facts_in(&Slot::IsFunction { entry: s.va })
            .next()
            .is_none();
        let has_symbol = funcs.iter().any(|f| f.va == s.va);
        assert!(
            only_fde
                || has_symbol
                || bin
                    .seeds
                    .iter()
                    .any(|t| t.va == s.va && t.kind != SeedKind::UnwindTable)
        );
    }
}
