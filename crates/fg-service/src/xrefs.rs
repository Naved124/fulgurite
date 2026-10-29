//! Cross-references for a session: who refers to an address, and how.

use crate::Session;
use crate::functions::FunctionsError;
use fg_analysis::xrefs::{self, Xref, XrefKind};
use fg_core::Va;
use fg_ir::Mode;
use serde::Serialize;

/// Which references to list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XrefTarget {
    /// Every reference in the file.
    All,
    /// The references to one address.
    Address(Va),
    /// The references to what a label or symbol names: to a function's
    /// entry; anywhere inside a data symbol with a size (an array's
    /// elements, a structure's fields).
    Name(String),
}

/// One reference, named.
#[derive(Clone, Debug, Serialize)]
pub struct XrefLine {
    /// The referring instruction or data word.
    pub from: Va,
    /// Its name (`main+0x1c`), if known.
    pub from_name: Option<String>,
    /// The function the referring instruction is in; `None` for a data word.
    pub function: Option<Va>,
    /// The address referred to.
    pub to: Va,
    /// Its name, if known.
    pub to_name: Option<String>,
    /// What the reference does.
    pub kind: XrefKind,
    /// How the target was found.
    pub via: String,
    /// False for a guess.
    pub certain: bool,
}

/// The references asked for.
#[derive(Clone, Debug, Serialize)]
pub struct XrefList {
    /// The address asked about (`None` for every reference).
    pub target: Option<Va>,
    /// The size of the named symbol asked about, if it has one: references
    /// anywhere inside it are listed.
    pub size: Option<u64>,
    /// The references, by target then source.
    pub refs: Vec<XrefLine>,
}

/// Why references could not be listed.
#[derive(Debug)]
pub enum XrefsError {
    /// Recovering the functions failed.
    Functions(FunctionsError),
    /// No label or defined symbol has this name.
    UnknownName(String),
}

impl std::fmt::Display for XrefsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefsError::Functions(e) => e.fmt(f),
            XrefsError::UnknownName(n) => write!(f, "no label or symbol is named {n:?}"),
        }
    }
}

impl std::error::Error for XrefsError {}

pub(crate) fn list(session: &Session, target: &XrefTarget) -> Result<XrefList, XrefsError> {
    let arch = session
        .arch()
        .ok_or(XrefsError::Functions(FunctionsError::NoDecoder))?;
    let namer = crate::disasm::Namer::new(session, arch);
    let (target, size) = match target {
        XrefTarget::All => (None, None),
        XrefTarget::Address(va) => (Some(*va), None),
        XrefTarget::Name(n) => {
            let va = namer
                .find(session.binary(), n)
                .ok_or_else(|| XrefsError::UnknownName(n.clone()))?;
            let size = session
                .binary()
                .symbols
                .iter()
                // A function's own branches land inside it: only references
                // to its entry are references to the function.
                .filter(|s| s.defined && s.va == va && s.size > 0)
                .filter(|s| {
                    !matches!(
                        s.kind,
                        fg_loader::SymbolKind::Function | fg_loader::SymbolKind::IndirectFunction
                    )
                })
                .filter(|s| s.name == *n || s.base_name() == n || s.display_name() == *n)
                .map(|s| s.size)
                .max();
            (Some(va), size)
        }
    };
    let (_, g) = crate::functions::analyse(session).map_err(XrefsError::Functions)?;
    let all = xrefs::collect(session.binary(), session.bytes(), arch, Mode::Native, &g);
    let chosen: &[Xref] = match (target, size) {
        (Some(va), Some(n)) => all.to_range(va, Va(va.0.saturating_add(n))),
        (Some(va), None) => all.to(va),
        (None, _) => all.all(),
    };
    let refs = chosen
        .iter()
        .map(|r| XrefLine {
            from: r.from,
            from_name: namer.name(r.from.0),
            function: r.function,
            to: r.to,
            to_name: namer.name(r.to.0),
            kind: r.kind,
            via: r.via.describe(),
            certain: r.certain,
        })
        .collect();
    Ok(XrefList { target, size, refs })
}
