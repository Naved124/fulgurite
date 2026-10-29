//! The service layer.
//!
//! Every front end (the `fulg` CLI today; the GUI, Python bindings and the
//! `fulgurited` daemon later) talks to Fulgurite through this crate only. Lower
//! crates can change shape freely as long as this API stays stable, which is what
//! lets new milestones land without rewriting the front ends.
//!
//! Today a [`Session`] holds one loaded binary. Later milestones add the
//! incremental analysis database behind the same type.

pub mod disasm;
pub mod functions;
pub mod xrefs;

use fg_loader::{LoadError, LoadOptions, LoadedBinary};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Re-exported lower layers, so front ends depend on `fg-service` alone.
pub use fg_core as core;
/// Re-exported instruction model.
pub use fg_ir as ir;
/// Re-exported loader types.
pub use fg_loader as loader;

/// Largest file a session will read into memory (4 GiB).
pub const MAX_FILE_SIZE: u64 = 4 << 30;

/// An open analysis session for one binary.
#[derive(Debug)]
pub struct Session {
    path: PathBuf,
    bytes: Arc<[u8]>,
    binary: LoadedBinary,
}

impl Session {
    /// Reads and loads the file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Session, ServiceError> {
        Session::open_with(path, &LoadOptions::default())
    }

    /// Reads and loads the file at `path` with custom loader options.
    pub fn open_with(
        path: impl AsRef<Path>,
        options: &LoadOptions,
    ) -> Result<Session, ServiceError> {
        let path = path.as_ref().to_path_buf();
        let io_err = |source| ServiceError::Io {
            path: path.clone(),
            source,
        };
        let len = std::fs::metadata(&path).map_err(io_err)?.len();
        if len > MAX_FILE_SIZE {
            return Err(ServiceError::TooLarge { path, size: len });
        }
        let bytes: Arc<[u8]> = std::fs::read(&path).map_err(io_err)?.into();
        Session::from_bytes(path, bytes, options)
    }

    /// Loads bytes that are already in memory. `path` is used for display only.
    pub fn from_bytes(
        path: impl Into<PathBuf>,
        bytes: Arc<[u8]>,
        options: &LoadOptions,
    ) -> Result<Session, ServiceError> {
        let path = path.into();
        let binary = fg_loader::load(&bytes, options).map_err(|source| ServiceError::Load {
            path: path.clone(),
            source,
        })?;
        Ok(Session {
            path,
            bytes,
            binary,
        })
    }

    /// Path the session was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The raw file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Everything the loader learned.
    pub fn binary(&self) -> &LoadedBinary {
        &self.binary
    }

    /// The decoder for this binary's architecture, if Fulgurite has one.
    pub fn arch(&self) -> Option<&'static dyn fg_ir::Arch> {
        disasm::arch_for(self.binary.arch)
    }

    /// Every function: declared ones and those CFG recovery finds, with
    /// their confidence and evidence.
    pub fn functions(&self) -> Result<functions::Functions, functions::FunctionsError> {
        functions::recover(self)
    }

    /// The references to `target` (or every reference): which instructions
    /// and data words refer to it, and how.
    pub fn xrefs(&self, target: &xrefs::XrefTarget) -> Result<xrefs::XrefList, xrefs::XrefsError> {
        xrefs::list(self, target)
    }

    /// A disassembly listing of `target`.
    pub fn disassemble(
        &self,
        target: &disasm::Target,
        options: disasm::Options,
    ) -> Result<Vec<disasm::Line>, disasm::DisasmError> {
        disasm::disassemble(self, target, options)
    }

    /// The listing of `target`, one line at a time (see [`disasm::for_each_line`]).
    pub fn disassemble_each(
        &self,
        target: &disasm::Target,
        options: disasm::Options,
        sink: &mut dyn FnMut(disasm::Line) -> std::ops::ControlFlow<()>,
    ) -> Result<(), disasm::DisasmError> {
        disasm::for_each_line(self, target, options, sink)
    }
}

/// Errors returned by the service layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServiceError {
    /// The file could not be read.
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_FILE_SIZE`].
    TooLarge {
        /// File involved.
        path: PathBuf,
        /// Its size in bytes.
        size: u64,
    },
    /// The loader rejected the file.
    Load {
        /// File involved.
        path: PathBuf,
        /// Why.
        source: LoadError,
    },
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            ServiceError::TooLarge { path, size } => {
                write!(
                    f,
                    "{}: file is {size} bytes, larger than the {MAX_FILE_SIZE}-byte limit",
                    path.display()
                )
            }
            ServiceError::Load { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServiceError::Io { source, .. } => Some(source),
            ServiceError::Load { source, .. } => Some(source),
            ServiceError::TooLarge { .. } => None,
        }
    }
}
