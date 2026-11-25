// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Foundation types shared by every Fulgurite crate.
//!
//! Nothing here knows about any file format or architecture. The types exist so
//! that every value the tool reports can carry **where it came from** (a [`Span`]
//! of file bytes), and so that every read of untrusted input goes through one
//! bounds-checked choke point ([`ByteView`]).

pub mod addr;
pub mod anomaly;
pub mod arch;
pub mod bytes;
pub mod evidence;
pub mod perms;
pub mod span;

pub use addr::{FileOffset, Va};
pub use anomaly::{Anomaly, Severity};
pub use arch::{ArchId, Bitness};
pub use bytes::{ByteView, Endian, OutOfBounds};
pub use evidence::Evidence;
pub use perms::Perms;
pub use span::{Field, Span};
