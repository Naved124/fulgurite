// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Section headers and the image map: how the Windows loader places file bytes
//! in memory, which every RVA lookup goes through.

use super::consts::*;
use fg_core::{ByteView, Field, OutOfBounds, Perms, Span};
use serde::Serialize;

/// One section header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SectionHeader {
    /// Position in the section table (0-based; COFF numbers sections from 1).
    pub index: u32,
    /// The 8 raw name bytes.
    pub raw_name: Field<Vec<u8>>,
    /// Name with long names (`/123`) resolved through the COFF string table.
    pub name: String,
    /// Size in memory.
    pub virtual_size: Field<u32>,
    /// Address relative to the image base.
    pub virtual_address: Field<u32>,
    /// Size of the data in the file.
    pub size_of_raw_data: Field<u32>,
    /// File offset of the data.
    pub pointer_to_raw_data: Field<u32>,
    /// COFF relocations (objects only; zero in images).
    pub pointer_to_relocations: Field<u32>,
    /// COFF line numbers (deprecated).
    pub pointer_to_linenumbers: Field<u32>,
    /// Number of COFF relocations.
    pub number_of_relocations: Field<u16>,
    /// Number of line numbers.
    pub number_of_linenumbers: Field<u16>,
    /// `IMAGE_SCN_*` flags.
    pub characteristics: Field<u32>,
    /// The header's 40 bytes.
    pub span: Span,
}

impl SectionHeader {
    /// True if `flag` (`IMAGE_SCN_*`) is set.
    pub fn has(&self, flag: u32) -> bool {
        self.characteristics.value & flag != 0
    }

    /// Memory permissions the section asks for.
    pub fn perms(&self) -> Perms {
        Perms::new(
            self.has(IMAGE_SCN_MEM_READ),
            self.has(IMAGE_SCN_MEM_WRITE),
            self.has(IMAGE_SCN_MEM_EXECUTE),
        )
    }

    /// Size the loader reserves in memory: `VirtualSize`, or `SizeOfRawData`
    /// when `VirtualSize` is zero.
    pub fn mem_size(&self) -> u64 {
        match self.virtual_size.value {
            0 => u64::from(self.size_of_raw_data.value),
            v => u64::from(v),
        }
    }

    pub(crate) fn parse(
        v: &ByteView<'_>,
        at: u64,
        index: u32,
    ) -> Result<SectionHeader, OutOfBounds> {
        let raw = v.bytes(at, 8)?.to_vec();
        let name =
            String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
        Ok(SectionHeader {
            index,
            raw_name: Field::new(raw, Span::new(at, 8)),
            name,
            virtual_size: v.field_u32(at + 8)?,
            virtual_address: v.field_u32(at + 12)?,
            size_of_raw_data: v.field_u32(at + 16)?,
            pointer_to_raw_data: v.field_u32(at + 20)?,
            pointer_to_relocations: v.field_u32(at + 24)?,
            pointer_to_linenumbers: v.field_u32(at + 28)?,
            number_of_relocations: v.field_u16(at + 32)?,
            number_of_linenumbers: v.field_u16(at + 34)?,
            characteristics: v.field_u32(at + 36)?,
            span: Span::new(at, SECTION_HEADER_SIZE),
        })
    }
}

/// One region of the image as the Windows loader maps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MappedRegion {
    /// Section index, or `None` for the headers.
    pub section: Option<u32>,
    /// Start, relative to the image base.
    pub rva: u64,
    /// Size in memory.
    pub mem_size: u64,
    /// File offset the bytes come from (after the loader's rounding).
    pub file_offset: u64,
    /// Bytes taken from the file; the rest of `mem_size` is zero-filled.
    pub file_size: u64,
}

/// Why an RVA could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RvaError {
    /// No section (or the headers) covers the address.
    Unmapped,
    /// Mapped, but in the zero-filled part of a section: the value is zero in
    /// memory and has no file bytes.
    ZeroFill,
}

/// The image layout: answers "which file bytes hold this RVA?" the way the
/// Windows loader would.
#[derive(Clone, Debug)]
pub(crate) struct Image<'a> {
    pub view: ByteView<'a>,
    pub image_base: u64,
    pub regions: Vec<MappedRegion>,
}

/// The loader's minimum alignment for section file offsets (corkami, "PE":
/// raw pointers below 0x200 round down to 0; sector-sized granularity).
pub(crate) const RAW_POINTER_GRANULARITY: u64 = 0x200;

/// Below this section alignment the image is in "low alignment" mode: Windows
/// maps the file as is, with RVA equal to file offset.
pub(crate) const PAGE_SIZE: u64 = 0x1000;

impl<'a> Image<'a> {
    /// Builds the map from the section table. `size_of_headers` bytes at RVA 0
    /// come first, then each section in table order.
    pub fn new(
        view: ByteView<'a>,
        image_base: u64,
        size_of_headers: u64,
        section_alignment: u64,
        sections: &[SectionHeader],
    ) -> Image<'a> {
        let file_len = view.len();
        let low_alignment = section_alignment < PAGE_SIZE;
        let mut regions = vec![MappedRegion {
            section: None,
            rva: 0,
            mem_size: size_of_headers,
            file_offset: 0,
            file_size: size_of_headers.min(file_len),
        }];
        for s in sections {
            let raw_ptr = u64::from(s.pointer_to_raw_data.value);
            let file_offset = if low_alignment {
                raw_ptr
            } else {
                raw_ptr & !(RAW_POINTER_GRANULARITY - 1)
            };
            let mem_size = s.mem_size();
            let wanted = u64::from(s.size_of_raw_data.value).min(mem_size);
            let file_size = if raw_ptr == 0 {
                0
            } else {
                wanted.min(file_len.saturating_sub(file_offset))
            };
            regions.push(MappedRegion {
                section: Some(s.index),
                rva: u64::from(s.virtual_address.value),
                mem_size,
                file_offset,
                file_size,
            });
        }
        Image {
            view,
            image_base,
            regions,
        }
    }

    /// The region that covers `rva` (sections take precedence over the headers).
    pub fn region(&self, rva: u64) -> Option<&MappedRegion> {
        let inside = |r: &&MappedRegion| rva >= r.rva && rva - r.rva < r.mem_size;
        self.regions[1..]
            .iter()
            .find(inside)
            .or_else(|| self.regions[..1].iter().find(inside))
    }

    /// File offset of `len` bytes at `rva`, if they all come from the file.
    pub fn offset(&self, rva: u64, len: u64) -> Result<u64, RvaError> {
        let r = self.region(rva).ok_or(RvaError::Unmapped)?;
        let delta = rva - r.rva;
        match delta.checked_add(len) {
            Some(end) if end <= r.file_size => Ok(r.file_offset + delta),
            _ => Err(RvaError::ZeroFill),
        }
    }

    /// True if `rva` is inside the mapped image.
    pub fn is_mapped(&self, rva: u64) -> bool {
        self.region(rva).is_some()
    }

    /// Converts a VA to an RVA (`None` below the image base).
    pub fn rva_of(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base)
    }

    /// Reads an integer of `size` bytes at `rva`.
    pub fn uint(&self, rva: u64, size: u8) -> Result<Field<u64>, RvaError> {
        let off = self.offset(rva, u64::from(size))?;
        self.view
            .field_uint(off, size)
            .map_err(|_| RvaError::ZeroFill)
    }

    /// Reads a 16-bit integer at `rva`.
    pub fn u16(&self, rva: u64) -> Result<Field<u16>, RvaError> {
        Ok(self.uint(rva, 2)?.map(|v| v as u16))
    }

    /// Reads a 32-bit integer at `rva`.
    pub fn u32(&self, rva: u64) -> Result<Field<u32>, RvaError> {
        Ok(self.uint(rva, 4)?.map(|v| v as u32))
    }

    /// Reads a NUL-terminated string at `rva` (at most `max` bytes, within one region).
    pub fn cstr(&self, rva: u64, max: u64) -> Result<Option<Field<String>>, RvaError> {
        let r = self.region(rva).ok_or(RvaError::Unmapped)?;
        let delta = rva - r.rva;
        if delta >= r.file_size {
            return Err(RvaError::ZeroFill);
        }
        let off = r.file_offset + delta;
        let window = max.min(r.file_size - delta);
        Ok(self
            .view
            .cstr(off, window)
            .ok()
            .flatten()
            .map(|f| f.map(|b| String::from_utf8_lossy(b).into_owned())))
    }
}
