// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Resource directory: a tree (normally type / name / language) whose leaves
//! point at icons, dialogs, version information, manifests or arbitrary data.

use super::consts::resource_type_name;
use super::section::Image;
use fg_core::{Anomaly, Field, Severity, Span};
use serde::Serialize;
use std::collections::HashSet;

/// A resource name or numeric id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ResourceName {
    /// Numeric id.
    Id(u32),
    /// UTF-16 name.
    Name(String),
}

impl std::fmt::Display for ResourceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceName::Id(i) => write!(f, "{i}"),
            ResourceName::Name(s) => write!(f, "{s:?}"),
        }
    }
}

/// One resource: the path through the tree and the data it points at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Resource {
    /// Names from the root, normally `[type, name, language]`.
    pub path: Vec<ResourceName>,
    /// RVA of the data.
    pub data_rva: Field<u32>,
    /// Size of the data.
    pub size: Field<u32>,
    /// Code page of the data.
    pub code_page: Field<u32>,
    /// File bytes of the data, if they are in the file.
    pub data: Option<Span>,
    /// The data entry's 16 bytes.
    pub span: Span,
}

impl Resource {
    /// The resource type: a predefined name (`ICON`, `VERSION`, `MANIFEST`...) or the custom name.
    pub fn type_name(&self) -> String {
        match self.path.first() {
            Some(ResourceName::Id(i)) => {
                resource_type_name(*i).map_or_else(|| i.to_string(), str::to_string)
            }
            Some(n) => n.to_string(),
            None => String::new(),
        }
    }
}

pub(crate) struct Walker<'i, 'a> {
    pub image: &'i Image<'a>,
    pub root: u64,
    pub max_depth: u32,
    pub max_resources: u32,
    pub out: Vec<Resource>,
    pub visited: HashSet<u64>,
    pub limit_hit: bool,
    pub loop_hit: bool,
}

impl Walker<'_, '_> {
    pub fn walk(&mut self, dir: u64, path: &mut Vec<ResourceName>, anomalies: &mut Vec<Anomaly>) {
        if path.len() as u32 >= self.max_depth {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.resource.depth",
                format!(
                    "resource tree deeper than {} levels; the rest is ignored",
                    self.max_depth
                ),
            ));
            return;
        }
        if !self.visited.insert(dir) {
            if std::mem::replace(&mut self.loop_hit, true) {
                return;
            }
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.resource.loop",
                format!(
                    "resource directory at RVA {:#x} is reached twice (a loop or shared subtree)",
                    self.root + dir
                ),
            ));
            return;
        }
        let base = self.root + dir;
        let (Ok(named), Ok(ids)) = (self.image.u16(base + 12), self.image.u16(base + 14)) else {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.resource.truncated",
                format!("resource directory at RVA {base:#x} cannot be read"),
            ));
            return;
        };
        let n = u64::from(named.value) + u64::from(ids.value);
        for i in 0..n {
            if self.out.len() as u32 >= self.max_resources {
                if !self.limit_hit {
                    self.limit_hit = true;
                    anomalies.push(Anomaly::new(
                        Severity::Warning,
                        "pe.resource.limit",
                        format!(
                            "more than {} resources; the rest are ignored",
                            self.max_resources
                        ),
                    ));
                }
                return;
            }
            let e = base + 16 + i * 8;
            let (Ok(name), Ok(target)) = (self.image.u32(e), self.image.u32(e + 4)) else {
                anomalies.push(Anomaly::new(
                    Severity::Warning,
                    "pe.resource.truncated",
                    format!("resource directory entry at RVA {e:#x} cannot be read"),
                ));
                return;
            };
            let label = if name.value & 0x8000_0000 != 0 {
                ResourceName::Name(self.read_name(u64::from(name.value & 0x7fff_ffff)))
            } else {
                ResourceName::Id(name.value)
            };
            path.push(label);
            let t = u64::from(target.value & 0x7fff_ffff);
            if target.value & 0x8000_0000 != 0 {
                self.walk(t, path, anomalies);
            } else {
                self.leaf(t, path, anomalies);
            }
            path.pop();
        }
    }

    fn read_name(&self, off: u64) -> String {
        let at = self.root + off;
        let Ok(len) = self.image.u16(at) else {
            return String::new();
        };
        let n = u64::from(len.value).min(1024);
        let units: Vec<u16> = (0..n)
            .map_while(|k| self.image.u16(at + 2 + k * 2).ok().map(|f| f.value))
            .collect();
        String::from_utf16_lossy(&units)
    }

    fn leaf(&mut self, off: u64, path: &[ResourceName], anomalies: &mut Vec<Anomaly>) {
        let at = self.root + off;
        let (Ok(data_rva), Ok(size), Ok(code_page)) = (
            self.image.u32(at),
            self.image.u32(at + 4),
            self.image.u32(at + 8),
        ) else {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.resource.truncated",
                format!("resource data entry at RVA {at:#x} cannot be read"),
            ));
            return;
        };
        let data = self
            .image
            .offset(u64::from(data_rva.value), u64::from(size.value))
            .ok()
            .map(|o| Span::new(o, u64::from(size.value)));
        if data.is_none() && size.value != 0 {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.resource.data_outside",
                    format!(
                        "resource data at RVA {:#x} (+{:#x}) is not in the file",
                        data_rva.value, size.value
                    ),
                )
                .at(data_rva.span),
            );
        }
        let span = Span::new(data_rva.span.offset.0, 16);
        self.out.push(Resource {
            path: path.to_vec(),
            data_rva,
            size,
            code_page,
            data,
            span,
        });
    }
}
