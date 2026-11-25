// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! `fulg`: the Fulgurite command-line front end.

mod render;
mod render_disasm;
mod render_pe;

use clap::{Parser, Subcommand, ValueEnum};
use fg_service::{ServiceError, Session};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "fulg",
    version,
    about = "Fulgurite: a disassembler whose guesses are visible, explainable and reversible"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what a binary is: format, type, entry point, segments, mitigations and anomalies.
    Info {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List sections (the file's own metadata), checked against the segments the OS maps.
    Sections {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List symbols from the dynamic and static symbol tables, with versions.
    Symbols {
        /// File to inspect.
        file: PathBuf,
        /// Only symbols needed from shared libraries.
        #[arg(long, conflicts_with = "exports")]
        imports: bool,
        /// Only symbols provided to other files.
        #[arg(long)]
        exports: bool,
        /// Only one table.
        #[arg(long, value_enum)]
        table: Option<TableArg>,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List relocations: the addresses the loader patches, and what goes there.
    Relocs {
        /// File to inspect.
        file: PathBuf,
        /// Only GOT and PLT slots (how imported functions and variables are reached).
        #[arg(long)]
        slots: bool,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List build metadata: ELF notes (build ID, ABI tag, CET/BTI properties); PE debug
    /// directory (PDB, CET marking), Rich header and signatures.
    Notes {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List imports grouped by library, with the slot each one is reached through.
    Imports {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List exports.
    Exports {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List code seeds: entry point, TLS callbacks, init/fini arrays, exception-table
    /// functions, Control Flow Guard targets.
    Seeds {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List functions: declared ones and those found by following control
    /// flow, with how sure Fulgurite is and why.
    Functions {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List cross-references: which instructions and data words refer to an
    /// address (calls, jumps, reads, writes, addresses taken, pointers), and how.
    Xrefs {
        /// File to inspect.
        file: PathBuf,
        /// A label or symbol name (`main`, `puts@plt`), or an address
        /// (`0x404028`). Default: every reference in the file.
        target: Option<String>,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List PE resources (icons, version information, manifests, embedded data).
    Resources {
        /// File to inspect.
        file: PathBuf,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Disassemble code: every executable section, one section, a function, or
    /// instructions from an address.
    Disasm {
        /// File to inspect.
        file: PathBuf,
        /// A function name, `entry`, or an address (`0x401000`). Default: every
        /// executable section.
        what: Option<String>,
        /// Only this section.
        #[arg(long, short = 's', conflicts_with = "what")]
        section: Option<String>,
        /// Number of instructions to show when starting at an address.
        #[arg(long, short = 'n', default_value_t = 32)]
        count: usize,
        /// Stop at this address (exclusive) instead of after `--count` instructions.
        #[arg(long)]
        end: Option<String>,
        /// AT&T syntax instead of Intel.
        #[arg(long)]
        att: bool,
        /// Print machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// Symbol table selector for `fulg symbols --table`.
#[derive(Clone, Copy, ValueEnum)]
enum TableArg {
    /// What the loader uses: ELF `.dynsym`; PE imports, delay imports and exports.
    Dynamic,
    /// The full table, removed by `strip`: ELF `.symtab`; PE COFF symbols.
    Static,
}

/// JSON shape of `fulg sections --json`.
#[derive(Serialize)]
struct SectionsJson<'a> {
    schema: &'static str,
    path: String,
    sections: &'a [fg_service::loader::Section],
}

/// JSON shape of `fulg symbols --json`.
#[derive(Serialize)]
struct SymbolsJson<'a> {
    schema: &'static str,
    path: String,
    symbols: Vec<&'a fg_service::loader::Symbol>,
}

/// JSON shape of `fulg relocs --json`.
#[derive(Serialize)]
struct RelocsJson<'a> {
    schema: &'static str,
    path: String,
    relocations: Vec<&'a fg_service::loader::Relocation>,
}

/// JSON shape of `fulg notes --json`.
#[derive(Serialize)]
struct NotesJson<'a> {
    schema: &'static str,
    path: String,
    notes: &'a [fg_service::loader::elf::ElfNote],
    /// PE only.
    #[serde(skip_serializing_if = "Option::is_none")]
    debug_directory: Option<&'a [fg_service::loader::pe::DebugEntry]>,
    /// PE only.
    #[serde(skip_serializing_if = "Option::is_none")]
    rich_header: Option<&'a fg_service::loader::pe::RichHeader>,
    /// PE only.
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates: Option<&'a [fg_service::loader::pe::Certificate]>,
}

/// JSON shape of `fulg info --json`.
#[derive(Serialize)]
struct InfoJson<'a> {
    schema: &'static str,
    path: String,
    binary: &'a fg_service::loader::LoadedBinary,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { file, json } => info(&file, json),
        Command::Sections { file, json } => sections(&file, json),
        Command::Symbols {
            file,
            imports,
            exports,
            table,
            json,
        } => symbols(
            &file,
            SymbolFilter {
                imports,
                exports,
                table,
            },
            json,
        ),
        Command::Relocs { file, slots, json } => relocs(&file, slots, json),
        Command::Notes { file, json } => notes(&file, json),
        Command::Imports { file, json } => list(&file, json, List::Imports),
        Command::Exports { file, json } => list(&file, json, List::Exports),
        Command::Seeds { file, json } => list(&file, json, List::Seeds),
        Command::Resources { file, json } => list(&file, json, List::Resources),
        Command::Functions { file, json } => functions(&file, json),
        Command::Xrefs { file, target, json } => xrefs(&file, target.as_deref(), json),
        Command::Disasm {
            file,
            what,
            section,
            count,
            end,
            att,
            json,
        } => disasm(&file, what, section, count, end, att, json),
    }
}

fn parse_addr(s: &str) -> Option<u64> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(&hex.replace('_', ""), 16).ok()
}

fn disasm(
    file: &PathBuf,
    what: Option<String>,
    section: Option<String>,
    count: usize,
    end: Option<String>,
    att: bool,
    json: bool,
) -> ExitCode {
    use fg_service::core::Va;
    use fg_service::disasm::{Options, Target};
    use fg_service::ir::Syntax;
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let end = match end.as_deref().map(|e| (e, parse_addr(e))) {
        Some((e, None)) => {
            eprintln!("fulg: --end {e:?} is not a hexadecimal address (0x...)");
            return ExitCode::from(1);
        }
        Some((_, Some(a))) => Some(Va(a)),
        None => None,
    };
    let start = |va: Va| match end {
        Some(end) => Target::Range { start: va, end },
        None => Target::At { va, count },
    };
    let target = match (what.as_deref(), section) {
        (_, Some(s)) => Target::Section(s),
        (None, None) => Target::CodeSections,
        (Some("entry"), None) => match &session.binary().entry {
            Some(e) => start(e.value),
            None => {
                eprintln!("fulg: {} has no entry point", file.display());
                return ExitCode::from(1);
            }
        },
        (Some(w), None) => match parse_addr(w) {
            Some(a) => start(Va(a)),
            None => Target::Symbol(w.to_string()),
        },
    };
    let syntax = if att { Syntax::Att } else { Syntax::Intel };
    // Stream: a large library has tens of millions of lines. A closed pipe
    // (`| head`) ends the listing quietly.
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut buf = String::new();
    let mut first = true;
    let width = render_disasm::address_width(session.binary());
    if json {
        let head = serde_json::json!({
            "schema": "fulgurite.disasm.v1",
            "path": session.path().display().to_string(),
            "arch": session.binary().arch,
            "syntax": syntax,
        })
        .to_string();
        // The header object, left open for the `lines` array.
        buf.push_str(&head[..head.len() - 1]);
        buf.push_str(",\"lines\":[\n");
    }
    let result = session.disassemble_each(&target, Options::with_syntax(syntax), &mut |l| {
        if json {
            let mut v = serde_json::json!(&l);
            if let fg_service::disasm::Line::Insn(i) = &l {
                v["text"] = serde_json::json!(fg_service::ir::tokens_text(&i.tokens));
            }
            if !first {
                buf.push_str(",\n");
            }
            first = false;
            buf.push_str(&v.to_string());
        } else {
            render_disasm::line(&mut buf, &l, width);
        }
        if buf.len() >= 1 << 16 {
            if out.write_all(buf.as_bytes()).is_err() {
                return std::ops::ControlFlow::Break(());
            }
            buf.clear();
        }
        std::ops::ControlFlow::Continue(())
    });
    if let Err(e) = result {
        eprintln!("fulg: {}: {e}", file.display());
        return ExitCode::from(1);
    }
    if json {
        buf.push_str("\n]}\n");
    }
    let _ = out.write_all(buf.as_bytes()).and_then(|()| out.flush());
    ExitCode::SUCCESS
}

#[derive(Clone, Copy)]
enum List {
    Imports,
    Exports,
    Seeds,
    Resources,
}

fn list(file: &PathBuf, json: bool, what: List) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let b = session.binary();
    let path = session.path().display().to_string();
    if json {
        let empty = Vec::new();
        let (schema, key, items) = match what {
            List::Imports => (
                "fulgurite.imports.v1",
                "imports",
                serde_json::json!(b.imports().collect::<Vec<_>>()),
            ),
            List::Exports => (
                "fulgurite.exports.v1",
                "exports",
                serde_json::json!(b.exports().collect::<Vec<_>>()),
            ),
            List::Seeds => ("fulgurite.seeds.v1", "seeds", serde_json::json!(&b.seeds)),
            List::Resources => (
                "fulgurite.resources.v1",
                "resources",
                serde_json::json!(b.pe().map_or(&empty, |p| &p.resources)),
            ),
        };
        let mut v = serde_json::json!({ "schema": schema, "path": path });
        v[key] = items;
        return print_json(&v);
    }
    let text = match what {
        List::Imports => render::imports(&session),
        List::Exports => render::exports(&session),
        List::Seeds => render::seeds(&session),
        List::Resources => render::resources(&session),
    };
    emit(&text);
    ExitCode::SUCCESS
}

fn functions(file: &PathBuf, json: bool) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let f = match session.functions() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("fulg: {}: {e}", session.path().display());
            return ExitCode::FAILURE;
        }
    };
    if json {
        let v = serde_json::json!({
            "schema": "fulgurite.functions.v1",
            "path": session.path().display().to_string(),
            "functions": f.functions,
            "fragments": f.fragments,
        });
        return print_json(&v);
    }
    emit(&render::functions(&f));
    ExitCode::SUCCESS
}

fn xrefs(file: &PathBuf, target: Option<&str>, json: bool) -> ExitCode {
    use fg_service::xrefs::XrefTarget;
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let target = match target {
        None => XrefTarget::All,
        Some(t) => match parse_addr(t) {
            Some(va) if t.starts_with("0x") || t.starts_with("0X") => {
                XrefTarget::Address(fg_service::core::Va(va))
            }
            _ => XrefTarget::Name(t.to_string()),
        },
    };
    let list = match session.xrefs(&target) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fulg: {}: {e}", session.path().display());
            return ExitCode::FAILURE;
        }
    };
    if json {
        let v = serde_json::json!({
            "schema": "fulgurite.xrefs.v1",
            "path": session.path().display().to_string(),
            "target": list.target,
            "xrefs": list.refs,
        });
        return print_json(&v);
    }
    emit(&render::xrefs(&list));
    ExitCode::SUCCESS
}

fn relocs(file: &PathBuf, slots: bool, json: bool) -> ExitCode {
    use fg_service::loader::RelocKind;
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let chosen: Vec<&fg_service::loader::Relocation> = session
        .binary()
        .relocations
        .iter()
        .filter(|r| !slots || matches!(r.kind, RelocKind::GotEntry | RelocKind::PltSlot))
        .collect();
    if json {
        return print_json(&RelocsJson {
            schema: "fulgurite.relocs.v1",
            path: session.path().display().to_string(),
            relocations: chosen,
        });
    }
    emit(&render::relocs(&session, &chosen));
    ExitCode::SUCCESS
}

fn notes(file: &PathBuf, json: bool) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let empty = Vec::new();
    let list = session.binary().elf().map_or(&empty, |e| &e.notes);
    let pe = session.binary().pe();
    if json {
        return print_json(&NotesJson {
            schema: "fulgurite.notes.v1",
            path: session.path().display().to_string(),
            notes: list,
            debug_directory: pe.map(|p| p.debug.as_slice()),
            rich_header: pe.and_then(|p| p.rich.as_ref()),
            certificates: pe.map(|p| p.certificates.as_slice()),
        });
    }
    emit(&render::notes(&session));
    ExitCode::SUCCESS
}

/// Which symbols `fulg symbols` shows.
struct SymbolFilter {
    imports: bool,
    exports: bool,
    table: Option<TableArg>,
}

impl SymbolFilter {
    fn keep(&self, s: &fg_service::loader::Symbol) -> bool {
        use fg_service::loader::SymbolTable;
        let table_ok = match self.table {
            Some(TableArg::Dynamic) => matches!(
                s.table,
                SymbolTable::Dynamic
                    | SymbolTable::Imports
                    | SymbolTable::DelayImports
                    | SymbolTable::Exports
            ),
            Some(TableArg::Static) => matches!(s.table, SymbolTable::Static | SymbolTable::Coff),
            None => true,
        };
        table_ok && (!self.imports || s.is_import()) && (!self.exports || s.is_export())
    }
}

/// Writes command output. A closed pipe (`fulg info x | head`) is not an error.
fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
}

fn print_json<T: Serialize>(value: &T) -> ExitCode {
    match serde_json::to_string_pretty(value) {
        Ok(text) => {
            emit(&format!("{text}\n"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fulg: could not encode JSON: {e}");
            ExitCode::from(1)
        }
    }
}

fn sections(file: &PathBuf, json: bool) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    if json {
        return print_json(&SectionsJson {
            schema: "fulgurite.sections.v1",
            path: session.path().display().to_string(),
            sections: &session.binary().sections,
        });
    }
    emit(&render::sections(&session));
    ExitCode::SUCCESS
}

fn symbols(file: &PathBuf, filter: SymbolFilter, json: bool) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    let chosen: Vec<&fg_service::loader::Symbol> = session
        .binary()
        .symbols
        .iter()
        .filter(|s| filter.keep(s))
        .collect();
    if json {
        return print_json(&SymbolsJson {
            schema: "fulgurite.symbols.v1",
            path: session.path().display().to_string(),
            symbols: chosen,
        });
    }
    emit(&render::symbols(&session, &chosen));
    ExitCode::SUCCESS
}

fn info(file: &PathBuf, json: bool) -> ExitCode {
    let session = match Session::open(file) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };
    if json {
        let out = InfoJson {
            schema: "fulgurite.info.v1",
            path: session.path().display().to_string(),
            binary: session.binary(),
        };
        match serde_json::to_string_pretty(&out) {
            Ok(text) => emit(&format!("{text}\n")),
            Err(e) => {
                eprintln!("fulg: could not encode JSON: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        emit(&render::info(&session));
    }
    ExitCode::SUCCESS
}

fn report_error(e: &ServiceError) -> ExitCode {
    eprintln!("fulg: {e}");
    match e {
        ServiceError::Load {
            source: fg_service::loader::LoadError::Malformed { anomalies, .. },
            ..
        } => {
            for a in anomalies {
                eprintln!("  {}", render::anomaly_line(a));
            }
            ExitCode::from(2)
        }
        ServiceError::Load { .. } => ExitCode::from(2),
        _ => ExitCode::from(1),
    }
}
