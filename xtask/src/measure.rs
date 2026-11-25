// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask measure CORPUS`: function-boundary precision and recall of
//! Fulgurite, IDA and Binary Ninja against the corpus's true function lists
//! (M1 step 8; `tools/measure/corpus.sh` builds the corpus).
//!
//! For each `truth/<config>/<name>.txt` the stripped binary is
//! `bin/<config>/<name>`. Fulgurite is run on it here; IDA's and Binary
//! Ninja's functions are read from `<binary>.ida.txt` and `<binary>.bn.txt`
//! next to it, when they exist. Every list has one function per line, its
//! entry address first (`0x...`); lines starting with `#` are comments.
//!
//! A function counts when its entry address is a true entry. Entries outside
//! executable segments (IDA's import stubs) and in PLT sections (no symbol
//! names them, so they are not in the true list) are left out of every list.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// The tools compared, with the file suffix of their exported lists.
const TOOLS: &[(&str, Option<&str>)] = &[
    ("fulgurite", None),
    ("ida", Some(".ida.txt")),
    ("binja", Some(".bn.txt")),
];

/// The configs of the M1 exit criterion: stripped `-O2` gcc and clang builds
/// for x86-64 (design document section 23).
const GATE: &[&str] = &["gcc-O2", "clang-O2"];

/// An address range, end excluded.
type Range = (u64, u64);

/// One binary of the corpus.
struct Binary {
    config: String,
    name: String,
    path: PathBuf,
    truth: BTreeMap<u64, String>,
}

/// What one tool found in one binary.
#[derive(Default)]
struct Found {
    /// Entries, after the exclusions.
    entries: BTreeSet<u64>,
    /// Analysis time (Fulgurite only), in milliseconds.
    ms: Option<u128>,
    /// Why there is no list.
    error: Option<String>,
}

/// Counts over a set of binaries.
#[derive(Default, Clone, Copy)]
struct Tally {
    binaries: usize,
    truth: usize,
    found: usize,
    hit: usize,
}

impl Tally {
    fn add(&mut self, truth: &BTreeSet<u64>, found: &BTreeSet<u64>) {
        self.binaries += 1;
        self.truth += truth.len();
        self.found += found.len();
        self.hit += truth.intersection(found).count();
    }

    fn recall(&self) -> f64 {
        ratio(self.hit, self.truth)
    }

    fn precision(&self) -> f64 {
        ratio(self.hit, self.found)
    }
}

fn ratio(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

pub fn measure(args: &[String]) -> ExitCode {
    let mut corpus = None;
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut only = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--jobs" => match it.next().and_then(|n| n.parse().ok()) {
                Some(n) if n > 0 => jobs = n,
                _ => return usage(),
            },
            "--config" => match it.next() {
                Some(c) => only = Some(c.clone()),
                None => return usage(),
            },
            _ if corpus.is_none() && !a.starts_with('-') => corpus = Some(PathBuf::from(a)),
            _ => return usage(),
        }
    }
    let Some(corpus) = corpus else {
        return usage();
    };

    let binaries = match read_corpus(&corpus, only.as_deref()) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            eprintln!("no binaries under {}/truth", corpus.display());
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("cannot read {}: {e}", corpus.display());
            return ExitCode::FAILURE;
        }
    };
    eprintln!("{} binaries, {jobs} at a time", binaries.len());

    // results[binary][tool]
    let results: Vec<Mutex<Vec<Option<Found>>>> =
        binaries.iter().map(|_| Mutex::new(Vec::new())).collect();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(b) = binaries.get(i) else { break };
                    let r = run_tools(b);
                    *results[i].lock().unwrap() = r;
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(50) || n == binaries.len() {
                        eprintln!("{n}/{}", binaries.len());
                    }
                }
            });
        }
    });
    let results: Vec<Vec<Option<Found>>> = results
        .into_iter()
        .map(|m| m.into_inner().unwrap())
        .collect();

    let report = report(&binaries, &results);
    print!("{report}");
    let md = corpus.join("results.md");
    let csv = corpus.join("results.csv");
    if let Err(e) = std::fs::write(&md, &report)
        .and_then(|()| std::fs::write(&csv, per_binary_csv(&binaries, &results)))
    {
        eprintln!("cannot write the results: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("wrote {} and {}", md.display(), csv.display());
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask measure CORPUS [--jobs N] [--config NAME]");
    ExitCode::from(2)
}

/// Every binary with a true list, by config and name.
fn read_corpus(corpus: &Path, only: Option<&str>) -> std::io::Result<Vec<Binary>> {
    let mut out = Vec::new();
    let mut configs: Vec<_> = std::fs::read_dir(corpus.join("truth"))?
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    configs.sort();
    for config in configs {
        if only.is_some_and(|o| o != config) {
            continue;
        }
        let mut names: Vec<_> = std::fs::read_dir(corpus.join("truth").join(&config))?
            .filter_map(Result::ok)
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_suffix(".txt")
                    .map(str::to_owned)
            })
            .collect();
        names.sort();
        for name in names {
            let text = std::fs::read_to_string(
                corpus
                    .join("truth")
                    .join(&config)
                    .join(name.clone() + ".txt"),
            )?;
            let truth = parse_list(&text)
                .map(|(va, rest)| (va, rest.to_owned()))
                .collect();
            let path = corpus.join("bin").join(&config).join(&name);
            if path.is_file() {
                out.push(Binary {
                    config: config.clone(),
                    name,
                    path,
                    truth,
                });
            }
        }
    }
    Ok(out)
}

/// The entries of a function list, with the rest of each line.
fn parse_list(text: &str) -> impl Iterator<Item = (u64, &str)> {
    text.lines().filter_map(|l| {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            return None;
        }
        let (first, rest) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
        let hex = first
            .strip_prefix("0x")
            .or_else(|| first.strip_prefix("0X"))?;
        u64::from_str_radix(hex, 16).ok().map(|v| (v, rest.trim()))
    })
}

/// Each tool's functions in `b`, or `None` where a tool has no list.
fn run_tools(b: &Binary) -> Vec<Option<Found>> {
    let bytes: std::sync::Arc<[u8]> = match std::fs::read(&b.path) {
        Ok(v) => v.into(),
        Err(e) => {
            let fulgurite = Found {
                error: Some(e.to_string()),
                ..Found::default()
            };
            return vec![Some(fulgurite), None, None];
        }
    };
    let session = fg_service::Session::from_bytes(&b.path, bytes, &Default::default());
    // The code ranges a function may start in: executable segments, less the
    // PLT sections.
    let (code, plt): (Vec<Range>, Vec<Range>) = match &session {
        Ok(s) => {
            let bin = s.binary();
            (
                bin.segments
                    .iter()
                    .filter(|s| s.perms.execute)
                    .map(|s| (s.va.0, s.va.0.saturating_add(s.mem_size)))
                    .collect(),
                bin.sections
                    .iter()
                    .filter(|s| s.name.starts_with(".plt") || s.name.starts_with(".iplt"))
                    .filter_map(|s| s.va.map(|v| (v.0, v.0.saturating_add(s.size))))
                    .collect(),
            )
        }
        Err(_) => (Vec::new(), Vec::new()),
    };
    let keep = |v: u64| {
        let within = |r: &[Range]| r.iter().any(|&(a, e)| v >= a && v < e);
        (code.is_empty() || within(&code)) && !within(&plt)
    };

    let mut out = Vec::new();
    for &(_, suffix) in TOOLS {
        let found = match suffix {
            None => {
                let mut f = Found::default();
                let start = Instant::now();
                let r = match &session {
                    Ok(s) => {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.functions()))
                            .map_err(|_| "panicked".to_owned())
                            .and_then(|r| r.map_err(|e| e.to_string()))
                    }
                    Err(e) => Err(e.to_string()),
                };
                f.ms = Some(start.elapsed().as_millis());
                match r {
                    Ok(fs) => {
                        f.entries = fs
                            .functions
                            .iter()
                            .map(|x| x.entry.0)
                            .filter(|&v| keep(v))
                            .collect();
                        let list: String = fs.functions.iter().fold(String::new(), |mut s, x| {
                            let _ = writeln!(
                                s,
                                "0x{:x} {}",
                                x.entry.0,
                                x.name.as_deref().unwrap_or("")
                            );
                            s
                        });
                        let _ = std::fs::write(with_suffix(&b.path, ".fulg.txt"), list);
                    }
                    Err(e) => {
                        eprintln!("{}/{}: fulgurite: {e}", b.config, b.name);
                        f.error = Some(e);
                    }
                }
                Some(f)
            }
            Some(suffix) => std::fs::read_to_string(with_suffix(&b.path, suffix))
                .ok()
                .map(|text| Found {
                    entries: parse_list(&text)
                        .map(|(v, _)| v)
                        .filter(|&v| keep(v))
                        .collect(),
                    ..Found::default()
                }),
        };
        out.push(found);
    }
    out
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn truth_set(b: &Binary) -> BTreeSet<u64> {
    b.truth.keys().copied().collect()
}

fn report(binaries: &[Binary], results: &[Vec<Option<Found>>]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Function-boundary recovery\n");
    let _ = writeln!(
        out,
        "A function counts when its entry address is a true entry. Recall: true functions found. \
         Precision: functions found that are true. Totals over all functions of the binaries each \
         tool has a list for.\n"
    );

    // Per config, and the gate and overall rows.
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    let all: Vec<usize> = (0..binaries.len()).collect();
    let gate: Vec<usize> = all
        .iter()
        .copied()
        .filter(|&i| GATE.contains(&binaries[i].config.as_str()))
        .collect();
    let mut by_config: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, b) in binaries.iter().enumerate() {
        by_config.entry(&b.config).or_default().push(i);
    }
    groups.push(("**all**".into(), all.clone()));
    groups.push(("**M1 gate (gcc-O2, clang-O2)**".into(), gate.clone()));
    groups.extend(by_config.into_iter().map(|(c, v)| (c.to_owned(), v)));

    let _ = writeln!(out, "## Recall and precision\n");
    let mut header = String::from("| config | binaries | true functions |");
    let mut rule = String::from("|---|--:|--:|");
    for (tool, _) in TOOLS {
        let _ = write!(header, " {tool} recall | {tool} precision |");
        rule.push_str("--:|--:|");
    }
    let _ = writeln!(out, "{header}\n{rule}");
    for (name, members) in &groups {
        let truth: usize = members.iter().map(|&i| binaries[i].truth.len()).sum();
        let _ = write!(out, "| {name} | {} | {truth} |", members.len());
        for t in 0..TOOLS.len() {
            let tally = tally(binaries, results, members, t, None);
            if tally.binaries == 0 {
                out.push_str(" – | – |");
            } else if tally.binaries == members.len() {
                let _ = write!(out, " {:.2}% | {:.2}% |", tally.recall(), tally.precision());
            } else {
                // Only some binaries have this tool's list.
                let _ = write!(
                    out,
                    " {:.2}% ({}) | {:.2}% |",
                    tally.recall(),
                    tally.binaries,
                    tally.precision()
                );
            }
        }
        out.push('\n');
    }

    // Fulgurite against each other tool, on the binaries both have.
    for (t, (tool, _)) in TOOLS.iter().enumerate().skip(1) {
        let members: Vec<usize> = all
            .iter()
            .copied()
            .filter(|&i| results[i][t].is_some())
            .collect();
        if members.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "\n## Fulgurite against {tool}, on the {} binaries {tool} has\n",
            members.len()
        );
        let _ = writeln!(
            out,
            "\"Of {tool}'s\": of the true functions {tool} found, how many Fulgurite found too.\n"
        );
        let _ = writeln!(
            out,
            "| config | binaries | fulgurite recall | {tool} recall | of {tool}'s | fulgurite precision | {tool} precision |\n|---|--:|--:|--:|--:|--:|--:|"
        );
        let mut rows: Vec<(String, Vec<usize>)> = vec![
            ("**all**".into(), members.clone()),
            (
                "**M1 gate (gcc-O2, clang-O2)**".into(),
                members
                    .iter()
                    .copied()
                    .filter(|i| gate.contains(i))
                    .collect(),
            ),
        ];
        let mut by_config: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for &i in &members {
            by_config.entry(&binaries[i].config).or_default().push(i);
        }
        rows.extend(by_config.into_iter().map(|(c, v)| (c.to_owned(), v)));
        for (name, m) in rows {
            if m.is_empty() {
                continue;
            }
            let f = tally(binaries, results, &m, 0, None);
            let o = tally(binaries, results, &m, t, None);
            let of_theirs = tally(binaries, results, &m, 0, Some(t));
            let _ = writeln!(
                out,
                "| {name} | {} | {:.2}% | {:.2}% | {:.2}% | {:.2}% | {:.2}% |",
                m.len(),
                f.recall(),
                o.recall(),
                of_theirs.recall(),
                f.precision(),
                o.precision()
            );
        }
    }

    // Where Fulgurite misses most, to look at first.
    let mut worst: Vec<(usize, usize)> = all
        .iter()
        .filter_map(|&i| {
            let f = results[i][0].as_ref()?;
            let missed = truth_set(&binaries[i]).difference(&f.entries).count();
            (missed > 0).then_some((i, missed))
        })
        .collect();
    worst.sort_by_key(|w| std::cmp::Reverse(w.1));
    if !worst.is_empty() {
        let _ = writeln!(out, "\n## Most functions missed by Fulgurite\n");
        let _ = writeln!(
            out,
            "| binary | true | missed | first missed |\n|---|--:|--:|---|"
        );
        for &(i, missed) in worst.iter().take(25) {
            let b = &binaries[i];
            let f = results[i][0].as_ref().unwrap();
            let first: Vec<&str> = b
                .truth
                .iter()
                .filter(|(v, _)| !f.entries.contains(v))
                .take(4)
                .map(|(_, n)| n.as_str())
                .collect();
            let _ = writeln!(
                out,
                "| {}/{} | {} | {missed} | {} |",
                b.config,
                b.name,
                b.truth.len(),
                first.join(", ")
            );
        }
    }
    let failed: Vec<String> = all
        .iter()
        .filter_map(|&i| {
            let e = results[i][0].as_ref()?.error.as_ref()?;
            Some(format!(
                "- {}/{}: {e}",
                binaries[i].config, binaries[i].name
            ))
        })
        .collect();
    if !failed.is_empty() {
        let _ = writeln!(out, "\n## Fulgurite errors\n\n{}", failed.join("\n"));
    }
    let ms: u128 = results.iter().filter_map(|r| r[0].as_ref()?.ms).sum();
    let _ = writeln!(
        out,
        "\nFulgurite analysis time: {:.1} s in total (all binaries, one thread each).",
        ms as f64 / 1000.0
    );
    out
}

/// Tool `t`'s counts over `members` that have its list. With `among`, only
/// the true functions tool `among` found count as true.
fn tally(
    binaries: &[Binary],
    results: &[Vec<Option<Found>>],
    members: &[usize],
    t: usize,
    among: Option<usize>,
) -> Tally {
    let mut tally = Tally::default();
    for &i in members {
        let Some(f) = results[i][t].as_ref() else {
            continue;
        };
        let mut truth = truth_set(&binaries[i]);
        if let Some(o) = among {
            let Some(other) = results[i][o].as_ref() else {
                continue;
            };
            truth.retain(|v| other.entries.contains(v));
        }
        tally.add(&truth, &f.entries);
    }
    tally
}

fn per_binary_csv(binaries: &[Binary], results: &[Vec<Option<Found>>]) -> String {
    let mut out = String::from("config,binary,tool,true,found,hit,ms,error\n");
    for (b, r) in binaries.iter().zip(results) {
        let truth = truth_set(b);
        for ((tool, _), f) in TOOLS.iter().zip(r) {
            let Some(f) = f else { continue };
            let _ = writeln!(
                out,
                "{},{},{tool},{},{},{},{},{}",
                b.config,
                b.name,
                truth.len(),
                f.entries.len(),
                truth.intersection(&f.entries).count(),
                f.ms.map(|m| m.to_string()).unwrap_or_default(),
                f.error.as_deref().unwrap_or("").replace(',', ";")
            );
        }
    }
    out
}
