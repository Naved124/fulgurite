# Fulgurite — Architecture Design

> **fulgurite** (n.): natural glass formed when lightning strikes sand. Its branching shape is a permanent record of the exact path the lightning took. Fulgurite turns opaque silicon code transparent and keeps the path from every output token back to its source bytes. *Lightning, frozen in glass.*

> A disassembler/decompiler whose guesses are **visible, explainable and reversible**.
> Friendly to someone who has only ever run `objdump`, and still useful to someone who
> reverses obfuscated malware for a living.

| | |
|---|---|
| **Status** | Draft v0.1 — hypothetical design, no code yet |
| **Author** | Naved |
| **Date** | 2026-10-10 |
| **v1 targets** | x86-64 + ARM64 · ELF + PE |
| **Core** | Own engine, written from scratch (loaders → decoders → IR → analyses → decompiler) |

---

## Table of contents

0. [Goals, non-goals, principles](#0-goals-non-goals-principles)
1. [Prior art and gap analysis](#1-prior-art-and-gap-analysis)
2. [Personas and journeys](#2-personas-and-journeys)
3. [System architecture](#3-system-architecture)
4. [Core data model and the Fact store](#4-core-data-model-and-the-fact-store)
5. [Storage and versioning](#5-storage-and-versioning)
6. [Loaders (ELF, PE)](#6-loaders-elf-pe)
7. [Architecture modules (x86-64, ARM64)](#7-architecture-modules-x86-64-arm64)
8. [Disassembly and CFG recovery](#8-disassembly-and-cfg-recovery)
9. [IR stack](#9-ir-stack)
10. [Analyses](#10-analyses)
11. [Decompiler](#11-decompiler)
12. [Confidence system](#12-confidence-system)
13. [Dynamic integration](#13-dynamic-integration)
14. [Symbolic queries](#14-symbolic-queries)
15. [Beginner layer](#15-beginner-layer)
16. [Advanced layer](#16-advanced-layer)
17. [AI assistance](#17-ai-assistance)
18. [UI architecture](#18-ui-architecture)
19. [Performance and concurrency](#19-performance-and-concurrency)
20. [Security of the tool itself](#20-security-of-the-tool-itself)
21. [Testing and validation](#21-testing-and-validation)
22. [Tech stack and rationale](#22-tech-stack-and-rationale)
23. [Roadmap](#23-roadmap)
24. [Open questions](#24-open-questions)
25. [Glossary and references](#25-glossary-and-references)

---

## 0. Goals, non-goals, principles

### 0.1 The problem

Every reverse-engineering tool shows the user **confident-looking output built from guesses**.
Compilation destroys names, types, struct layouts and often function boundaries; the tool
reconstructs them heuristically. No tool can be right every time:

- **Separating code from data is undecidable** (a consequence of Rice's theorem). Any tool that
  says "these bytes are instructions" is making a heuristic bet.
- **Indirect control flow** (`jmp rax`, function pointers, vtables, compiler-generated jump
  tables) hides edges of the control-flow graph.
- **Optimised code** (`-O2`/`-O3`: inlining, tail calls, merged branches, SIMD) does not map back
  to the C a human wrote.
- **Languages other than C** (Rust, Go, C++, Swift) use idioms that C-shaped decompilers render badly.
- **Obfuscation** (control-flow flattening, opaque predicates, virtualising protectors) is
  designed to defeat the heuristics.

Existing tools hide *how sure they are* and *why they decided*. Beginners can't tell a solid
deduction from a coin flip; experts waste time re-verifying everything.

There is also a **second problem**, reported by a beginner: a whole binary prints thousands of
lines, and without a question to ask, *you don't know where to look or what to derive*.
Experts read with a question in mind and ignore 99% of the output; tools don't help beginners
learn which questions to ask.

### 0.2 Goals

| # | Goal |
|---|---|
| G1 | Every inferred claim carries a **confidence** and **evidence**, and the UI shows both. |
| G2 | Every line of pseudocode can answer **"why does it say this?"** down to the source bytes and the passes that transformed them. |
| G3 | Every inference is **reversible**: users can reject or override any fact, and the rejection is *sticky* across re-analysis. |
| G4 | **Question-first** workflow: the tool can supply the question, highlight the relevant output and dim the rest. |
| G5 | Static and dynamic analysis are **one model**: runtime observations become evidence for static facts. |
| G6 | **Progressive disclosure**: one tool from first binary to expert work; no "lite edition". |
| G7 | User analysis is **plain text**, diffable and mergeable in git. |
| G8 | Decompiler quality competitive on unobfuscated `gcc`/`clang`/`MSVC` output at `-O0`…`-O2` for x86-64 and ARM64. |
| G9 | Fully scriptable and headless; the GUI uses the same public API as plugins. |

### 0.3 Non-goals for v1

- Kernel-mode debugging, hypervisor-level tracing.
- Full MSVC C++ exception-handling recovery (basic `.pdata` unwind support only).
- Architectures beyond x86-64 and ARM64 (32-bit x86, ARM32/Thumb, MIPS, RISC-V are designed-for but not built).
- Formats beyond ELF and PE (Mach-O, raw firmware are designed-for but not built).
- Swift and Objective-C language frontends.
- Defeating commercial virtualising protectors (VMProtect/Themida) automatically. v1 provides the *tools* (traces, symbolic queries, custom passes), not a one-click unpacker.

### 0.4 Design principles

1. **Visible, explainable, reversible.** If the tool guessed, it says so, says why, and lets you undo it.
2. **One source of truth per concept.** Instruction semantics live in the lifter only; the emulator, the symbolic engine, the decompiler *and the beginner's plain-English explanations* are all derived from it, so they cannot disagree.
3. **Question-first.** Views can be driven by a question ("is the stack executable?") rather than only by an address.
4. **Evidence beats heuristics.** An observed execution outranks an inferred guess; a user decision outranks both.
5. **The assembly is the truth; pseudocode is a hint.** The UI never hides the bytes and instructions a pseudocode line came from.
6. **Analysis is text.** Anything a human decided is stored as human-readable text that git can merge.
7. **Same API for everyone.** The GUI, the CLI, Python scripts and plugins call the same RPC surface.

---

## 1. Prior art and gap analysis

> Competitor features below were checked against vendor release notes as of **October 2026**
> (IDA 9.2, Binary Ninja 5.x/6.0, Ghidra 12.x). Re-check before relying on them; these tools
> ship fast.

### 1.1 What the incumbents already do

| | IDA Pro (9.2) | Binary Ninja (5.x–6.0) | Ghidra (12.x) | angr |
|---|---|---|---|---|
| Decompiler | Hex-Rays: best-in-class on hard code; Go decompilation (stack and register ABIs) added in 9.2 | HLIL: good, improving | P-code decompiler: good | Basic |
| Internal design | Microcode inside the decompiler; **microcode viewer** added in 9.2 | Layered IL (LLIL/MLIL/HLIL + SSA), all viewable | P-code drives decompiler **and** emulator | VEX IR + symbolic engine |
| Dynamic | Debugger with many backends | **rr time-travel debugging** via a GDB-RSP adapter (5.0), using static analysis while debugging; TTD queries (5.2) | Trace database; breakpoint timeline across a trace (12.1) | Symbolic execution |
| Symbolic | Plugins | Plugins | Z3-based symbolic summaries via the emulator (12.0) | Core feature |
| Function matching | FLIRT signatures, Lumina server | **WARP** format + signature server (5.1–5.3) | BSim similarity search | — |
| AI | Third-party plugins | **Sidekick**: structure recovery, multi-step investigations, chat that can search and edit the binary | Third-party plugins / MCP servers | — |
| Collaboration | IDA Teams (paid) | Enterprise (paid) | Ghidra Server | — |
| Cross-tool git sync | BinSync (open-source plugin, git-based, works across IDA/Binja/Ghidra/angr) | ← same | ← same | ← same |
| Architectures | Dozens, incl. microcontrollers (TriCore, V850…) | Many (TMS320C6x added in 6.0) | Many (SLEIGH specs) | Many (via VEX) |

**Correction to earlier drafts:** "static + dynamic unified", "symbolic queries in the tool",
"Go support", "git collaboration" and "AI assistance" are **not** differentiators. Incumbents or
plugins already ship them. Fulgurite still includes them because users expect them.

### 1.2 What no shipping tool does (Fulgurite's real differentiators)

| # | Differentiator | Status elsewhere |
|---|---|---|
| D1 | **Calibrated confidence + evidence on every claim** (§4, §12) | Not offered by any major tool; a 2026 decompilation survey lists exposing uncertainty as an **open problem** |
| D2 | **Per-token provenance: "why does it say this?"** with the reason for every rewrite (§9.3, §15.5) | IL/microcode viewers show *stages*, not per-token history with reasons |
| D3 | **One fact model with sticky rejections** across every inference kind (§4.4) | Overrides exist per feature (types, names), not as one uniform model |
| D4 | **Verified rewrites** (translation validation, §1.4) | Rewrites are trusted from testing, not proved |
| D5 | **Question Mode + learning layer** (§15) | Not attempted |
| D6 | **Over-confidence as a release-blocking regression** (§12.4, §21.5) | Not publicly measured |

### 1.3 Where Fulgurite would be weaker, and the counter-measure for each

| Weakness | Why | Counter-measure |
|---|---|---|
| Decompiler output quality | Hex-Rays ~30 years, Binja ~10 years of tuning | Verified e-graph simplification, search-based structuring, learned+checked naming (§1.4); public benchmark (§1.5) |
| Architecture breadth | 2 arches vs dozens | Spec-generated decoders/lifters (§1.4): an arch costs a spec, not months |
| Signature databases | Years of curation (FLIRT/Lumina, WARP, BSim) | Compilation farm + debuginfod + import of open formats (§1.4) |
| Battle-testing on weird binaries | Incumbents have seen millions | Fuzzing + **differential testing against real OS loaders** (§1.4, §21) |
| Ecosystem (plugins, training, writeups) | Network effects | Clean API, WASM plugins, DWARF export, BinSync-compatible import/export |
| Cost of evidence/provenance | Storing "why" for every fact costs memory and time | **Provenance on demand** via deterministic replay (§1.4) |
| Confidence could mislead if miscalibrated | Research shows simple quality proxies flag bad output poorly | Per-kind, per-compiler, per-opt-level calibration with published reliability charts (§12) |

### 1.4 Technical superiority plan

The incumbents' lead is mostly **accumulated hand-written work**: processor modules, tuned
heuristics, curated signature databases. Fulgurite replaces each kind of hand work with something
**generated from specs, learned from compiled code, or proved by a solver**. That kind of work
scales with compute instead of years.

| Axis | Incumbents | Fulgurite mechanism | Where specified |
|---|---|---|---|
| Instruction semantics | Hand-written lifters (processor modules, SLEIGH, per-arch lifters) | ARM64 lifter **generated from Arm's machine-readable ASL spec**; x86-64 lifter hand-written but checked against a **formal x86-64 semantics** (K framework, PLDI 2019) as an oracle, plus real-CPU differential tests | §7, §21.2 |
| New architectures | Months per processor | Ingest a formal **Sail** model (exists for ARM, RISC-V and others) → generated decoder + lifter | §7.1 |
| Rewrite correctness | Trusted heuristics | **Translation validation**: each rewrite on a region is SMT-checked for equivalence, Alive2-style. Modes: `always` / `sampled` / `ci-only` | §9.4, §11 |
| Expression simplification | Ordered rewrite rules (order-dependent) | **E-graphs / equality saturation** (`egg`): apply all rewrites at once, extract the most readable equivalent form; every step checkable | §10.7 |
| Control-flow structuring | One algorithm + fallbacks | **Search + verify**: several candidate structurings, scored for readability (gotos, nesting, variable count); best proved-equivalent wins | §11.2 |
| Names and types | Heuristics; AI as an add-on | Learned models (DIRTY-style) **propose**; type solver + SMT **check**; calibrated confidence | §10.5, §17 |
| Signatures | Years of curation | **Compilation farm** rebuilding distro packages across compiler versions and `-O` levels; **debuginfod** symbols for real distro binaries; semantic (MIR) hashes; import open formats (e.g. WARP) where licensing allows | §10.8 |
| Confidence | None | Calibrated per fact kind × compiler × opt level (compiler detected from `.comment` / PE Rich header) | §12.3 |
| Provenance cost | Not stored | Store compact ids only; **rebuild the full explain log on demand by re-running deterministic passes** for that one function | §9.3, §19.3 |
| Incrementality | Re-analysis passes | Salsa: precise invalidation, early cut-off, cancellation | §22.3 |
| Tool safety | C++ (IDA, Binja), Java (Ghidra) | Rust, `unsafe` forbidden in parsers, WASM-sandboxed plugins | §20, §22 |
| Loader correctness | Sample files | **Differential vs real OS loaders**: Linux kernel ELF loader, `ld.so`, Windows loader (in a VM) on fuzzed files; compare resulting memory maps | §21.7 |
| Real-world exposure | ~30 years of user bug reports | **Corpus program**: compiled open source (complete labels) + traced malware (free execution labels) + agent-assisted triage behind a verification gate | §21.8 |
| Collaboration | Paid servers / plugin | Git-native text **plus** real-time CRDT sync (Automerge/yrs) on the same records; DWARF export so `gdb` sees analyst names | §16.4 |

### 1.5 Benchmark scoreboard ("better" is measured, not claimed)

Every release runs **the same public corpus** (§21.4) through IDA, Binary Ninja, Ghidra and
Fulgurite, using each tool's headless mode where licences allow.

| Metric | How measured | Release gate |
|---|---|---|
| Function-boundary precision/recall | stripped build vs DWARF ground truth | ≥ best incumbent on v1 scope |
| Type accuracy (params/locals) | exact + compatible match vs DWARF | ≥ best incumbent |
| Struct layout accuracy | field offsets vs DWARF | ≥ best incumbent |
| Semantic correctness | recompile decompiled output, differential execution on generated inputs | ≥ best incumbent; zero regressions on verified functions |
| Readability | `goto` count, nesting depth, variable count vs source; blinded human ratings | ≥ best incumbent |
| Indirect-jump resolution | edge precision/recall vs traced execution | ≥ best incumbent |
| Library matching | precision/recall vs symbolised builds | ≥ best incumbent |
| Confidence calibration | expected calibration error per fact kind | no fact kind more over-confident than last release |
| Performance | wall time + peak memory on 10 MB / 100 MB binaries | within §19.4 targets |

**Rule:** a release does not ship if any metric falls below the best incumbent on the v1 scope
(x86-64 + ARM64, ELF + PE, unobfuscated gcc/clang/MSVC/Go/rustc output at `-O0`…`-O3`).

### 1.6 Limits no design can beat

- **Undecidability** (code vs data, indirect targets) bounds every tool equally; Fulgurite can only be more honest about it.
- **Verification costs time**: proving every rewrite is slower than trusting it, which is why it is a mode.
- **Specs only help where specs exist**: there is no official machine-readable x86-64 semantics from Intel, and the K model covers user-level instructions, not everything.
- **Readability is partly subjective**: Fulgurite optimises measurable proxies plus human ratings, not taste.
- **Real-world weirdness** (one-off packers, broken linkers) still takes exposure; fuzzing and corpora shorten that, they don't erase it.

---

## 2. Personas and journeys

### 2.1 Personas

| Persona | Background | What they need | What frustrates them today |
|---|---|---|---|
| **Beginner** (e.g. Naved, Stage 1 of an RE curriculum) | Knows C basics, has used `objdump`/`readelf`, no asm yet | Know *where to look*; learn what instructions mean; learn compiler patterns | "WTF did it just print"; pseudocode looks authoritative but is wrong |
| **CTF player** | Comfortable with asm and GDB | Fast triage, find the input path to the bug, pwn quickly | Switching between Ghidra, GDB, angr and pwntools |
| **Vulnerability researcher** | Expert, large binaries | Reachability ("can user input reach this `memcpy`?"), type recovery at scale, diffing patches | Manual type propagation; no integrated solver |
| **Malware analyst** | Expert, hostile and obfuscated samples | Safe handling, deobfuscation, library identification, team collaboration | Obfuscation defeats heuristics; costly collaboration servers |

### 2.2 Journey A — beginner: "Is this binary exploitable?"

1. Open `vuln` → the **Welcome panel** offers starter questions instead of a wall of disassembly.
2. Pick **"What protections does this binary have?"** → Question Mode opens the *Segments* and *Header* views, dims everything except the `Type:` row, the `GNU_STACK` row, the `GNU_RELRO` row and the dynamic `BIND_NOW` flag, and shows a step card per protection: *what to look at → what it means → what you can derive*.
3. The checksec panel summarises: `PIE: no · NX: yes · Canary: no · RELRO: partial` and every entry has a **"how was this detected?"** link that shows the exact header bytes.
4. Follow-up question offered: **"Where does user input enter?"** → highlights calls to `read`, `gets`, `fgets`, `scanf`, `recv` with the buffer argument and its size if known.
5. User clicks the `gets` call → Explain mode: "`gets` writes until newline with **no length limit** into `buf` (64 bytes at `rbp-0x40`)". The stack-frame diagram shows `buf`, saved `rbp`, return address and the distance between them (`0x48` bytes), with `last − first + 1` written on every range.

### 2.3 Journey B — CTF player: crackme with a check function

1. `fulg open crackme && fulg ask "find input reaching 0x401234"` from the terminal, or right-click the "Correct!" block → **Find input that reaches here**.
2. Symbolic query runs on MIR from `main`, `stdin` symbolic, 30 s budget → returns a concrete input, or a partial answer listing the unsolved constraint.
3. Runs the input in the emulator → the trace confirms the path → edges along the path upgrade to `observed` confidence.

### 2.4 Journey C — vuln researcher: struct recovery at scale

1. In `parse_packet`, the user defines `struct packet` from field accesses (the struct editor proposes it from access offsets).
2. Fulgurite's **propagation engine** finds 14 other functions with the same access pattern on the same allocation site → review queue with a diff per function.
3. User accepts 12, rejects 2 (rejections are sticky). The pseudocode across the program goes from `*(long *)(p + 0x18)` to `pkt->next`.

### 2.5 Journey D — malware analyst: flattened control flow

1. Function graph shows one dispatcher block with in-degree 40 → the **CFF detector** flags it with confidence 0.9 and its evidence (state variable, dispatcher shape).
2. Analyst runs the `unflatten` pass in **preview** → before/after IR diff → accepts.
3. Annotations are committed to the team's git repo; a colleague pulls and sees the same unflattened view plus the names.

---

## 3. System architecture

### 3.1 Layer diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Clients:   GUI (Tauri)   │  CLI `fulg`  │   Python (PyO3)   │  Plugins   │
└──────────────┬────────────┴───────┬──────┴────────┬──────────┴─────┬──────┘
               │      Fulgurite RPC (versioned schema, streaming)     │
┌──────────────┴─────────────────────────────────────────────────────┴──────┐
│  Service layer:  Session · Query engine · Question engine · Undo/op-log    │
├───────────────────────────────────────────────────────────────────────────┤
│  Services:  Emulator │ Debugger bridge │ Symbolic solver │ AI suggester    │
├───────────────────────────────────────────────────────────────────────────┤
│  FACT STORE  (facts · evidence · confidence · provenance · dependency DAG)│
├───────────────────────────────────────────────────────────────────────────┤
│  Decompiler: structuring → expression folding → variable recovery → AST   │
├───────────────────────────────────────────────────────────────────────────┤
│  Analyses: SSA · const-prop · stack · VSA · types · idioms · libmatch ·   │
│            language frontends · deobfuscation passes                      │
├───────────────────────────────────────────────────────────────────────────┤
│  IR stack:  LIR ──► MIR ──► HIR      (each with SSA form, all w/ provenance)│
├───────────────────────────────────────────────────────────────────────────┤
│  Disassembly & CFG recovery (recursive descent + guided sweep)            │
├───────────────────────────────────────────────────────────────────────────┤
│  Arch modules:  x86-64 │ ARM64      (decode · lift · regs · conventions)  │
├───────────────────────────────────────────────────────────────────────────┤
│  Loaders:  ELF │ PE    (→ address spaces, symbols, relocs, metadata)      │
├───────────────────────────────────────────────────────────────────────────┤
│  Storage:  blob store │ analysis cache (SQLite) │ user layer (text, git)  │
└───────────────────────────────────────────────────────────────────────────┘
```

Every arrow upward carries **provenance**: anything a layer produces records which lower-layer
objects and which pass produced it.

### 3.2 Process model

```
           ┌──────────────┐  Unix socket / named pipe   ┌───────────────────┐
           │  GUI client  │◄───────────────────────────►│                   │
           └──────────────┘                             │  fulgurited       │
           ┌──────────────┐                             │  (analysis daemon)│
           │  fulg CLI    │◄───────────────────────────►│  - core library   │
           └──────────────┘                             │  - worker pool    │
           ┌──────────────┐  in-process (PyO3) OR RPC   │  - fact store     │
           │  Python      │◄───────────────────────────►│                   │
           └──────────────┘                             └────────┬──────────┘
                                                                 │ spawns, sandboxed
                                     ┌────────────────────────────┼─────────────────┐
                                     ▼                            ▼                 ▼
                              ┌─────────────┐           ┌────────────────┐  ┌──────────────┐
                              │ plugin host │           │ debug sandbox  │  │ solver worker│
                              │ (WASM/Py)   │           │ (container/VM) │  │ (bitwuzla/z3)│
                              └─────────────┘           └────────────────┘  └──────────────┘
```

- **`libfulgurite`** (Rust crate): the whole engine as a library, with no I/O policy. Usable directly from Rust and Python.
- **`fulgurited`**: a thin daemon hosting one or more sessions; lets the GUI, CLI and scripts share one live analysis. Single-user, local-only by default (listens on a socket with `0600` permissions; no TCP unless explicitly enabled).
- **Out-of-process workers**, so a crash or hang can't take down the session:
  - plugin host, so a buggy plugin cannot corrupt the fact store;
  - solver worker, because SMT queries can blow up memory and get killed on budget;
  - debug sandbox, because the target binary is hostile.

### 3.3 RPC surface (shape)

Versioned schema (`fulgurite.v1`), request/response plus server-push streams.

| Service | Key methods |
|---|---|
| `Session` | `open(path)`, `save()`, `close()`, `undo()`, `redo()`, `history()` |
| `Listing` | `range(addr, count)` (paginated, virtualised), `seek(addr)`, `xrefs(addr)` |
| `Functions` | `list(filter)`, `get(addr)`, `il(addr, tier, ssa)`, `decompile(addr)` |
| `Facts` | `query(selector)`, `explain(fact_id)`, `override(fact_id, value)`, `reject(fact_id)` |
| `Types` | `parse_c(text)`, `apply(target, type)`, `propagate(preview=true)` |
| `Questions` | `catalog(level)`, `start(question_id)`, `step(n)`, `answer(text)` |
| `Dynamic` | `emulate(start, budget)`, `attach(backend, target)`, `trace.load(file)`, `trace.last_write(addr, at_seq)` |
| `Solve` | `reach(target, from, budget)`, `can(expr_at_addr, predicate, budget)` |
| `Events` (stream) | `analysis_progress`, `facts_changed(ids)`, `view_invalidated(ranges)` |

---

## 4. Core data model and the Fact store

### 4.1 Entities

```rust
struct Project      { id: Uuid, binaries: Vec<BinaryId>, settings: Settings }
struct Binary       { id: BinaryId /* sha256 of file bytes */, format: Format, arch: ArchId,
                      spaces: Vec<AddressSpace>, entry_points: Vec<Va> }
struct AddressSpace { name: String /* "default", "tls", "overlay:X" */, segments: Vec<Segment> }
struct Segment      { va: Va, size: u64, file_off: Option<u64>, file_size: u64, perms: Perms /* R W X */ }
struct Section      { name: String, va: Va, size: u64, file_off: u64, kind: SectionKind, flags: u64 }
struct Symbol       { name: String, demangled: Option<String>, va: Va, size: Option<u64>,
                      kind: SymKind /* func, object, import, export, tls */, source: SymSource }
struct Function     { entry: Va, blocks: Vec<BlockId>, conv: Option<ConvId>, signature: Option<TypeId> }
struct BasicBlock   { start: Va, end: Va /* exclusive */, insns: Vec<Va>, succs: Vec<Edge> }
struct Edge         { to: Va, kind: EdgeKind /* fall, jump, cond_t, cond_f, call, ret, indirect */ }
struct Insn         { va: Va, len: u8, bytes: SmallVec<[u8; 15]>, mnemonic: Op, operands: Vec<Operand> }
struct Xref         { from: Va, to: Va, kind: XrefKind /* code, data_read, data_write, data_ptr */ }
```

These structs are **projections** of the fact store. A `Function` exists because the fact
`is_function(0x401000)` exists and is not rejected. They are cached for speed but always
re-derivable.

### 4.2 The Fact

```rust
struct Fact {
    id:         FactId,           // stable hash of (subject, claim-kind, producing pass)
    subject:    Subject,          // Va | VaRange | FuncId | IrNodeId | TypeSlot | VarId
    claim:      Claim,            // see table below
    confidence: Confidence,       // f32 in [0,1] + bucket (see §12)
    status:     Status,           // Declared | Inferred | Observed | User | Rejected
    provenance: Provenance,       // which pass, which version, which input facts
    evidence:   Vec<Evidence>,    // human-readable + machine-checkable reasons
    created:    OpSeq,            // op-log sequence number (for undo)
}

enum Status {
    Declared,   // from format metadata: symbol table, DWARF, PDB, export table
    Inferred,   // from an analysis pass
    Observed,   // from an execution trace / debugger
    User,       // a human set it
    Rejected,   // a human said "no" — suppresses re-inference (sticky)
}

struct Provenance { pass: PassId, pass_version: u32, inputs: Vec<FactId>, insns: Vec<Va> }

struct Evidence {
    kind:   EvidenceKind,  // ApiArgument, AccessPattern, Signature, TraceHit, Symbol, Dwarf, Heuristic, AiSuggestion
    text:   String,        // "passed as arg 1 to strlen at 0x401a20"
    anchor: Option<Va>,    // click-through target
    weight: f32,           // contribution to confidence
}
```

### 4.3 Claim kinds (v1)

| Claim | Example | Typical producers |
|---|---|---|
| `IsCode(range)` / `IsData(range)` | bytes 0x401000..0x401030 are code | CFG recovery, traces |
| `IsFunction(va)` | function starts at 0x401136 | symbols, call targets, prologues, `.eh_frame`/`.pdata` |
| `FunctionEnd(va, va)` | ends at 0x40116b | CFG recovery |
| `Edge(from, to, kind)` | indirect jump 0x401200 → 0x401240 | jump-table resolver, traces |
| `NoReturn(func)` | `exit`, `abort`, `__stack_chk_fail` | import names, analysis |
| `Type(slot, type)` | `param_1 : int *` | type inference, user, AI |
| `Name(entity, name)` | `param_1 → arr` | symbols, DWARF, naming heuristics, user, AI |
| `StructLayout(type, fields)` | `struct packet { +0 u16 len; … }` | struct recovery, user |
| `Idiom(ir_node, idiom)` | `x*0xAAAAAAAB>>33 ≡ x/3` | idiom recogniser |
| `LibraryMatch(func, lib_fn)` | `0x402000 = memcpy (glibc 2.40)` | signature matcher |
| `Obfuscation(func, kind)` | `control-flow flattening` | deobfuscation detectors |
| `Value(ir_node, set)` | `rax ∈ {0x404000, 0x404008}` | VSA, traces |

### 4.4 Resolution rules (when facts disagree)

1. `Rejected` beats everything for that exact claim. Re-analysis may not re-create it; it may produce a *different* claim on the same subject (e.g. a different type).
2. `User` beats `Observed` beats `Declared` beats `Inferred`. (Declared metadata can lie, e.g. in stripped/forged binaries, which is why `Observed` outranks it.)
3. Within the same status, higher confidence wins; **ties within 0.05 are surfaced as a conflict** in the UI rather than silently decided.
4. A conflict between `Observed` and `User` raises a **warning** ("you said this is data, but execution reached it at trace step 1832"); the user's decision is still kept.

### 4.5 Dependency DAG and invalidation

Every fact lists its input facts in `provenance.inputs`. The store maintains reverse edges.

```
user sets Type(param_1, int*) ─► invalidates every fact whose inputs include
                                 the old Type(param_1, long)
                                     ├─ HIR expr  *(int*)(param_1 + i*4)   → recompute
                                     ├─ Name heuristics for param_1          → recompute
                                     └─ propagation candidates in callers   → enqueue for review
```

- Invalidation marks facts **dirty**, not deleted; the worklist recomputes them (§19).
- Recompute is **per function** where possible; inter-procedural facts (signatures, types crossing calls) enqueue callers/callees.
- "**Why?**" queries walk the DAG *downwards* (what was this built from?), "**What depends on this?**" walks it *upwards*.

---

## 5. Storage and versioning

### 5.1 On-disk project layout

```
myproject.fulg/
├── project.toml              # settings, list of binaries, analysis options, Fulgurite version
├── blobs/
│   └── 3f9a…e1.bin           # original binary, named by sha256 (immutable, never modified)
├── cache/                    # REGENERABLE — safe to delete, git-ignored
│   └── analysis.sqlite       # inferred facts, IR, CFG, decompiler output (WAL mode)
├── user/                     # HUMAN DECISIONS — plain text, committed to git
│   ├── names.jsonl           # one rename per line
│   ├── comments.jsonl
│   ├── facts.jsonl           # overrides and sticky rejections
│   ├── types/
│   │   ├── packet.h          # user types as real C declarations
│   │   └── _applied.jsonl    # which type is applied where
│   ├── bookmarks.jsonl
│   └── learning/
│       └── progress.jsonl    # Question Mode / practice-mode progress (per user)
└── .gitignore                # ignores cache/ and blobs/ by default (blobs optional via git-lfs)
```

### 5.2 Why three layers

| Layer | Mutable? | In git? | If lost |
|---|---|---|---|
| Blob store | Never | Optional (git-lfs) | Re-add the binary; sha256 must match |
| Analysis cache | Constantly | No | Re-analyse (minutes); no human work lost |
| User layer | On human action | **Yes** | This is the only irreplaceable data |

### 5.3 Record format (user layer)

One JSON object per line, files **kept sorted by anchor**, so two people annotating different
functions produce non-overlapping line diffs that git merges automatically.

```jsonl
{"anchor":{"bin":"3f9a…e1","va":"0x401136","h":"55488bec"},"kind":"name","entity":"func","value":"parse_packet","by":"naved","at":"2026-10-10T12:00:00Z"}
{"anchor":{"bin":"3f9a…e1","va":"0x401136","h":"55488bec"},"kind":"name","entity":"param:0","value":"pkt","by":"naved","at":"2026-10-10T12:01:10Z"}
{"anchor":{"bin":"3f9a…e1","va":"0x4011a0","h":"e8b1feffff"},"kind":"reject","claim":"IsFunction","by":"naved","at":"2026-10-10T12:05:00Z"}
```

### 5.4 Stable anchors

An anchor is `(binary sha256, va, h)` where `h` is a short hash of the bytes at `va`
(first instruction, or 8 bytes for data).

- **Same binary:** `va` is enough; `h` is a sanity check.
- **New build of the binary** (patch diffing, updated malware sample): the **re-binder** uses the function matcher (§16.3) to map old functions to new ones, then re-anchors by function-relative offset + byte hash. Each re-bound annotation becomes a fact with a confidence; low-confidence rebinds go to a review queue rather than being silently applied.

### 5.5 Undo / redo

- Every mutation is an **op** in an append-only op-log: `{seq, op, inverse, affected_facts}`.
- Undo applies `inverse` and replays invalidation; redo re-applies `op`.
- Ops are grouped into **transactions** (e.g. "apply struct to 12 functions" undoes as one step).
- The op-log is per session and lives in the cache; the *result* of ops lands in the user layer as text.

### 5.6 Merge conflicts

Because records are line-oriented and sorted, git conflicts only occur when two people change
the **same entity**. `fulg merge-tool` understands the format: it shows both values, both
authors, and the evidence each one had, and writes the chosen line back.

---

## 6. Loaders (ELF, PE)

### 6.1 Loader contract

```rust
trait Loader {
    fn probe(bytes: &[u8]) -> Option<ProbeResult>;          // magic + sanity, cheap
    fn load(bytes: &[u8], opts: &LoadOpts) -> LoadResult;   // never panics on bad input
}
struct LoadResult {
    image:     MemoryImage,          // segments mapped at chosen base (PIE rebased per opts)
    symbols:   Vec<Symbol>,
    relocs:    Vec<Reloc>,
    imports:   Vec<Import>,
    exports:   Vec<Export>,
    seeds:     Vec<SeedFact>,        // entry, exception-table functions, init/fini arrays, TLS callbacks
    metadata:  FormatMetadata,       // raw header structs for the header views
    mitigations: MitigationReport,   // §6.5
    anomalies: Vec<Anomaly>,         // §6.4
}
```

Every field in `metadata` keeps its **file offset**, so any header view can say
"this value came from bytes at file offset 0x18".

### 6.2 ELF (v1: ELF64 little-endian, x86-64 and AArch64)

| Area | Details handled |
|---|---|
| `e_ident` | magic `7f 45 4c 46`, `EI_CLASS` (2 = 64-bit), `EI_DATA` (1 = little-endian), `EI_OSABI`; mismatches are anomalies, not fatal |
| ELF header | `e_type` (`ET_EXEC` vs `ET_DYN` → PIE detection, plus `DF_1_PIE` flag), `e_machine` (`EM_X86_64` = 62, `EM_AARCH64` = 183), `e_entry` |
| Program headers | `PT_LOAD` → segments; `PT_DYNAMIC`, `PT_INTERP`, `PT_NOTE`, `PT_TLS`, `PT_GNU_STACK` (NX), `PT_GNU_RELRO`, `PT_GNU_PROPERTY` |
| Section headers | optional: **loading uses segments, not sections** (sections can be stripped or forged). Sections are used for naming and extra metadata only |
| Dynamic section | `DT_NEEDED`, `DT_SONAME`, `DT_RUNPATH`, `DT_FLAGS`/`DT_FLAGS_1` (`BIND_NOW`, `PIE`), `DT_INIT_ARRAY`/`DT_FINI_ARRAY` (seeds), `DT_RELR*` |
| Relocations | `REL`, `RELA`, and compressed `RELR` (`.relr.dyn`); applied to the image when rebasing; each reloc site becomes a data-pointer fact |
| Symbols | `.symtab`, `.dynsym`, symbol versioning (`.gnu.version`, `.gnu.version_r`) so `memcpy@GLIBC_2.14` is distinguished from `memcpy@GLIBC_2.2.5` |
| PLT/GOT | classic lazy PLT, `.plt.sec` (CET), **and no-PLT binaries** (`-fno-plt`: calls go `call [rip+GOT]` directly). Import thunks are recognised by pattern, not section name |
| Notes | `.note.gnu.build-id`, `.note.ABI-tag`, `.note.gnu.property` (CET IBT/SHSTK) |
| Unwind | `.eh_frame` / `.eh_frame_hdr` CIEs/FDEs → **function boundary seeds with high confidence** and stack-pointer deltas |
| Debug info (optional) | DWARF 4/5: `.debug_info` (types, variables, params), `.debug_line` (addr→source line), split DWARF where present. Facts get status `Declared` |

### 6.3 PE (v1: PE32+ for AMD64 and ARM64)

The loader itself reads PE32 and PE32+ for every machine type (only the optional header,
thunk size, TLS and load-config layouts differ), so 32-bit x86 and ARMv7 images load
today; the v1 *analysis* targets remain AMD64 and ARM64. Every RVA is resolved through one
image map that applies the Windows loader's rules (raw pointers rounded down to 0x200, raw
size capped by the virtual size, low-alignment images mapped as is).

| Area | Details handled |
|---|---|
| DOS header | `MZ`, `e_lfanew` at offset `0x3C` → NT headers; DOS stub preserved for display |
| NT headers | `PE\0\0` signature; COFF `Machine` (`0x8664` AMD64, `0xAA64` ARM64); `Characteristics` |
| Optional header | magic `0x20B` (PE32+); `ImageBase`, `AddressOfEntryPoint`, `SectionAlignment`/`FileAlignment`, `DllCharacteristics` (`DYNAMIC_BASE` 0x40, `HIGH_ENTROPY_VA` 0x20, `NX_COMPAT` 0x100, `GUARD_CF` 0x4000) |
| Data directories (16) | export, import, resource, **exception**, security, base reloc, debug, TLS, load config, bound import, IAT, **delay import**, CLR (flagged: .NET is out of scope) |
| Imports | by name and by ordinal; IAT slots become typed import facts; delay-load thunks recognised |
| Exception directory | `.pdata` `RUNTIME_FUNCTION` entries → **function boundary seeds** + `UNWIND_INFO` → prologue/stack layout facts |
| TLS | TLS callbacks are entry-point seeds (malware uses them to run before `main`) |
| Load config | security cookie address (→ canary detection), CFG function table (→ valid indirect-call targets = high-confidence function seeds) |
| Debug directory | CodeView RSDS GUID + PDB path; optional PDB loading → `Declared` names/types |
| Rich header | parsed and displayed (toolchain fingerprinting), never trusted for analysis |

### 6.4 Hostile-input rules

Binaries are attacker-controlled input. Loaders follow these rules:

1. **No `unsafe` in loaders.** Every read goes through a bounds-checked cursor; out-of-range is an `Anomaly`, never a panic.
2. **Hard limits**: max sections/segments/symbols/relocs (configurable, defaults e.g. 65 535 sections), max string length, max decompressed size, max recursion depth for nested structures (resources).
3. **Overlaps allowed but flagged**: overlapping segments, sections outside segments, headers inside code. These are real malware tricks; they load, and each produces an anomaly with a confidence-reducing effect on nearby facts.
4. **Two views of truth**: "what the OS loader would do" (segments, `e_lfanew`) is authoritative; "what the metadata claims" (section names) is advisory. Disagreements are shown side by side.
5. **Continuous fuzzing** of every loader (§20.2).

`Anomaly { severity, file_offset, description, os_behaviour }`, e.g.
"section `.text` header claims size 0x5000 but file ends at 0x3200; Linux maps the PT_LOAD
segment regardless, so analysis follows the segment."

### 6.5 Mitigation report (built-in checksec)

Every entry shows **the verdict, the exact evidence and a one-line "why it matters"**.

| Mitigation | ELF evidence | PE evidence | Why it matters (shown to beginners) |
|---|---|---|---|
| PIE / ASLR | `e_type == ET_DYN` (+ `DF_1_PIE`, `PT_INTERP`) | `DYNAMIC_BASE` + base relocs present | Code addresses are randomised, so hard-coded addresses don't work |
| NX / DEP | `PT_GNU_STACK` flags without `X` | `NX_COMPAT` (64-bit code always runs with DEP; a DLL inherits it from its host) | Data on the stack can't be executed as code |
| Stack canary | calls to `__stack_chk_fail` / reads of `fs:0x28` | `/GS` cookie from load config + `__security_check_cookie` | A random value before the return address detects overflows |
| RELRO | `PT_GNU_RELRO` (partial); + `BIND_NOW` (full) | IAT inside a read-only section (the loader restores the section's protection after filling it); delay-load IAT protected by `PROTECT_DELAYLOAD_IAT` + `DELAYLOAD_IAT_IN_ITS_OWN_SECTION` | GOT / IAT can't be overwritten after startup |
| CET / CFG | `.note.gnu.property` IBT/SHSTK, `endbr64` | `GUARD_CF` + `CF_INSTRUMENTED` + CFG table (forward edges); `CET_COMPAT` extended DLL characteristic (shadow stack) | Indirect jumps can only go to marked targets |
| FORTIFY | `__*_chk` imports (e.g. `__memcpy_chk`) | MinGW `__*_chk` functions; MSVC has no equivalent (n/a) | Some buffer functions are bounds-checked |
| Separate code | no W+X segment; executable segments map only code | no W+X section; no data directory inside a code section; not a low-alignment image | Headers and data are not a source of gadgets |
| Library paths | `RPATH` / `RUNPATH` entries (absolute, `$ORIGIN`, relative) | load-config `DependentLoadFlags` (`SEARCH_SYSTEM32`) vs the default search order (application directory first) | Where libraries can be planted |
| SafeSEH | — | x86 only: `NO_SEH`, or the load-config `SEHandlerTable` | Overwritten exception records can only reach registered handlers |

"No canary found" is reported carefully: *no canary-protected function found* ≠ *compiled
without canaries* (the compiler only adds canaries to functions with qualifying buffers). The
report says which one applies.

---

## 7. Architecture modules (x86-64, ARM64)

### 7.1 The `Arch` trait

```rust
trait Arch {
    fn id(&self) -> ArchId;
    fn max_insn_len(&self) -> usize;                       // x86-64: 15, ARM64: 4
    fn decode(&self, bytes: &[u8], va: Va, mode: Mode) -> Result<Insn, DecodeError>;
    fn lift(&self, insn: &Insn, b: &mut LirBuilder);       // THE semantics source of truth
    fn registers(&self) -> &RegisterFile;                  // incl. aliasing
    fn conventions(&self) -> &[CallingConvention];
    fn format(&self, insn: &Insn, syntax: Syntax) -> Tokens; // Intel / AT&T / ARM syntax
    fn idioms(&self) -> &[IdiomPattern];                   // arch-specific prologues, thunks
}
```

*Implemented so far (M0 step 5, `fg-ir`):* `id`, `max_insn_len`, `insn_alignment`, `decode`
and `format`. `Insn` is architecture-neutral (bytes, mode, `Flow` with direct targets,
the explicit memory operand with its resolved address, first immediate, padding flag);
`format` returns typed tokens (mnemonic, register, number, address, symbol, comment...).
`lift`, `registers`, `conventions` and `idioms` join in M1–M2.

Decode and lift are **separate on purpose**: the decoder is table-driven and differentially
tested (§21.1); the lifter is a hand-written semantics function per instruction class that
every downstream consumer reuses (emulator, solver, decompiler, Explain mode).

**Spec-generated semantics (§1.4).** Where a formal model exists, the lifter is *generated*
rather than hand-written: the ARM64 lifter is compiled from Arm's ASL pseudocode (via its Sail
translation), and any future architecture with a Sail model (RISC-V, MIPS…) gets decoder +
lifter from the same generator. The x86-64 lifter is hand-written (no official machine-readable
semantics exists) and checked against the K-framework formal x86-64 semantics as an oracle.

### 7.2 x86-64 decoder

Decode pipeline for one instruction (max 15 bytes; longer is `#UD` and reported as such):

```
[legacy prefixes]* → [REX | VEX(C4/C5) | EVEX(62)] → opcode (1–3 bytes, maps 0F/0F38/0F3A)
                   → ModRM → [SIB] → [displacement 1/4] → [immediate 1/2/4/8]
```

| Detail | Handling |
|---|---|
| Legacy prefixes | 4 groups (lock/rep, segment/branch hints, operand-size `66`, address-size `67`); duplicates and order quirks follow hardware behaviour, not the manual's ideal |
| REX `40`–`4F` | W (64-bit operand), R/X/B (extend reg/index/base to r8–r15); a REX not immediately before the opcode is ignored, matching hardware |
| VEX / EVEX | AVX/AVX2/AVX-512: vector length, `vvvv` register, masking `k0–k7`, embedded broadcast/rounding |
| ModRM `mod=00 rm=101` | **RIP-relative** `[rip + disp32]` in 64-bit mode; the decoder resolves the absolute target and emits a data-xref fact |
| Segment overrides | `fs:`/`gs:` kept (TLS, canary at `fs:0x28` on Linux, TEB/PEB via `gs:` on Windows) |
| Tables | not hand-typed: `iced-x86`'s tables, generated from its own instruction database (§22.4) |
| Syntax | Intel by default (matches `objdump -M intel` after documented spelling normalisation), AT&T available |

**Register aliasing** (the source of many beginner and decompiler bugs):

| Write to | Effect on full 64-bit register |
|---|---|
| `rax` (64-bit) | replaced |
| `eax` (32-bit) | **upper 32 bits zeroed** |
| `ax` (16-bit) | upper 48 bits **preserved** |
| `al` / `ah` (8-bit) | other bits **preserved** |

The lifter models each case explicitly, so `mov eax, edx` lifts to `rax = zext64(edx)` and
data flow never treats the upper half as live garbage.

### 7.3 ARM64 decoder

| Detail | Handling |
|---|---|
| Encoding | fixed 32-bit little-endian, 4-byte aligned; misaligned code is an anomaly |
| Tables | generated from Arm's machine-readable architecture specification (XML/ASL), so coverage tracks new extensions |
| Registers | `x0–x30` / `w0–w30` (writing `wN` **zeroes the upper 32 bits**), `sp`, `xzr`/`wzr` (register 31 means SP *or* zero depending on the instruction: decoder resolves per encoding), `v0–v31` SIMD/FP, `nzcv` flags |
| PC-relative pairs | `adrp x0, page` + `add x0, x0, #off` / `ldr x0, [x0, #off]` are fused by a pass into one address fact (`adrp` gives a 4 KiB page; the pair gives the real address) |
| Branches | `b`, `bl`, `br`, `blr`, `ret`, `cbz/cbnz`, `tbz/tbnz`; `bti` landing pads; PAC instructions (`paciasp`/`autiasp`) recognised as prologue/epilogue markers, not semantics noise |

*Implemented in M0 step 6 (`fg-arch-arm64`):* the tables are generated by
`tools/arm64/gen.py`. The open-source JSON build of the Machine Readable Specification
supplies the decode tree, assembler grammar, alias rules and system registers. The A64
ISA XML supplies operand meanings, value tables, and the decode/post-decode pseudocode,
translated to Rust for the UNDEFINED and CONSTRAINED UNPREDICTABLE checks. The XML is
not stored in the repository. The `adrp` pair is resolved for PLT stubs; the general
fusion pass comes with M1.

### 7.4 Calling conventions

```rust
struct CallingConvention {
    name: &'static str,
    int_args: &'static [Reg], float_args: &'static [Reg],
    int_ret: &'static [Reg],  float_ret: &'static [Reg],
    callee_saved: &'static [Reg],
    stack_align_at_call: u8,
    shadow_space: u16,           // MS x64: 32 bytes
    red_zone: u16,               // SysV: 128 bytes
    stack_cleanup: Cleanup,      // Caller for all v1 conventions
}
```

| Convention | Integer args | Return | Callee-saved | Stack notes |
|---|---|---|---|---|
| **SysV x86-64** (Linux ELF) | `rdi, rsi, rdx, rcx, r8, r9` | `rax` (`rdx:rax` for 128-bit) | `rbx, rbp, r12–r15` | 16-byte aligned at `call`; 128-byte red zone below `rsp` |
| **Microsoft x64** (PE) | `rcx, rdx, r8, r9` | `rax` | `rbx, rbp, rdi, rsi, r12–r15, xmm6–xmm15` | 32-byte shadow space reserved by caller |
| **AAPCS64** (ARM64 ELF/PE) | `x0–x7` (`x8` = indirect result) | `x0` (`x0:x1`) | `x19–x28`, `x29` (FP), low 64 bits of `v8–v15` | 16-byte aligned `sp`; `x30` = link register |
| **Go ABIInternal (amd64)** | `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11` | same set | none (Go-specific) | Selected by the Go frontend (§10.9), not by default |

Convention selection is itself a **fact** (`Conv(func, SysV)`, confidence from format + observed
register usage), so a Windows binary with a hand-written SysV helper is representable.

---

## 8. Disassembly and CFG recovery

### 8.1 Strategy: recursive descent, guided by evidence

```
seeds (with confidence) ─► worklist ─► decode block ─► successors ─► worklist
                                            │
                                            ├─ direct call  → new function seed
                                            ├─ direct jump  → same-function block
                                            ├─ indirect     → resolver (§8.3)
                                            └─ ret / noreturn call → block end
gaps remaining ─► guided linear sweep (low-confidence candidates only)
```

### 8.2 Seed sources and their starting confidence

| Seed | Status | Confidence |
|---|---|---|
| ELF/PE entry point | Declared | 1.0 |
| Exported / `.symtab` function symbols | Declared | 0.98 |
| `.eh_frame` FDEs / `.pdata` `RUNTIME_FUNCTION` | Declared | 0.97 |
| PE CFG table targets, `init_array`/`fini_array`, TLS callbacks | Declared | 0.95 |
| Direct `call` targets from already-trusted code | Inferred | 0.95 × caller confidence |
| Pointers in data that land in executable segments *and* decode cleanly *and* are aligned | Inferred | 0.5–0.8 |
| Prologue patterns (`endbr64; push rbp; mov rbp,rsp`, `paciasp; stp x29,x30,…`) in gaps | Inferred | 0.4–0.7 |
| Linear-sweep candidates in gaps | Inferred | ≤ 0.4 |
| Executed in a trace | Observed | 1.0 for the executed bytes |

### 8.3 Indirect control flow

| Case | Approach |
|---|---|
| **Switch jump tables** (`jmp [base + idx*8]`, or ARM64 `adr` + `ldrb/ldrh` + `add` + `br`) | Value-set analysis on the index (§10.4) finds the bound from the preceding `cmp/ja`; table entries are read, validated (land in code, inside function), and become `Edge` facts. Unbounded index ⇒ edges are low-confidence and the block is flagged "unresolved indirect" |
| **Tail calls** (`jmp other_func`) | `jmp` to a known function entry, with the stack pointer at its entry value ⇒ `TailCall` edge, not an intra-function edge |
| **Calls through GOT/IAT** | resolved to the import symbol |
| **vtable calls** (`call [rax + 0x18]`) | C++ frontend (§10.9) links the slot to candidate implementations; edges are `Inferred` with the candidate set |
| **Function pointers in general** | VSA candidates; otherwise left unresolved, visibly |
| **Anything** | trace evidence turns any observed indirect target into an `Observed` edge |

### 8.4 No-return analysis

A call that never returns ends its block, otherwise the next bytes are wrongly decoded as the
fall-through. Sources: import names (`exit`, `_exit`, `abort`, `__stack_chk_fail`,
`__assert_fail`, `ExitProcess`), plus a fixed-point analysis: a function is no-return if
every path ends in a no-return call or an infinite loop. Changing a no-return fact invalidates
every caller's CFG (via the DAG). What the analysis does not understand (an unresolved indirect
jump, undecodable bytes, a call into the function's own code) may return: a wrong no-return
claim hides the code after every call, a missed one only decodes a few bytes too many.

### 8.5 Overlapping instructions and code-vs-data conflicts

- The block graph is keyed by **(va, decoding)**, so two different decodings of overlapping bytes can coexist (an anti-disassembly trick).
- When `IsCode` and `IsData` claims overlap, both remain as facts; the higher-ranked wins for display (§4.4) and the loser is shown as a dotted alternative ("these bytes also decode as a jump table entry").
- **This is where the undecidability shows**: the UI never pretends it has a definite answer for low-confidence regions.

---

## 9. IR stack

### 9.1 Three tiers

| Tier | What it is | Example for `add eax, 0x1` |
|---|---|---|
| **LIR** (lifted) | 1:N per machine instruction; explicit flags; registers as full-width variables with sub-register ops | `t0 = trunc32(rax) + 0x1; rax = zext64(t0); ZF = t0 == 0; SF = t0 <s 0; CF = …; OF = …` |
| **MIR** (medium) | flags eliminated where unused; stack slots become variables; calls carry arguments/returns per convention; SSA available | `v3 = v2 + 1` |
| **HIR** (high) | structured control flow (if/while/switch), nested expressions, typed variables | `return arr[i] * 3 + 1;` |

Each tier has an **SSA form** (`*.ssa`) built with the Braun et al. algorithm, which builds SSA
directly during construction and fits incremental re-lifting.

### 9.2 LIR operation set (summary)

```
arith:   add sub mul umulh smulh udiv sdiv urem srem neg
bits:    and or xor not shl lshr ashr rol ror
width:   zext sext trunc  extract(hi,lo)  concat
compare: eq ne ult ule slt sle
memory:  load(size, addr)  store(size, addr, val)
control: jump(target)  branch(cond, t, f)  call(target, conv?)  ret  jump_indirect(addr)
special: intrinsic(name, args)  // e.g. cpuid, syscall, rdtsc, SIMD ops not yet modelled
         undefined(width)       // architecturally undefined flags/results
```

Every LIR op has **exact bit-precise semantics**; that one definition drives the emulator,
the SMT encoding and the plain-English explanations.

### 9.3 Provenance on every node

```rust
struct IrNode {
    id: IrNodeId,
    op: Op,
    args: SmallVec<[IrNodeId; 3]>,
    origin: Origin,
}
struct Origin {
    insns: SmallVec<[Va; 2]>,      // machine instructions this came from
    pass: PassId,                  // pass that created or last rewrote it
    rewrite_of: Option<IrNodeId>,  // previous form, if rewritten (chain = history)
}
```

Following `rewrite_of` from any HIR token back to LIR gives the **full transformation
history**. This is what powers Explain-why (§15.5).

**Provenance on demand.** Storing every intermediate node forever would cost memory. Only the
compact `Origin` ids are kept; when a user asks "why?", the function's passes are **re-run
deterministically** with full logging on, reproducing the exact chain. Determinism (§9.4) is
what makes this sound: the replay is bit-identical to the original run.

### 9.4 Pass manager

```rust
trait Pass {
    fn id(&self) -> PassId;
    fn tier(&self) -> Tier;
    fn requires(&self) -> &[FactKind];    // inputs, declared
    fn produces(&self) -> &[FactKind];    // outputs, declared
    fn run(&self, f: &mut FunctionIr, facts: &FactView, log: &mut ExplainLog) -> PassResult;
}
```

- Passes **declare inputs and outputs**, so the scheduler can order them and the DAG can invalidate precisely.
- Every rewrite writes an **explain-log entry**: `{pass, before, after, reason}`, e.g.
  `mul_idiom: (x + x) + x → x * 3  [reason: repeated addition of the same SSA value]`.
- Passes are deterministic. Same inputs give the same outputs, which makes caching and testing sound.
- Third-party passes (§16.5) use the same trait through the plugin host.
- **Translation validation.** After a pass rewrites a region, an equivalence query
  `before ≡ after` (bit-vector SMT, Alive2-style) is sent to the solver worker (§14). Modes:
  `always` (slow, maximum trust), `sampled` (default: random subset plus every rewrite in
  functions the user is viewing), `ci-only` (the corpus run). A failed proof discards the rewrite,
  logs a counterexample, and files a pass bug automatically. Validated rewrites carry a ✓ in
  Explain-why.

---

## 10. Analyses

### 10.1 Pipeline order (per function, default)

```
lift → SSA(LIR) → stack-pointer tracking → flag elimination → MIR
     → const-prop + DCE → VSA → calls/conventions → SSA(MIR)
     → type inference → idioms → language frontend passes
     → (optional) deobfuscation passes → HIR → decompiler (§11)
```

### 10.2 Constant propagation and dead-code elimination

Sparse conditional constant propagation on SSA. Dead flag computations are the bulk of what
it removes (most LIR flag writes are never read). DCE never removes stores to memory or
calls with unknown effects.

### 10.3 Stack-pointer tracking

Tracks `rsp`/`sp` as `entry_sp + delta` through each block. Produces:
- stack-frame layout facts (locals at `entry_sp − 0x40` etc.), which the stack-frame diagram uses (§15.4);
- a `StackImbalance` anomaly when paths disagree (common in obfuscated code or bad CFGs);
- verification against `.eh_frame`/`UNWIND_INFO` CFA rules where present (disagreement lowers confidence).

### 10.4 Value-set analysis (VSA)

Abstract interpretation over memory regions (global, stack-frame, heap allocation-site), with
strided intervals as values (Balakrishnan & Reps). Used for jump-table bounds, pointer
targets, and which memory region an access touches. Results become `Value` facts with
confidence reflecting widening (precision lost → confidence lowered).

### 10.5 Type inference

- **Constraint generation** from: loads/stores (size → `int8..int64`), pointer arithmetic (`base + i*4` ⇒ pointer to 4-byte elements), comparisons (signed vs unsigned compare instructions → signedness), library calls with known prototypes (`strlen(x)` ⇒ `x: const char *`), returns.
- **Solving** over a subtyping lattice (in the style of TIE and Retypd), producing the most specific type consistent with the constraints.
- **Each solved type is a fact** whose evidence lists the constraints that forced it: *"`int *` because: 4-byte load at `[p + i*4]` (0x401018); passed to function expecting `int *` (0x401090)"*.
- **Unconstrained** slots stay `undefinedN` (as Ghidra does) **with confidence shown as `guess`**, not dressed up as `long`.

### 10.6 Struct recovery

From accesses `[p + 0x0]` (8-byte), `[p + 0x8]` (4-byte), `[p + 0x10]` (8-byte, passed to `free`)
on one base pointer, propose `struct anon_401136 { u64 f0; u32 f8; /* pad 4 */ void *f10; }`.
The proposal shows **padding explicitly**, and the struct editor runs the
**sum check** (last offset + last size, rounded to alignment = `sizeof`) live while editing.

### 10.7 Idiom recognition

| Idiom | Machine pattern | Rewritten to |
|---|---|---|
| Multiply by constant | `lea eax,[rdx+rdx*2]` or `add eax,eax; add eax,edx` | `x * 3` |
| Unsigned divide by constant | `imul`/`mul` by magic number + shift (e.g. `x * 0xAAAAAAAB >> 33` for 32-bit `x / 3`) | `x / 3` |
| Modulo by constant | divide idiom + multiply + subtract | `x % n` |
| Inlined `strlen` / `memset` / `memcpy` | loop or `rep stos`/`rep movs` | library call form |
| Bit tests | `test al, 1` / `tbz` | `x & 1` |
| Boolean materialisation | `setcc` / `cset` | `(a < b)` |
| Switch | bounds check + table jump | `switch` |
| Stack canary | `mov rax, fs:0x28` … `xor` … `call __stack_chk_fail` | hidden in HIR, shown as a `/* canary */` marker |

Every rewrite logs its reason (§9.4), so **beginners can learn the patterns from the tool**
rather than having them silently disappear.

**Engine: e-graphs.** Idioms and algebraic simplifications are rewrite rules applied by
**equality saturation** (the `egg` library): all rules fire into one e-graph of equivalent forms,
then a readability cost model extracts the best form. This removes rule-ordering bugs, finds
simplifications that sequential rule chains miss, and every applied rule is individually
checkable by translation validation.

### 10.8 Library function matching

Two-level signatures, built by compiling known library versions (glibc, musl, MSVC CRT, libstdc++, OpenSSL…):

1. **Byte pattern with wildcards**: relocated operands and absolute addresses masked out (the FLIRT idea), very fast first filter.
2. **MIR semantic hash**: normalised MIR (register names canonicalised, constants kept), robust to register allocation differences.

A match is a `LibraryMatch` fact; multiple candidates are kept with confidences (e.g. three
glibc versions that compile `memcpy` identically) instead of picking one silently.

**Building the database (§1.4).** A **compilation farm** rebuilds common libraries and distro
packages across compiler versions and `-O` levels; **debuginfod** supplies symbols for real
distro binaries so signatures come from what actually ships. Open external formats (e.g. WARP)
are importable where licensing allows. The database is versioned and regenerated automatically,
not hand-curated.

### 10.9 Language frontends

| Language | Detection | Recovery |
|---|---|---|
| **C++ (Itanium ABI)** | `_Z` mangled symbols, `__cxa_*` imports | demangling; vtables via `_ZTV*` and RTTI `_ZTI*`; virtual-call slot → class method; `this` as first param |
| **C++ (MSVC)** | `?` mangled symbols | demangling; RTTI Complete Object Locator → class hierarchy; vtables |
| **Go** | `.gopclntab` section or pclntab magic in data (version-specific magic values) | function names and boundaries from pclntab (works on stripped binaries); Go ABIInternal convention; strings as `(ptr, len)`; slices as `(ptr, len, cap)`; interfaces as `(itab, data)`; runtime calls (`runtime.morestack`, `runtime.panicIndex`) hidden or annotated |
| **Rust** | `_ZN…17h<hash>E` legacy or `_R` v0 mangling; panic-location data referencing `.rs` paths | demangling; `&[T]`/`&str` as `(ptr, len)`; `Option`/`Result` niche-encoded enums; panic paths (bounds checks, `unwrap`) collapsed to annotations so the real logic is visible |

Frontends are **passes** like any other: they produce facts with evidence, and they can be disabled.

### 10.10 Deobfuscation passes (opt-in)

| Pass | Detects | Does |
|---|---|---|
| `cff_detect` / `unflatten` | dispatcher block with very high in-degree + a state variable compared against constants | tracks the state variable symbolically per block, reconstructs the original edges |
| `opaque_pred` | branch whose condition is provably constant | SMT query (§14) proves the condition always true/false; dead edge removed with proof attached as evidence |
| `mba_simplify` | mixed boolean-arithmetic expressions | simplifies via algebraic rewriting + SMT equivalence check |
| `junk_insns` | instructions with no effect on live state | removes, with DCE justification |

Every deobfuscation pass runs in **preview mode** first: before/after IR diff, then accept or discard.

---

## 11. Decompiler

### 11.1 Stages

```
MIR(SSA) ──► expression propagation ──► variable recovery (out of SSA)
         ──► control-flow structuring ──► type-cast minimisation
         ──► naming ──► token AST (every token → IrNodeId → provenance)
```

### 11.2 Control-flow structuring

1. Build dominator and post-dominator trees; detect loops (natural loops + Havlak's algorithm for irreducible regions).
2. **Pattern-independent structuring** (in the style of *No More Gotos*): for each single-entry region, compute the reaching condition of every node and emit `if`/`else`/`while`/`do-while`/`switch` from those conditions, rather than matching a fixed list of shapes.
3. Phoenix-style iterative refinement for regions that fail.
4. **Fallback**: a `goto` only where the region is truly irreducible, and the `goto` carries a visible marker: *"irreducible flow: original control flow could not be structured"*.
5. **Search + verify (§1.4).** Steps 2–3 produce *several* candidate structurings (different
   loop-exit choices, condition orderings, switch recovery). Each is scored with a readability cost
   (gotos, nesting depth, variable count, expression size) and checked equivalent to the CFG; the
   cheapest verified candidate is emitted. Alternatives remain viewable.

### 11.3 Expression propagation

Inline single-use SSA values into their uses when no intervening store may alias the loaded
memory (alias facts from VSA). This is what folds 14 instructions into one line, and it is
the main place decompilers go wrong, so every fold is logged.

### 11.4 Variable recovery

- Out-of-SSA via live-range interference: SSA versions that never interfere merge into one variable.
- Stack slots become locals; their frame offsets are kept as metadata (shown on hover: `local_40 @ rbp-0x40`).
- When merging is ambiguous, prefer **more variables** (correct but verbose) over fewer (compact but wrong).

### 11.5 Naming heuristics (each a fact with evidence)

| Source | Example |
|---|---|
| Symbols / DWARF / PDB | real names (`Declared`) |
| Library prototypes | arg 1 of `open` → `path`; return of `open` → `fd` |
| Loop shape | induction variable → `i`, `j` |
| Struct field types | `pkt->len` |
| String references | function only references `"usage: %s <file>"` → suggests `print_usage` (low confidence) |
| AI suggestions | §17, always reviewed |
| Fallback | `param_1`, `local_40` (position/offset-based, never fake-meaningful) |

### 11.6 Output

- The decompiler emits a **token AST**: `{text, kind (keyword/var/type/literal/op), node: IrNodeId, confidence}`. The UI renders this, not a string, so every token is clickable and carries its confidence.
- **C mode** (default) and **language-flavoured modes** when a frontend is active (Rust-ish `match`, Go-ish multiple returns). These are display modes over the same HIR, not separate decompilers.

---

## 12. Confidence system

### 12.1 Scale

Confidence is an `f32` in `[0, 1]`, always displayed through **four buckets** (exact numbers on hover):

| Bucket | Range | Meaning | Default UI encoding |
|---|---|---|---|
| **Certain** | 1.0 | From the format spec, a user decision, or an observed execution | plain text |
| **Strong** | 0.80 – 0.99 | Multiple independent pieces of evidence agree | plain text, small ● marker in the gutter |
| **Weak** | 0.50 – 0.79 | One piece of evidence, or evidence with known false positives | dotted underline + ◐ marker |
| **Guess** | < 0.50 | Default/fallback, unconstrained, or heuristic only | faded text + dashed underline + ○ marker |

Encoding is **never colour-only** (underline style + glyph), so it survives colour-blindness and monochrome themes.

### 12.2 Combining evidence

- **Independent supporting evidence** combines by noisy-OR: `c = 1 − Π(1 − wᵢ)`. Two 0.6 pieces of evidence give 0.84.
- **Derivation chains** take the weakest link: a fact derived from inputs `a, b` has confidence ≤ `min(c_a, c_b) × c_pass`. A strong type built on a guessed function boundary stays a guess.
- **Contradicting evidence** subtracts: `c' = c × (1 − w_contra)`.
- **Observed** facts are 1.0 *for what was observed* (this target was reached), not for generalisations (this is the *only* target). Those stay inferred.

### 12.3 Where pass weights come from

Each pass declares base weights per evidence kind. They are **calibrated**, not invented:
run the pass over the ground-truth corpus (§21.4), measure precision per evidence kind, and set
the weight to the measured precision. Weights ship with the release and are versioned.

**Conditioning.** Weights are calibrated **per fact kind × compiler family × optimisation level**,
because heuristics behave very differently on `gcc -O0` and `clang -O3`. The compiler is
detected from the ELF `.comment` section (e.g. `GCC: (GNU) 16.2.1`), the PE Rich header, or
code-shape classifiers; unknown compilers fall back to pooled weights (wider uncertainty).

### 12.4 Calibration target

A reliability diagram over the corpus: of all facts the tool labels ≈0.7, about 70% should be
correct. **Over-confidence is treated as a bug** (a release-blocking regression metric, §21.5),
because confident wrong output is exactly what misleads beginners.

### 12.5 Confidence in aggregate views

- Function list: per-function "analysis health" = share of HIR tokens at Strong or above; sort by lowest health to see where the tool needs a human.
- Minimap/scrollbar: a strip showing low-confidence regions of the binary.
- "**Weakest facts here**" button on any function: lists its lowest-confidence facts with the evidence that would raise them (e.g. "run a trace through this block").

---

## 13. Dynamic integration

### 13.1 Principle

An execution is **evidence**. Traces and debugger sessions write `Observed` facts into the same
store the static analysis uses, so the static view gets better every time code runs.

### 13.2 Emulator

- Interprets **LIR** directly (no second semantics implementation; §0.4 principle 2).
- Memory: sparse paged model with permissions from the loader; unmapped access = fault event (not a crash of the tool).
- **Linux syscall layer** for the common subset (`read`, `write`, `open(at)`, `close`, `mmap`, `munmap`, `brk`, `exit(_group)`, `getrandom`, …) with a virtual filesystem and configurable stdin. Unsupported syscalls stop emulation with a clear message.
- **Windows**: v1 provides stub hooks for common imports (`GetProcAddress`, `VirtualAlloc`, `LoadLibraryA`…) that users and plugins can extend. Full OS emulation is a non-goal.
- Budgets: instruction count, wall time, memory. Hitting a budget gives a partial trace, never a hang.
- Snapshots: save/restore the full emulator state (used by "re-run from here with different input").

### 13.3 Debugger backends

| Backend | Use |
|---|---|
| **GDB Remote Serial Protocol client** | talks to `gdbserver`, QEMU's gdbstub (both architectures, incl. foreign-arch user-mode), and **`rr replay`** (which speaks the same protocol: record-and-replay time travel for free) |
| **ptrace (Linux, native)** | low-latency local debugging inside the sandbox (§20.3) |
| **Windows debug API** | native PE debugging (v1.1) |

All backends implement one trait (`attach`, `step`, `continue`, `breakpoints`, `read/write regs/mem`, `events`).

### 13.4 Trace format

```rust
struct TraceStep {
    seq: u64,
    pc: Va,
    reg_writes: SmallVec<[(Reg, u64); 4]>,
    mem_writes: SmallVec<[(Va, u8 /* size */, u64 /* old */, u64 /* new */); 2]>,
    mem_reads:  SmallVec<[(Va, u8); 2]>,        // optional, larger traces
}
```

- Stored in chunked, compressed files (`zstd`), with keyframes (full register state) every N steps for fast seeking.
- **Index**: for each written address, a sorted list of `seq` numbers. *"Who last wrote `0x7ffd1230` before step 1832?"* is a binary search, answered instantly.
- Traces from external tools (e.g. a QEMU plugin or a Pin/DynamoRIO tool) are importable through a documented converter format.

### 13.5 What traces feed back

| Observation | Becomes |
|---|---|
| Bytes executed | `IsCode` Observed (and conflicting `IsData` facts drop in rank) |
| Indirect jump/call targets taken | `Edge` Observed |
| Values in registers/memory | `Value` Observed at that IR node → overlay in pseudocode (`len /* = 72 at step 1832 */`) |
| Functions entered | `IsFunction` Observed, plus coverage |
| Branches taken/not taken | coverage colouring in graph view |

### 13.6 Time-travel UI

- Timeline scrubber under any view; dragging it moves the "current step".
- Registers/stack/heap panels show state at the current step.
- **"Who last wrote this?"** on any memory byte or register → jumps to the writing instruction.
- **"Where did this value come from?"** → backwards data-flow over the trace (dynamic slicing), shown as a chain of steps.

---

## 14. Symbolic queries

### 14.1 Engine

- Symbolically executes **MIR** (smaller than LIR, flags already eliminated where unused).
- Encodes to SMT bit-vector theory; **Bitwuzla** as the default solver (strong on bit-vectors), **Z3** as a fallback. Both run in the solver worker process (§3.2).
- Memory model: concrete addresses where VSA proves them; symbolic addresses resolved over a bounded candidate set; the rest marks the result as "under-approximated".
- Inputs: `stdin`, `argv`, file contents, return values of chosen calls, or any user-marked memory/register.

### 14.2 Query types

| Query | Example (UI / CLI) | Answer |
|---|---|---|
| **Reach** | right-click block → *Find input that reaches here* / `fulg ask reach 0x401234` | concrete input, or "unreachable (proved)", or "unknown within budget" + the blocking constraint |
| **Can** | right-click `memcpy` → *Can `len` exceed 64?* | yes (with an input), no (proof), unknown |
| **Equivalence** | *Is this expression equal to that one?* (used by deobfuscation) | yes / no + counterexample |
| **Constant branch** | *Is this branch always taken?* (opaque predicates) | proof or counterexample |

### 14.3 Path explosion budgets

- Budgets on time, number of states, solver memory and loop unrolling depth.
- Strategies: directed search toward the target (distance on the CFG), state merging at join points, function summaries for known library calls (`strlen`, `memcmp`…).
- **Partial answers are first-class**: "reached the target under the assumption that `rand()` returns 0", or "stuck in loop at 0x401300 (unrolled 64×)". The tool never just says "timeout".
- Found inputs can be run immediately in the emulator to confirm them, and confirmation upgrades the path to `Observed`.

---

## 15. Beginner layer

### 15.1 Why this layer exists

Beginners don't lack the *data*; tools print everything. They lack the **question**. Given
a question ("did the range change?", "did the distance between these two change?") a beginner
can find the answer. Without one, a whole binary is noise. The beginner layer supplies the
question, points at the rows that answer it, dims the rest, and gradually hands the job of
asking back to the user.

### 15.2 Question Mode

#### 15.2.1 Question spec format

Questions are data files (TOML), shipped in a catalog and extendable by users and teachers.

```toml
[question]
id          = "elf.is_pie"
text        = "Is this binary position-independent (PIE)?"
level       = 0                      # 0 = first week, 1 = after asm basics, 2 = exploitation
applies_to  = { format = ["elf"] }
prerequisites = []
tags        = ["mitigations", "header"]

[[step]]
view        = "elf.header"
highlight   = "field in ['e_type']"
dim_rest    = true
look_at     = "The Type: row."
derive      = "EXEC means fixed addresses (not PIE). DYN means it can be loaded anywhere (PIE, or a shared library)."

[[step]]
view        = "elf.dynamic"
highlight   = "tag == 'DT_FLAGS_1'"
dim_rest    = true
look_at     = "The FLAGS_1 entry."
derive      = "If it contains PIE, this DYN file is an executable, not a library."

[answer]
from        = "mitigations.pie"      # the tool knows the real answer
check_user  = true                   # ask the user first, then reveal
explain     = "PIE matters because with ASLR the code's addresses change every run, so an exploit can't hard-code them."

[[followup]]
id = "elf.is_stack_executable"
```

#### 15.2.2 Selector language (`highlight = …`)

A small, safe expression language over view rows: `field`, `tag`, `flags contains 'X'`,
`segment.perms == 'RWX'`, `insn.mnemonic in ['call']`, `call.target.name matches 'gets|strcpy|read'`,
`addr in range(a, b)`. Selectors are evaluated by the query engine; no plugin code runs.

#### 15.2.3 Flow

```
Welcome panel / "Ask" button ─► catalog (filtered by format, arch, level, what's present)
   ─► step cards: LOOK AT → (user looks) → WHAT TO DERIVE
   ─► user types or picks their answer ─► tool reveals its own answer + evidence
   ─► follow-up questions offered
```

#### 15.2.4 Fading the support

| Level | Behaviour |
|---|---|
| **Guided** | Tool proposes the question and highlights the rows |
| **Hinted** | Tool proposes the question; user finds the rows; "show me" button available |
| **Self-directed** | User must type their *own* question before running a view; the tool suggests a related catalog entry afterwards ("you asked X; experts also check Y") |

Progress per question is stored in `user/learning/progress.jsonl` (§5.1), so the level
can rise per topic, not globally.

#### 15.2.5 Starter catalog

Worked example (complete, follows the spec above):

| id | Question | View → rows highlighted | What to derive |
|---|---|---|---|
| `elf.is_pie` | Is this binary PIE? | ELF header → `Type:`; dynamic → `FLAGS_1` | `EXEC` = fixed addresses; `DYN` + `PIE` flag = randomised |
| `elf.is_stack_executable` | Can code run from the stack? | Segments → the `GNU_STACK` row, `Flags` column only | `RW` = stack not executable (NX on); `RWE` = shellcode placed on the stack could run |
| `elf.got_writable` | Can the GOT be overwritten after startup? | Segments → `GNU_RELRO` row; Dynamic → `FLAGS` (`BIND_NOW`) and `FLAGS_1` (`NOW`) | no `GNU_RELRO` = no RELRO; `GNU_RELRO` without `BIND_NOW` = partial (GOT still writable); both = full (read-only after startup) |
| `fn.has_canary` | Does this function have a stack canary? | Listing of the function → prologue `mov rax, QWORD PTR fs:0x28` and epilogue `call __stack_chk_fail` | both present = an overflow is detected before `ret`; absent here doesn't mean the whole binary lacks canaries (only functions with buffers get one) |
| `input.where_enters` | Where does user input enter the program? | Imports → `read`, `fgets`, `gets`, `scanf`, `recv`; Listing → their call sites with the argument registers (`rdi`, `rsi`, `rdx`) | which buffer receives input, and its size limit (`gets` has none; for `read` the limit is `rdx`) |
| `frame.distance_to_ret` | How far is this buffer from the saved return address? | Stack-frame view → the buffer row and the return-address row | distance = return-address start − buffer start (e.g. `rbp+0x8 − (rbp−0x40) = 0x48`): the number of bytes an overflow must write to reach it |
| `strings.what_it_says` | What does the program print or check for? | Strings view, referenced-only filter → each string's xref | usage/error/success messages name the functions that handle them; `"Correct!"`-style strings mark the goal block |

### 15.3 Hex "shape" highlighting

In hex and memory views, a **Shapes** toggle highlights patterns instead of making the user decode values:

| Shape | Rule (x86-64 Linux defaults; per-OS/arch tables) | Meaning shown on hover |
|---|---|---|
| Stack-looking pointer | 8-byte value `0x00007ffc…`–`0x00007fff…` | "Probably points into the stack" |
| PIE/heap-looking pointer | `0x000055…`/`0x000056…` | "Probably points into the program (PIE) or the heap" |
| Non-PIE pointer | `0x0000000000400000`–`0x0000000000ffffff` in a non-PIE binary | "Probably points into the program's code/data" |
| Library pointer | `0x00007f…` (below the stack range) | "Probably points into a shared library (libc)" |
| Zero runs | ≥ 4 consecutive `00` | "Padding, unused or zeroed memory" |
| Printable text | runs of `0x20`–`0x7e` (+ `\n` `\t`), ≥ 4 bytes | "Probably a string": decoded inline |
| Repeated input | runs of the same byte, e.g. `41 41 41 41` | "Repeated byte: often your own test input (`AAAA`)" |
| Canary-looking value | 8 bytes, low byte `00`, high entropy, sitting just below a saved frame pointer | "Possibly a stack canary" |

When a live process or trace exists, shapes are **checked against the real memory map** and
the guess becomes a fact ("this *is* a stack address: it lies inside `[stack]`").

### 15.4 Explain mode

- **Instruction semantics in plain English**, generated from the instruction's **LIR** (so the explanation always matches what the tool actually models):

  | Instruction | LIR | Explanation |
  |---|---|---|
  | `lea rax, [rbp-0x20]` | `rax = rbp - 0x20` | "rax = the address 32 bytes below rbp. **No memory is read**: `lea` only computes an address." |
  | `mov eax, DWORD PTR [rbp-0xc]` | `rax = zext64(load32(rbp - 0xc))` | "Read 4 bytes from the stack at rbp−12 into eax; the upper half of rax becomes 0." |
  | `cdqe` | `rax = sext64(trunc32(rax))` | "Sign-extend eax to 64 bits: a negative int stays negative as a 64-bit value." |
  | `add eax, eax` | `rax = zext64(eax + eax)` | "eax = eax × 2 (adding a value to itself)." |

- **Live register panel**: values before/after the selected instruction (from emulator/trace when available, symbolic otherwise: `rax = param_2 * 4`).
- **Stack-frame diagram**, built from stack tracking (§10.3) plus types:

  ```
  scale(int *arr, int i)  — leaf function: rsp == rbp, locals live in the red zone (no `sub rsp`)

  higher addresses        start      end        size (end − start + 1)
  ┌───────────────────┐
  │ return address    │   rbp+0x8 .. rbp+0xf    8
  ├───────────────────┤
  │ saved rbp         │   rbp+0x0 .. rbp+0x7    8
  ├───────────────────┤ ◄── rbp, rsp
  │ arr   : int *     │   rbp-0x8 .. rbp-0x1    8
  ├───────────────────┤
  │ i     : int       │   rbp-0xc .. rbp-0x9    4
  └───────────────────┘
  lower addresses         distance arr → return address: 0x8 − (−0x8) = 0x10 bytes
  ```

  Every range displays **start, end and `last − first + 1` size**, so the fencepost is always written down.
  The example is the real `-O0` layout of `scale()` from `objdump`: `arr` saved at `[rbp-0x8]`, `i` at `[rbp-0xc]`.

### 15.5 Explain-why on pseudocode

Click any token or line → a panel showing:

1. **Source instructions** (highlighted in the listing): the 14 instructions behind `return arr[i] * 3 + 1;`.
2. **Transformation chain** from the explain log (§9.4), oldest first:
   - `lift`: 14 instructions → 23 LIR ops
   - `flag_elim`: 11 flag writes removed (never read)
   - `stack_vars`: `[rbp-0x8]` → variable `arr`, `[rbp-0xc]` → `i`
   - `mul_idiom`: `(x + x) + x` → `x * 3`
   - `ptr_arith`: `arr + sext(i) * 4` with `arr: int *` → `arr[i]`
3. **Facts used** and their confidence: `Type(arr, int *)` *weak: from one 4-byte scaled access*.
4. **"What would change this?"**: e.g. "retype `arr` as `char *` → this line becomes `*(int *)(arr + i * 4)`".

### 15.6 Ground-truth practice mode

1. User picks or writes a C file (or picks from a bundled exercise set).
2. Fulgurite compiles it **twice** with the system compiler: `-g` (ground truth) and stripped, at a chosen optimisation level (`-O0` → `-O2` as the user improves). On Arch-like systems it notes defaults (e.g. stack protector on by default) and shows the exact flags used.
3. **Alignment view**: from the `-g` build's `.debug_line`, every source line maps to its instructions. Clicking a C line highlights its assembly (like Compiler Explorer, inside the RE tool).
4. **Challenge**: open the stripped build; the user recovers function names, parameter types, struct layouts.
5. **Score** against DWARF: function boundaries (exact), types (exact or compatible), struct offsets (exact), names (semantic match, lenient). Mistakes link back to the evidence the user missed.

### 15.7 Progressive disclosure

| Profile | Shown by default | Hidden until enabled |
|---|---|---|
| **Learn** | Welcome panel, Question Mode, listing + pseudocode side by side, Explain mode, shapes, checksec | IL tiers, solver, scripting console, deobfuscation |
| **Standard** | listing, graph, pseudocode, xrefs, types, strings, debugger | IL tiers, scripting console |
| **Expert** | everything, including IL tiers (LIR/MIR/HIR and SSA), solver console, pass manager, explain log | — |

Profiles change the **default layout only**. Nothing is locked; every feature is one command-palette search away.

---

## 16. Advanced layer

### 16.1 Type propagation with review

1. User applies a type at one site.
2. The propagation engine finds candidates: same allocation site, same access-pattern signature (set of `(offset, size)` pairs), flows through calls (argument → parameter → callee).
3. Each candidate gets a confidence and a **diff of its pseudocode before/after**.
4. Review queue: accept all ≥ Strong, step through Weak, ignore Guess. Rejections are sticky (§4.4).
5. The whole batch is one undo transaction.

### 16.2 Scripting and headless use

```python
import fulgurite as fulg

proj = fulg.open("crackme.fulg")
for f in proj.functions(health_below=0.5):          # least-confident functions first
    print(f.name, f.entry, f.health)
    for fact in f.weakest_facts(limit=3):
        print("   ", fact.claim, fact.confidence, fact.evidence[0].text)

main = proj.function("main")
print(main.decompile().text)
print(main.il("mir", ssa=True))

r = proj.solve.reach(target=0x401234, start="main", stdin_len=32, budget_s=30)
print(r.status, r.input)
```

- The CLI `fulg` exposes the same operations (`fulg open`, `fulg ls funcs`, `fulg decompile main`, `fulg ask reach …`, `fulg checksec`), suitable for CI pipelines and batch triage.
- Batch mode: analyse a directory of samples, export facts/JSON reports.

### 16.3 Binary diffing

- Function matching between two binaries in stages: exact byte hash → MIR semantic hash → CFG structure (block/edge counts, call graph neighbours) → fuzzy matching with a confidence.
- Views: matched/unmatched/changed functions; side-by-side pseudocode diff; changed basic blocks highlighted.
- Used for patch diffing (find the fixed bug) and for re-binding annotations to new builds (§5.4).

### 16.4 Collaboration via git

- The user layer (§5.1) is the shared state. `fulg sync` = `git pull` + re-apply + `git push` with sensible commit messages ("rename 3 functions, apply struct packet to 12 sites").
- Blame on any name/type: who decided it, when, and with what evidence.
- No server product required; any git host works.
- **Real-time mode:** the same records can sync live through a CRDT (Automerge/yrs) for
  pair-reversing sessions; git remains the durable history.
- **Interop:** import/export of BinSync-compatible state, and **DWARF export**, so the analyst's
  names and types appear in `gdb` when debugging the original binary.

### 16.5 Plugin system

| Plugin kind | Runtime | Can do |
|---|---|---|
| **Passes** | WASM (sandboxed) | read IR + facts, emit rewrites + facts with evidence |
| **Loaders / arch modules** | WASM | add formats/architectures through the same traits |
| **Views / panels** | WASM + UI manifest | render data from the RPC API |
| **Scripts** | Python (out-of-process) | anything the RPC API allows |

Plugins get **capabilities**, not ambient authority: no filesystem/network unless the manifest
requests it and the user approves. Plugin facts are tagged with the plugin id and version, so
their output can be filtered or bulk-rejected.

### 16.6 Authoring deobfuscation passes

A pass-authoring workspace: pick a function, write a pass (WASM via Rust, or Python in a
slower dev mode), run it in preview, see the IR diff and explain log, iterate. Passes that work
can be shared as plugins.

---

## 17. AI assistance

### 17.1 Rules

1. AI output is **just another fact producer** (`EvidenceKind::AiSuggestion`), with confidence capped (default ≤ 0.6) unless corroborated by non-AI evidence.
2. **Never auto-applied.** Suggestions go to the review queue, like type propagation.
3. **Evidence required.** A suggestion must cite the facts/instructions it relied on ("named `parse_header` because it compares the first 4 bytes against `\x7fELF` at 0x401020"); suggestions without checkable evidence are discarded.
4. **Checkable claims are checked.** If the AI claims "this returns the string length", the tool verifies what it can (e.g. emulate on a test input) and adjusts confidence.

### 17.2 Tasks

| Task | Input given to the model | Output |
|---|---|---|
| Name suggestion | HIR + strings + callee names | names with cited evidence |
| Function summary | HIR + facts | 1–3 sentence summary, shown with a "machine-generated" badge |
| Type suggestion | access patterns + API calls | types, routed through type inference as soft constraints |
| Explain to a beginner | the Explain-why chain (§15.5) | plain-language walkthrough, grounded in that chain |

### 17.3 Privacy

- Default **off**. Enabling it shows exactly what will be sent.
- **Local model** backend supported (no data leaves the machine).
- Remote backends require an explicit per-project opt-in, and malware projects default to local-only.

---

## 18. UI architecture

### 18.1 View catalog

| View | Shows | Notes |
|---|---|---|
| **Hex** | raw bytes + ASCII, file offset *and* virtual address columns | Shapes toggle (§15.3); selection syncs to every other view |
| **Linear listing** | `objdump`-like disassembly with labels, xrefs, comments | familiar starting point for beginners; virtualised |
| **Graph** | basic-block CFG of one function | coverage colouring, confidence markers on edges, unresolved indirect jumps drawn as open-ended arrows |
| **IL views** | LIR / MIR / HIR, each with optional SSA form | Expert profile by default |
| **Pseudocode** | decompiler token AST | confidence encoding, Explain-why on click, runtime-value overlay |
| **Headers** | ELF/PE structures as tables with file offsets | Question Mode's main target |
| **Segments / Sections** | memory map with permissions, both "loader truth" and "metadata claims" | RWX highlighted |
| **Imports / Exports / Symbols** | tables with filters | library matches shown with their confidence |
| **Strings** | ASCII/UTF-16 strings with xrefs | filter by referenced-only |
| **Types** | C declarations editor with live layout (offset/size/padding) and the sum check | |
| **Xrefs** | who references this address, by kind | |
| **Stack frame** | diagram from §15.4 | per function |
| **Registers / Memory** | state at the current trace step / debugger stop | |
| **Timeline** | trace scrubber, events, coverage over time | |
| **Facts** | raw fact browser: filter by kind/status/confidence/pass | the "show me everything you believe" view |
| **Question / Learn panel** | step cards, catalog, progress | |
| **Review queue** | pending propagations, AI suggestions, rebinds, conflicts | |
| **Console** | Python REPL + `fulg` commands | |

### 18.2 Linked cursor model

One global **location** = `(binary, va, optional IrNodeId, optional trace seq)`.

- Every view subscribes to location changes and highlights its own representation (hex bytes, listing line, graph block, IL op, pseudocode token, stack slot).
- **Sync groups**: views can be unlinked or put into a separate group, for side-by-side comparison of two functions or two trace steps.
- Selections are ranges of locations; selecting a pseudocode token selects its source bytes in hex.
- Navigation history (back/forward) is per tab, like a browser.

### 18.3 Rendering huge binaries

- Every list/listing/hex view is **virtualised**: it requests only the visible rows (`Listing.range(addr, count)`) plus a prefetch margin.
- Server-side pagination with stable cursors, so scrolling a 500 MB binary doesn't load it into the UI.
- Graph layout runs on the daemon, cached per function, re-laid-out incrementally on edits.

### 18.4 Interaction

- **Command palette** (fuzzy search over every action, symbol, address, question).
- **Keyboard-first**, with keybinding presets: *Fulgurite*, *IDA-like*, *Binja-like*, *Ghidra-like*, to lower the cost of switching tools.
- Theming via design tokens; light/dark; confidence encodings tested in both.
- Every number has a **base toggle** (hex/decimal) and hex values show decimal on hover (helps beginners still learning hex).

---

## 19. Performance and concurrency

### 19.1 Incremental analysis

- A global **worklist** of `(function, pass)` jobs, prioritised by: the function currently in view > its callers/callees > the rest.
- The user can navigate and read immediately after load: the listing and loader facts appear first; deeper analysis streams in, and views update via `facts_changed` events.
- Edits invalidate through the DAG (§4.5) and only dirty functions re-run.

### 19.2 Parallelism

- Per-function passes run in parallel on a work-stealing pool (Rayon).
- Inter-procedural phases (signature recovery, type propagation, no-return fixed point) run as rounds: parallel per function, then a merge step, until a fixed point or an iteration cap.
- The fact store uses MVCC snapshots: readers (UI, scripts) never block writers (analysis).

### 19.3 Memory

- Instructions decoded lazily and cached in an LRU; IR for functions not in view can be evicted and re-lifted (deterministic).
- Facts are stored compactly (interned strings, arena-allocated evidence), spilled to SQLite beyond a memory budget.
- Explain logs are **not** persisted; they are rebuilt on demand by deterministic replay (§9.3).

### 19.4 Targets (design goals, to be measured, not claims)

| Metric | Target |
|---|---|
| Open a 10 MB binary → navigable listing | < 2 s |
| Full analysis of a 10 MB binary (8 cores) | < 1 min |
| Full analysis of a 100 MB binary | < 15 min, with progress and an interactive UI throughout |
| Re-decompile one function after a type change | < 100 ms (feels instant) |
| Steady-state memory | ≤ ~10× binary size for full analysis |

---

## 20. Security of the tool itself

The tool's input is, by definition, often **malicious**. Threat model: a crafted binary,
project file or trace tries to crash, hang or compromise the analyst's machine.

### 20.1 Memory safety

- Core in Rust; `unsafe` limited to a small, audited set of modules (FFI to solvers, mmap), and **forbidden in loaders and decoders**.
- Every loop over file-derived counts has a hard bound; every recursion has a depth limit.

### 20.2 Fuzzing

- Continuous fuzzing (`cargo-fuzz`/libFuzzer) of every loader, both decoders, the DWARF/PDB parsers, the trace reader and the project-file reader.
- Crash-to-regression-test pipeline: every fuzzer finding becomes a permanent test case.

### 20.3 Never running targets unprotected

- **Emulation is the default** dynamic mode (no native execution).
- Native debugging runs the target only inside a sandbox: container with no network, read-only filesystem except a scratch dir, seccomp profile, resource limits. For malware projects, the default is a VM backend.
- Starting native execution requires an explicit confirmation showing the sandbox profile.

### 20.4 Untrusted project files

- Project files never contain executable code. Plugins referenced by a project are **not** auto-loaded: the user is asked.
- Question catalog files are data (TOML + the safe selector language, §15.2.2), not scripts.

### 20.5 Plugins

- WASM plugins run with capability-based permissions (§16.5).
- Python plugins run out-of-process with the same RPC permissions model.

---

## 21. Testing and validation

### 21.1 Decoder correctness

- **ARM64: exhaustive.** All 2³² encodings are decoded and compared against at least one reference disassembler (e.g. LLVM's `llvm-mc` and Capstone). This is feasible in hours on a workstation.
  *M0 has:* the `llvm-mc` oracle with documented accepted categories (163,179 words per `cargo test`, no unexplained difference), ARM64 listings checked against `llvm-objdump`, and the full 2³² run: every 32-bit word compared with LLVM 23 and GNU binutils 2.47, 99.70% identical or both invalid, every other word in a documented category checked against Arm's specification (details in `docs/progress/m0-step6.md`).
- **x86-64: differential + structured fuzzing** against Intel XED and Capstone: random byte strings, plus generation from the opcode tables (every opcode × prefix combinations × ModRM/SIB forms).
  *M0 has:* an `objdump -d` oracle over system libraries and fixtures covering every instruction family (5.0 million instructions, no unexplained difference), an exhaustive sweep of every two-byte prefix in 16/32/64-bit mode, random-byte invariants, and a libFuzzer target. XED and Capstone come later.
- Disagreements are triaged; references are sometimes wrong, so hardware behaviour (§21.2) is the tie-breaker.

### 21.2 Lifter correctness (the most important test)

- **Single-instruction differential testing against real CPUs**: a harness sets random register/memory state, executes one instruction natively (inside a sandboxed child under ptrace), and compares the result with the LIR emulator's result, including flags.
- Run on real x86-64 and real ARM64 hardware (QEMU is used only as a secondary reference because it can be wrong too).
- Undefined flags are excluded from comparison only where the architecture documents them as undefined, and the lifter marks them `undefined` (§9.2).

### 21.3 Decompiler correctness

- **Recompile-and-compare**: for corpus programs, decompile functions, recompile the output (where it is valid C), and run both versions on generated inputs; behaviour must match.
- Golden tests: decompiled output of a fixed corpus is snapshot-tested; changes require review.
- Structuring metrics: number of `goto`s, nesting depth, compared against source.

### 21.4 Ground-truth corpus

| Axis | Values |
|---|---|
| Compilers | gcc, clang, MSVC (via cross builds), Go, rustc |
| Optimisation | `-O0`, `-O1`, `-O2`, `-O3`, `-Os` |
| Variants | stripped / unstripped / PIE / non-PIE / static / dynamic |
| Programs | coreutils-like utilities, parsers, CTF-style challenges, crypto libraries |

DWARF/PDB from the unstripped builds is the answer key. Metrics:
- **Function boundaries**: precision/recall on stripped builds.
- **Types**: exact-match and compatible-match rates for params/locals.
- **Struct layouts**: field offset accuracy.
- **CFG**: edge precision/recall, especially indirect jumps.
- **Library matching**: precision/recall.

### 21.5 Confidence calibration

- Reliability diagrams per fact kind (§12.4); Expected Calibration Error tracked per release.
- **Release gate**: no fact kind may become more over-confident than the previous release.

### 21.6 Beginner-layer testing

- Every catalog question has fixture binaries and an expected answer (`answer.from` must match).
- Explain-mode text is generated from LIR, so it is covered by the lifter tests; template wording is snapshot-tested.
- Usability sessions with real beginners: measure time-to-answer per question with and without Question Mode.

### 21.7 OS-loader differential testing and the competitive benchmark

- **Loader truth from the real loaders:** fuzzed and corpus ELF/PE files are loaded by the Linux
  kernel's ELF loader + `ld.so` (in a disposable VM, inspecting `/proc/<pid>/maps`) and by the
  Windows loader (in a VM, via the debug API). Fulgurite's computed memory map must match; every
  mismatch is a loader bug or a documented anomaly.
- **Competitive benchmark:** the §1.5 scoreboard runs on every release against IDA, Binary
  Ninja and Ghidra headless (where licences allow); results and the corpus are published.

### 21.8 Corpus and continuous tuning program

The incumbents' 30-year lead is mostly **exposure**: decades of strange binaries reported by
users. This program compresses that exposure with large corpora plus automated triage.

#### 21.8.1 What can and cannot be tuned from data

Most of Fulgurite is algorithms, not a trained model. Data tunes:

| Tunable | Example |
|---|---|
| Confidence weights | per evidence kind × compiler × opt level (§12.3) |
| Heuristic thresholds | prologue-pattern scores, pointer-scan acceptance, jump-table bounds |
| Readability cost model | weights for structuring search (§11.2) and e-graph extraction (§10.7) |
| Learned components | name/type proposal models (§10.5, §17) |
| Signature database | library matching (§10.8) |
| Pass correctness | not "tuned", but **bugs found** by disagreements, fixed, and locked with regression tests |

#### 21.8.2 Three label sources

**Key constraint:** malware databases label *behaviour* (family names, tags, YARA hits,
sandbox reports of files/registry/network). Decompiler tuning needs **code-level** ground truth
(boundaries, types, correct pseudocode), which behaviour labels do not give. Hence:

| Source | Labels it provides | Coverage | Primary use |
|---|---|---|---|
| **S1: Open source we compile ourselves** (distro packages, popular GitHub projects, the compilation farm of §10.8) | **Complete** code-level truth from DWARF + source: boundaries, types, structs, line mappings | Unlimited, any compiler/flags | Decompiler correctness, types, calibration. **The backbone** |
| **S2: Real malware under our own tracing** | **Partial, free labels from execution**: executed bytes = code; taken indirect targets = real edges; entered addresses = functions; observed values | Real adversarial distribution (packers, anti-disassembly, odd linkers) | CFG recovery, code-vs-data, indirect jumps, robustness, calibration on hostile input |
| **S3: Malware with published source** (leaked or released research collections) compiled under varied compilers and obfuscators (e.g. OLLVM) | Complete code-level truth **for real malware code** | Small but highly relevant | Deobfuscation passes, malware idioms, obfuscator-specific tests |

S2 works because Fulgurite already records observations as `Observed` facts (§13.5): **every
traced sample emits labels automatically**, and every static/dynamic disagreement is a measured
error, with no human labelling.

Additional label-free uses of malware: crash/hang robustness, OS-loader differential testing
(§21.7), packer variety for deobfuscation, statically linked libraries (OpenSSL, zlib, CRTs)
for signatures.

#### 21.8.3 Data sources and access

| Source | Access model (verify current terms before use) |
|---|---|
| MalwareBazaar (abuse.ch) | free, API key |
| VirusTotal Academic | by application, for research |
| VirusShare | by request |
| SOREL-20M (Sophos AI / ReversingLabs) | public research release; ~10 M **disarmed** PE samples plus metadata |
| Vendor / CERT partnerships | case by case, for an established open-source project |

Requests are made **as the open-source project**, with this section and §21.8.6 as the data-handling statement.

#### 21.8.4 Pipeline

```
 ingest ──► quarantine store ──► static analysis (Fulgurite headless)
   │          (encrypted, hashed,          │
   │           no exec bit)                ▼
   │                               facts + confidence
   │                                       │
   └──► detonation VM (no network or sinkholed) ──► trace (§13.4) ──► Observed facts
                                                                         │
            static ⟷ observed diff  ◄────────────────────────────────────┘
                     │
                     ▼
     disagreement records {sample, va, claim_static, claim_observed, pass, confidence}
                     │
         ┌───────────┴─────────────┐
         ▼                         ▼
  calibration update        triage queue (clustered by pass + pattern)
  (§12, per kind ×                 │
   compiler × opt)                 ▼
                       agent proposes: root cause + fix + regression test
                                   │
                                   ▼
          gate: translation validation (§9.4) + full scoreboard (§1.5)
                                   │
                        merged only if no metric regresses
```

#### 21.8.5 AI-agent automation

| Agent may | Agent may not |
|---|---|
| Cluster thousands of disagreements into root causes | **Create ground-truth labels** (its errors would poison calibration) |
| Propose pass fixes and heuristic changes | Merge anything; the gate (§21.8.4) decides |
| Write regression tests from minimised failing samples | Touch the quarantine store or detonation VMs outside the pipeline's API |
| Summarise behaviour reports for the AI naming/summary layer (§17), as *weak* evidence | Promote AI output above `Inferred` status |

Rule: **the AI proposes, the verifier decides.** Labels come only from S1 (DWARF/source),
S2 (execution) or S3 (source), never from model output.

#### 21.8.6 Safety and data governance

- **Detonation only in disposable VMs**: snapshot-reverted after every run, no host mounts, no internet (or a sinkholed fake internet), egress firewall enforced outside the VM.
- **Quarantine store**: samples stored encrypted at rest, never with execute permission, accessed only by the pipeline.
- **Publish derivatives, never samples**: the open-source repository ships signatures, calibration weights, metrics, minimised *non-functional* regression snippets and sample hashes, not binaries.
- **Respect each provider's terms** (redistribution limits, attribution, research-only clauses), recorded per sample in the corpus manifest.
- **Minimised test cases are defanged**: only the bytes needed to reproduce the analysis bug are kept, re-checked so they cannot execute the original payload.

#### 21.8.7 Success metrics

| Metric | Target trend |
|---|---|
| Static/dynamic disagreement rate on S2 (per 1 000 executed functions) | falls every release |
| Crash/hang rate on the full malware corpus | 0 crashes; hangs only at budget limits |
| Calibration error on S2 observed labels | ≤ calibration error on S1 (hostile input is no excuse for over-confidence) |
| Median time from disagreement cluster → merged fix | falls as triage automation matures |
| Scoreboard (§1.5) gap to best incumbent on obfuscated/packed subset | closes release over release |

**What this does not replace:** judgment about *readable* output still comes from human ratings
and the scoreboard; data shows where Fulgurite is wrong, not what reads best.

---

## 22. Tech stack and rationale

### 22.1 What the architecture demands

The language and framework choices follow from five requirements this design imposes:

1. **Hostile input everywhere** (§20): loaders, decoders and trace readers parse attacker-controlled bytes.
2. **Graph-and-tree-heavy code**: IR nodes, CFGs, dominator trees, the fact DAG. This rewards algebraic data types and pattern matching (the reason compilers are often written in ML-family languages).
3. **Incremental, cancellable recomputation**: a user edit must invalidate exactly the dependent facts (§4.5) and cancel stale work so the UI stays responsive.
4. **Parallel per-function analysis** without data races (§19.2).
5. **Three front doors onto one engine**: GUI, CLI, Python, plus sandboxed plugins (§0.4 principle 7).

### 22.2 Core language: Rust

| Candidate | Verdict |
|---|---|
| **Rust** | ✅ Memory-safe parsing (1), `enum` + exhaustive `match` for IR work (2), data-race freedom enforced by the compiler (4), first-class WASM host and Python bindings (5). The strict compiler also acts as a continuous correctness check on the code being written |
| C++ | ❌ What IDA and Binary Ninja's core use, and fast, but every hostile-input bug becomes a vulnerability in the analyst's tool; no compiler-enforced race freedom |
| OCaml | ⚠️ Excellent for IR and analysis (the BAP platform used it), but a small ecosystem for GUI, Python bindings and WASM hosting |
| Java | ❌ Ghidra's choice. Works, but GC pauses, heavy memory use on large binaries and awkward native interop |
| Go / Python / Zig | ❌ Go: GC and weak ADTs for IR. Python: too slow for an engine (fine as the scripting layer). Zig: promising but immature ecosystem |

### 22.3 Internal architecture rules (Rust-specific)

| Rule | Detail | Why |
|---|---|---|
| **Arena + typed indices** for all graphs | IR nodes, blocks, facts live in `Vec`-backed arenas addressed by `u32` newtype ids (`IrNodeId`, `BlockId`, `FactId`); no `Rc<RefCell<…>>` graphs | cache-friendly, trivially serialisable, no borrow-checker fights, ids double as stable provenance keys |
| **Incremental engine: Salsa** | the query framework used by rust-analyzer (and Astral's `ty` type checker). User-layer records and the binary are Salsa *inputs*; every analysis is a memoised *query*; Salsa tracks dependencies, invalidates precisely, supports early cut-off (a recomputed result equal to the old one stops propagation) and **cancels** in-flight queries when inputs change | this *is* the §4.5 dependency DAG and the §19.1 worklist: reuse a proven implementation instead of hand-rolling invalidation, the hardest-to-debug part of incremental systems |
| Facts on top of Salsa | queries return `Vec<Fact>` (claim + confidence + evidence + provenance); resolution rules (§4.4) are a query over those | keeps Fulgurite's novel layer (evidence, confidence, stickiness) separate from generic incrementality |
| Inter-procedural cycles | recursion in the call graph handled by Salsa's fixpoint cycle support where available, else by explicit rounds (§19.2) | signatures and no-return analysis are naturally cyclic |
| Persistence | Salsa is in-memory; expensive per-function results are additionally written to SQLite **keyed by a hash of their inputs**, so re-opening a project skips recomputation | fast re-open without trusting stale data |
| **Sync core, async edges** | the engine is synchronous + Rayon; `tokio` appears only in `fulgurited`/RPC | keeps analysis code simple and deterministic |
| `#![forbid(unsafe_code)]` | in `fg-loader`, both decoders, trace and project readers | enforces §20.1 at compile time |

### 22.4 Build vs reuse

"Own core" means Fulgurite owns everything that **differentiates** it. Commodity parsers
that are already correct and well-tested are reused.

| Area | Decision | Component |
|---|---|---|
| ELF / PE loaders | **Build** | Needs per-field file offsets, anomaly reports and "loader truth vs metadata claims" (§6), which generic parsers don't expose. Generic crates (`object`, `goblin`) are used as **test oracles** |
| x86-64 decoder | **Reuse** `iced-x86` behind the `Arch` trait | pure Rust with a safe API and very high test coverage (it uses `unsafe` internally for speed; Fulgurite's own crates still forbid it, and iced is fuzzed through Fulgurite's `disasm` target). Re-deriving x86 decoding gains nothing; the value is in lifting. Differentially tested against objdump now and XED later (§21.1) |
| ARM64 decoder | **Build**, generated from Arm's machine-readable spec | fixed-width and exhaustively testable (2³² encodings), so owning it is cheap and keeps new extensions in step with the spec |
| Lifters (both arches) | **Build**: ARM64 generated from Arm's ASL/Sail spec, x86-64 hand-written and checked against the K-framework semantics | the semantics source of truth for emulator, solver, decompiler and Explain mode (§0.4 principle 2) |
| IR, analyses, decompiler, fact store, confidence | **Build** | the product |
| DWARF | **Reuse** `gimli` | the standard Rust DWARF reader |
| PDB | **Reuse** `pdb` crate | |
| Demangling | **Reuse** `cpp_demangle`, `msvc-demangler`, `rustc-demangle` | |
| SMT solving | **Reuse** solvers as **subprocesses speaking SMT-LIB2** over a pipe | solver-agnostic (Bitwuzla default, Z3/cvc5 interchangeable), and the process boundary *is* the isolation §3.2 asks for: a blown-up query is just killed |
| Debugger protocol | **Build** a GDB RSP client (simple text protocol); ptrace via the `nix` crate | works against `gdbserver`, QEMU gdbstub and `rr replay` |
| Emulator speed-up (later) | **Reuse** Cranelift to JIT hot LIR blocks | only if interpreted traces prove too slow; Cranelift already powers wasmtime |

### 22.5 Interfaces

| Front door | Choice | Notes |
|---|---|---|
| Public API | one Rust **service trait** per §3.3 service | the single definition everything else wraps |
| GUI | calls the service trait **in-process** (no serialisation) | fastest path for the main user |
| RPC | **gRPC** (`tonic` + `prost`), generated from the same `.proto` schema | for CLI-to-daemon, remote analysis and other-language clients; streaming for progress and `facts_changed` |
| Python | **PyO3 + maturin**, with generated `.pyi` type stubs | in-process; same methods as the service trait |
| CLI | `clap` | thin client; works directly on the library for one-shot commands, or against `fulgurited` |
| Plugins | **wasmtime + WIT component model** (`wit-bindgen`) for typed host/plugin interfaces; Python plugins out-of-process via gRPC | capability-based (§16.5) |

### 22.6 GUI

| Option | Verdict |
|---|---|
| **Tauri v2 shell + TypeScript/React frontend** | ✅ Chosen. Rich per-token text, virtualised lists and dockable panes are mature on the web stack; the same frontend runs in a normal browser against `fulgurited` (remote analysis for free) |
| Qt | ⚠️ What IDA and Binary Ninja use; excellent docking, but Rust bindings are immature |
| egui | ⚠️ Very fast, pure Rust, but rich interactive text and accessibility are weaker |
| Electron | fallback shell only (see risk below) |

Frontend pieces: React + TypeScript; TanStack Virtual for virtualised listings/hex; a dock
layout library for panes; graph view drawn on Canvas/WebGL with layered (Sugiyama-style)
layout computed in Rust so the CLI can export the same graphs as SVG.

**Known risk:** on Linux, Tauri uses the system WebKitGTK, which can be slower than Chromium
for very large DOMs. Mitigation: the frontend is shell-agnostic, so if profiling shows
WebKitGTK as the bottleneck, swap the shell to Electron without touching frontend code.

### 22.7 Storage, formats, tooling

| Component | Choice |
|---|---|
| Analysis cache | **SQLite** via `rusqlite` (WAL mode); cached blobs serialised with `serde` + `bincode`, schema-versioned |
| User layer | **JSONL + C headers** (§5) |
| Traces | chunked `zstd` files + index (§13.4) |
| Parallelism | `rayon` |
| Tests | `proptest` (property tests), `insta` (decompiler golden snapshots), `cargo-fuzz`/libFuzzer, `criterion` (benchmarks); differential oracles: XED, Capstone, `llvm-mc`, `object`/`goblin`, real CPUs |
| Workspace | one Cargo workspace; crates layered as in §3.1, and **a crate may only depend on crates below it** (checked in CI with `cargo-deny`/a layering lint) |

### 22.8 Crate layout

```
fulgurite/
├── crates/
│   ├── fg-core/        # ids, arenas, Va, errors              (no internal deps)
│   ├── fg-loader/      # ELF, PE                              → fg-core
│   ├── fg-ir/          # Insn + Arch trait; LIR/MIR/HIR, SSA  → fg-core
│   ├── fg-arch-x86/    # iced-x86 decode + own lifter         → fg-ir
│   ├── fg-arch-arm64/  # generated decoder + own lifter       → fg-ir
│   ├── fg-facts/       # Fact, confidence, resolution rules   → fg-core
│   ├── fg-analysis/    # Salsa db, CFG, VSA, types, idioms    → all of the above
│   ├── fg-decomp/      # structuring, token AST               → fg-analysis
│   ├── fg-dynamic/     # emulator, RSP client, traces         → fg-analysis
│   ├── fg-solve/       # MIR → SMT-LIB2, solver processes     → fg-analysis
│   ├── fg-learn/       # Question Mode, Explain, practice     → fg-decomp, fg-dynamic
│   ├── fg-store/       # SQLite cache, JSONL user layer       → fg-facts
│   ├── fg-service/     # the public service traits            → everything above
│   ├── fulgurited/     # gRPC daemon                          → fg-service
│   ├── fg-cli/         # `fulg`                               → fg-service
│   └── fg-py/          # PyO3 bindings                        → fg-service
├── proto/              # fulgurite.v1 .proto schema
├── catalog/            # Question Mode TOML files
├── corpus/             # ground-truth programs + build scripts
└── ui/                 # Tauri shell + React frontend
```

---

## 23. Roadmap

Each milestone ends with something usable on its own.

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0: Inspect** | ELF + PE loaders, both decoders, `fulg` CLI that replaces `file`/`readelf -h -l -S -d`/`objdump -d`, checksec with evidence, anomaly reports | `fulg` output matches `readelf`/`objdump` on a corpus of system binaries (instruction text normalised); loaders survive 24 h of fuzzing without crashes |
| **M1: Graph** | CFG recovery, seeds, jump tables, no-return, xrefs, fact store v1, SQLite cache | function-boundary recall ≥ 95% on stripped `-O2` gcc/clang corpus; every fact has evidence |
| **M2: IR** | LIR lifters (both arches) + differential CPU testing, MIR, SSA, const-prop, stack tracking, explain log | lifter differential tests pass on all supported instructions; IL views in CLI |
| **M3: Decompile** | type inference, struct recovery, idioms, structuring, token AST, confidence system v1, first GUI (listing, graph, pseudocode, hex) | recompile-and-compare passes on ≥ 80% of `-O0` corpus functions, ≥ 60% at `-O2`; calibration ECE tracked |
| **M4: Dynamic** | LIR emulator, Linux syscall layer, GDB RSP client (incl. `rr`), traces + index, time-travel UI, observed facts | "who last wrote" queries answered < 100 ms on a 10 M-step trace |
| **M5: Learn** | Question Mode + starter catalog, Shapes, Explain mode, stack-frame diagram, Explain-why, practice mode, profiles | a beginner answers the starter catalog questions faster with Question Mode than without (usability study) |
| **M6: Advanced** | symbolic queries, type propagation review, diffing, git collaboration, plugin system, language frontends, deobfuscation passes, AI assistance | journeys B–D (§2) completed end-to-end on test binaries |

**Building order suggestion** for a solo learner: M0 is buildable *right now* alongside
Stage 1–2 of an RE curriculum (it is mostly ELF parsing, which you've already studied by hand);
M1–M2 fit naturally after learning x86-64 asm; M3 onward after Ghidra experience.

---

## 24. Open questions

1. **Confidence for user facts**: should a user decision ever be marked less than certain (e.g. "I think this is a `struct packet`, not sure")? Proposal: allow a "tentative" flag that keeps status `User` but confidence 0.7.
2. **Global vs per-function SSA**: inter-procedural analyses would benefit from a whole-program SSA, at a big memory cost. Defer to measurement in M2.
3. **Trace storage limits**: multi-billion-step traces don't fit the current index design; is sampling acceptable, or does the index need to be on-disk and hierarchical?
4. **Question catalog governance**: who curates the shipped catalog, and how are community questions reviewed so wrong "derive" text doesn't teach beginners incorrect facts?
5. **Practice-mode scoring of names**: what counts as "semantically equal" (`len` vs `length` vs `n`)? Possibly an embedding similarity threshold, validated by humans.
6. **Windows emulation depth**: stubs only (v1 plan), or invest in a minimal Windows API layer for malware triage?
7. **Starter catalog growth** (§15.2.5): the first seven questions are x86-64 ELF only. PE and ARM64 equivalents (DEP/ASLR flags in `DllCharacteristics`, AAPCS64 argument registers) are still to be written.

---

## 25. Glossary and references

### 25.1 Glossary

| Term | Meaning |
|---|---|
| **Basic block** | straight-line run of instructions with one entry and one exit |
| **CFG** | control-flow graph: basic blocks as nodes, jumps/fall-throughs as edges |
| **Lifting** | translating machine instructions into an IR with explicit semantics |
| **IR / IL** | intermediate representation / intermediate language |
| **SSA** | static single assignment: every variable assigned exactly once, which makes data flow explicit |
| **VSA** | value-set analysis: computes the possible values (as strided intervals) of registers and memory |
| **Structuring** | turning a CFG back into `if`/`while`/`switch` without `goto`s |
| **Idiom** | a compiler pattern with a simpler meaning (`x*0xAAAAAAAB>>33` ≡ `x/3` for 32-bit unsigned `x`) |
| **Fact** | any claim Fulgurite makes, with confidence, status, provenance and evidence |
| **Provenance** | the record of which inputs and which pass produced a fact or IR node |
| **Sticky rejection** | a user "no" that re-analysis may not override |
| **Noisy-OR** | rule for combining independent evidence: `1 − Π(1 − wᵢ)` |
| **Red zone** | (SysV) 128 bytes below `rsp` that leaf functions may use without moving `rsp` |
| **Shadow space** | (MS x64) 32 bytes the caller reserves above the return address for the callee |
| **PIE / ASLR / NX / RELRO / canary** | see the mitigation table in §6.5 |
| **Time-travel debugging** | stepping backwards through a recorded execution |
| **SMT** | satisfiability modulo theories: solver for constraints over bit-vectors, arrays, etc. |
| **CFF** | control-flow flattening, an obfuscation that routes all blocks through one dispatcher |
| **Opaque predicate** | a branch condition that is always true/false but hard to prove statically |
| **MBA** | mixed boolean-arithmetic expressions used to obfuscate simple computations |

### 25.2 References (prior work this design builds on)

- G. Balakrishnan, T. Reps: *Analyzing Memory Accesses in x86 Executables* (CC 2004): value-set analysis.
- J. Lee, T. Avgerinos, D. Brumley: *TIE: Principled Reverse Engineering of Types in Binary Programs* (NDSS 2011).
- M. Noonan, A. Loginov, D. Cok: *Polymorphic Type Inference for Machine Code* (PLDI 2016): Retypd.
- E. Schwartz et al.: *Native x86 Decompilation Using Semantics-Preserving Structural Analysis and Iterative Control-Flow Structuring* (USENIX Security 2013): Phoenix.
- K. Yakdan et al.: *No More Gotos: Decompilation Using Pattern-Independent Control-Flow Structuring and Semantics-Preserving Transformations* (NDSS 2015).
- M. Braun et al.: *Simple and Efficient Construction of Static Single Assignment Form* (CC 2013).
- R. Cytron et al.: *Efficiently Computing Static Single Assignment Form and the Control Dependence Graph* (TOPLAS 1991).
- P. Havlak: *Nesting of Reducible and Irreducible Loops* (TOPLAS 1997).
- N. Lopes et al.: *Alive2: Bounded Translation Validation for LLVM* (PLDI 2021): translation validation.
- M. Willsey et al.: *egg: Fast and Extensible Equality Saturation* (POPL 2021): e-graphs.
- S. Dasgupta et al.: *A Complete Formal Semantics of x86-64 User-Level Instruction Set Architecture* (PLDI 2019): K-framework x86-64 model.
- Q. Chen et al.: *Augmenting Decompiler Output with Learned Variable Names and Types* (USENIX Security 2022): DIRTY.
- A. Armstrong et al.: *ISA Semantics for ARMv8-A, RISC-V, and CHERI-MIPS* (POPL 2019): Sail models.
- L. Dramko et al.: *A Taxonomy of C Decompiler Fidelity Issues* (USENIX Security 2024).
- *The Evolution of Binary Decompilation in the Modern Era: A Taxonomy, Literature Review, and Future Perspectives* (arXiv 2608.24955, 2026): names uncertainty exposure as an open problem.
- Tools: IDA Pro / Hex-Rays, Binary Ninja (BNIL, WARP, Sidekick), Ghidra (P-code, BSim, trace database), angr (VEX + claripy), BinSync, BinDiff, Diaphora, `rr`, debuginfod, Intel XED, Capstone, LLVM MC, Compiler Explorer, Automerge/yrs.
- Competitor release notes used for §1.1 (checked October 2026): Hex-Rays IDA 9.2 release notes; Binary Ninja 5.0 / 5.1 / 5.2 / 5.3 / 6.0 release posts; Ghidra 12.0 / 12.1 change histories.
- Specs: System V AMD64 ABI; Microsoft x64 calling convention docs; Arm AAPCS64; ELF gABI + `elf(5)`; Microsoft PE/COFF specification; DWARF 5 standard; Itanium C++ ABI.
