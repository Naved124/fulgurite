#!/usr/bin/env python3
"""Generates the A64 decoder tables of `fg-arch-arm64` from Arm's specification.

Inputs (not part of the repository; download them from developer.arm.com):

* the Arm A-profile Machine Readable Specification, open-source JSON build
  (AARCHMRS_OPENSOURCE_A_profile_FAT-<version>.tar.gz, BSD-3-Clause): decode tree,
  encodings, assembler syntax grammar, alias conditions, system register encodings;
* the A64 ISA XML release (ISA_A64_xml_A_profile-<version>.tar.gz): the meaning of
  every operand (which fields encode it and how), value tables, and the decode
  pseudocode that rejects reserved encodings.

Neither input is stored in the repository; only the generated Rust is.

    python3 -I tools/arm64/gen.py --mrs DIR --xml DIR [--out crates/fg-arch-arm64/src/tables.rs]

Standard library only. The script stops with a list of problems if the
specification contains something it does not understand, so a new release
cannot silently produce a wrong decoder.
"""

import argparse
import html
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict

# ---------------------------------------------------------------------------
# Loading


class Spec:
    """Everything read from the two inputs."""

    def __init__(self, mrs_dir, xml_dir):
        with open(os.path.join(mrs_dir, "Instructions.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.meta = data["_meta"]
        self.rules = data["assembly_rules"]
        self.a64 = next(s for s in data["instructions"] if s.get("name") == "A64")
        del data
        with open(os.path.join(mrs_dir, "Registers.json"), encoding="utf-8") as f:
            self.registers = json.load(f)
        self.xml_dir = xml_dir
        self._by_enc = None
        self.expl = {}  # (encoding name, link) -> Explanation
        self.decode_ps = {}  # encoding name -> decode pseudocode text
        self.label = {}  # encoding name -> variant label ("32-bit", "Post-index"...)
        self.exec_checks = {}  # encoding name -> ('CPY'|'SET', [argument expressions])
        self.shared_checks = {}  # 'CPY'|'SET' -> (parameter names, [condition text])
        self.xml_version = None
        self._load_xml()

    # Registers.json accessor of a system instruction -> (pseudocode function, kind).
    SYS_ACCESSORS = {
        "A64.AT": ("SysOp", "At"),
        "A64.BRB": ("SysOp", "Brb"),
        "A64.DC": ("SysOp", "Dc"),
        "A64.GIC": ("SysOp", "Gic"),
        "A64.GSB": ("SysOp", "Gsb"),
        "A64.IC": ("SysOp", "Ic"),
        "A64.PLBI": ("SysOp", "Plbi"),
        "A64.TLBI": ("SysOp", "Tlbi"),
        "A64.TLBIP": ("SysOp128", "Tlbip"),
        "A64.GICR": ("SysLOp", "Gicr"),
    }

    def _merge_sys_ops(self):
        """Adds the system instructions Registers.json names but the XML's
        SysOp()/SysOp128()/SysLOp() tables leave out (2026-09: DC ZGBVA,
        GBVA, CVAOC...; TLBI VMALLWS2E1...; every PLBI). Without them the
        DC/TLBI/PLBI alias conditions fail and a named operation shows as
        SYS. A Registers.json operation the XML gives a different kind stops
        generation."""
        self.sys_inputs = {}  # (function, op1:CRn:CRm:op2) -> takes a register value
        for reg in self.registers:
            for acc in reg.get("accessors") or []:
                fk = self.SYS_ACCESSORS.get(acc.get("name"))
                if fk is None:
                    continue
                fn, kind = fk
                for _, f in accessor_encodings(acc):
                    try:
                        if any(f[k][0] != (1 << f[k][2]) - 1 for k in ("op1", "CRn", "CRm", "op2")):
                            raise SystemExit(f"{reg['name']}: system operation with a pattern encoding")
                        key = (f["op1"][1] << 11) | (f["CRn"][1] << 7) | (f["CRm"][1] << 3) | f["op2"][1]
                    except KeyError:
                        raise SystemExit(f"{reg['name']}: system operation without op1/CRn/CRm/op2")
                    self.sys_inputs[(fn, key)] = takes_input(reg)
                    rows = self.sys_cases[fn]
                    known = next((k for m, v, k in rows if key & m == v), None)
                    if known is None:
                        rows.append((0x3FFF, key, kind))
                    elif known != kind:
                        raise SystemExit(f"{reg['name']}: SysOp kind {known} in the XML, {kind} in Registers.json")

    def _load_xml(self):
        self.sys_cases = {}  # SysOp / SysOp128 / SysLOp -> [(mask, value, kind)]
        with open(os.path.join(self.xml_dir, "shared_pseudocode.xml"), encoding="utf-8") as f:
            shared = f.read()
        for m in re.finditer(r"<pstext[^>]*>(.*?)</pstext>", shared, re.S):
            body = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
            f = re.search(r"^func (SysOp|SysOp128|SysLOp)\(", body, re.M)
            if not f:
                continue
            rows = []
            for c in re.finditer(r"when '([01x ]+)' => return Sysl?_(\w+);", body):
                mm, vv, n = pattern(c.group(1).replace(" ", ""))
                if n != 14:
                    raise SystemExit(f"{f.group(1)}: case of {n} bits")
                rows.append((mm, vv, c.group(2).capitalize()))
            self.sys_cases[f.group(1)] = rows
        for m in re.finditer(r"<pstext[^>]*>(.*?)</pstext>", shared, re.S):
            body = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
            f = re.search(r"^func Check(CPY|SET)ConstrainedUnpredictable\(([^)]*)\)", body, re.M)
            if f:
                params = [p.split(":")[0].strip() for p in f.group(2).split(",")]
                conds = re.findall(r"if \((.*?)\) then\s+let c : Constraint = ConstrainUnpredictable", body, re.S)
                self.shared_checks[f.group(1)] = (params, conds)
        if set(self.sys_cases) != {"SysOp", "SysOp128", "SysLOp"}:
            raise SystemExit(f"system operation tables not found: {sorted(self.sys_cases)}")
        self._merge_sys_ops()
        files = sorted(os.listdir(self.xml_dir))
        for name in files:
            if not name.endswith(".xml"):
                continue
            with open(os.path.join(self.xml_dir, name), encoding="utf-8") as f:
                text = f.read()
            if "<instructionsection" not in text:
                continue
            for m in re.finditer(r'<encoding name="([^"]+)"[^>]*?label="([^"]*)"', text):
                self.label[m.group(1)] = html.unescape(m.group(2))
            for m in re.finditer(
                r'<explanation enclist="([^"]*)"[^>]*>(.*?)</explanation>', text, re.S
            ):
                ex = Explanation.parse(m.group(2), name)
                for enc in m.group(1).split(","):
                    self.expl[(enc.strip(), ex.link)] = ex
            # Execute pseudocode calls that check registers for CONSTRAINED
            # UNPREDICTABLE use (MOPS: overlapping or XZR registers).
            plain = html.unescape(re.sub(r"<[^>]+>", "", text))
            for m in re.finditer(r"Check(CPY|SET)ConstrainedUnpredictable\(([^)]*)\)", plain):
                for e in re.findall(r'<encoding name="([^"]+)"', text):
                    self.exec_checks[e] = (m.group(1), [a.strip() for a in m.group(2).split(",")])
            # Shared "Postdecode" pseudocode runs after the decode of every
            # encoding in the file (LDP: the same-register checks).
            post = [
                html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
                for m in re.finditer(r'<pstext[^>]*section="Postdecode"[^>]*>(.*?)</pstext>', text, re.S)
            ]
            # Decode pseudocode: one <ps> per iclass, named after its first encoding;
            # it applies to every encoding of the iclass.
            for m in re.finditer(r"<iclass [^>]*>(.*?)</iclass>", text, re.S):
                body = m.group(1)
                encs = re.findall(r'<encoding name="([^"]+)"', body)
                ps = re.search(
                    r'<pstext[^>]*section="Decode"[^>]*>(.*?)</pstext>', body, re.S
                )
                if ps or post:
                    code = html.unescape(re.sub(r"<[^>]+>", "", ps.group(1))) if ps else ""
                    code = "\n".join([code] + post)
                    for e in encs:
                        self.decode_ps[e] = code


def _expl_by_enc(self, enc):
    if getattr(self, "_by_enc", None) is None:
        self._by_enc = defaultdict(list)
        for k, v in self.expl.items():
            self._by_enc[k[0]].append((k, v))
    return self._by_enc[enc]


Spec.expl_by_enc = _expl_by_enc


class Explanation:
    """One operand explanation from the XML: which fields encode it and how."""

    def __init__(self):
        self.link = None
        self.symbol = None
        self.kind = None  # 'account' (prose) or 'definition' (value table)
        self.encodedin = None
        self.text = ""
        self.table = []  # rows of (cell class, text), header first
        self.file = None

    @staticmethod
    def parse(body, file):
        ex = Explanation()
        ex.file = file
        m = re.search(r'<symbol link="([^"]+)">(.*?)</symbol>', body, re.S)
        ex.link = m.group(1)
        ex.symbol = html.unescape(m.group(2))
        m = re.search(r'<(account|definition) encodedin="([^"]*)"', body)
        if m:
            ex.kind, ex.encodedin = m.group(1), m.group(2)
        m = re.search(r"<intro>(.*?)</intro>", body, re.S)
        if m:
            t = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
            ex.text = re.sub(r"\s+", " ", t).strip()
        m = re.search(r"<after>(.*?)</after>", body, re.S)
        ex.after = ""
        if m:
            t = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
            ex.after = re.sub(r"\s+", " ", t).strip()
        for row in re.findall(r"<row>(.*?)</row>", body, re.S):
            cells = re.findall(r'<entry(?: class="([^"]*)")?[^>]*>(.*?)</entry>', row, re.S)
            ex.table.append(
                [
                    (cls, re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", c))).strip())
                    for cls, c in cells
                ]
            )
        return ex


# ---------------------------------------------------------------------------
# Decode tree and encodings


class Problems:
    """Collects everything the generator does not understand."""

    def __init__(self):
        self.items = []

    def add(self, where, what):
        self.items.append(f"{where}: {what}")

    def stop_if_any(self):
        if self.items:
            for p in self.items[:200]:
                print("error:", p, file=sys.stderr)
            if len(self.items) > 200:
                print(f"... and {len(self.items) - 200} more", file=sys.stderr)
            sys.exit(1)


PROBLEMS = Problems()


def pattern(value):
    """'1x0' -> (mask, value) of a bit string, most significant bit first."""
    s = value.strip("'")
    mask = val = 0
    for ch in s:
        mask <<= 1
        val <<= 1
        if ch in "01":
            mask |= 1
            val |= ch == "1"
        elif ch != "x":
            raise ValueError(f"bad bit pattern {value!r}")
    return mask, val, len(s)


class Node:
    """A group or an encoding of the decode tree."""

    def __init__(self, raw, parent):
        self.raw = raw
        self.parent = parent
        self.name = raw["name"]
        self.kind = raw["_type"].split(".")[-1]  # InstructionSet / InstructionGroup / Instruction
        self.mask = 0
        self.value = 0
        self.sb_mask = 0  # bits that should have a value (CONSTRAINED UNPREDICTABLE otherwise)
        self.sb_value = 0
        self.fields = OrderedDict()  # name -> (lo, width), this node only
        for e in raw["encoding"]["values"]:
            lo, width = e["range"]["start"], e["range"]["width"]
            m, v, n = pattern(e["value"]["value"])
            if n != width:
                PROBLEMS.add(self.name, f"pattern width {n} != field width {width}")
            _, sb, _ = pattern(e["should_be_mask"]["value"])
            # Bits that only "should be" a value are not part of the decode
            # (the architecture makes them CONSTRAINED UNPREDICTABLE).
            self.sb_mask |= (m & sb) << lo
            self.sb_value |= (v & m & sb) << lo
            m &= ~sb
            self.mask |= m << lo
            self.value |= (v & m) << lo
            if e["_type"].endswith("Field"):
                self.fields[e["name"]] = (lo, width)
        self.cond = raw.get("condition")
        self.children = []
        self.enc_id = None

    def scope(self):
        """Fields visible to conditions of this node: its own, then its ancestors'."""
        out = {}
        n = self
        while n is not None:
            for k, v in n.fields.items():
                out.setdefault(k, v)
            n = n.parent
        return out

    def path(self):
        out = []
        n = self
        while n is not None:
            out.append(n.name)
            n = n.parent
        return "/".join(reversed(out))


def build_tree(spec):
    encodings = []

    def walk(raw, parent):
        node = Node(raw, parent)
        if node.kind == "Instruction":
            node.enc_id = len(encodings)
            encodings.append(node)
            node.aliases = [c for c in raw.get("children") or []]
        else:
            for c in raw.get("children") or []:
                node.children.append(walk(c, node))
        return node

    root = walk(spec.a64, None)
    return root, encodings


# ---------------------------------------------------------------------------
# Conditions (ASL abstract syntax) compiled to Rust


class CondTable:
    """Deduplicated boolean expressions over the instruction word."""

    def __init__(self):
        self.exprs = OrderedDict()  # rust source -> id
        self.helpers = set()

    def add(self, ast, scope, where):
        if ast is None:
            return 0
        code, kind = compile_expr(ast, scope, where, self)
        if kind != "bool":
            PROBLEMS.add(where, f"condition is not boolean: {code}")
            return 0
        return self.add_code(code)

    def add_code(self, code):
        if code == "true":
            return 0
        if code not in self.exprs:
            self.exprs[code] = len(self.exprs) + 1
        return self.exprs[code]


def field_expr(name, scope, where):
    if name not in scope:
        PROBLEMS.add(where, f"unknown field {name}")
        return "0", 1
    lo, width = scope[name]
    mask = (1 << width) - 1
    return f"((w >> {lo}) & {mask:#x})", width


def compile_expr(e, scope, where, table):
    """Returns (rust code, kind) with kind 'bool', ('bits', width) or 'int'."""
    t = e["_type"]
    if t == "AST.Bool":
        return ("true" if e["value"] else "false"), "bool"
    if t == "AST.Integer":
        return f"{e['value']}i64", "int"
    if t == "AST.Identifier":
        code, width = field_expr(e["value"], scope, where)
        return code, ("bits", width)
    if t == "Values.Value":
        m, v, n = pattern(e["value"])
        return (m, v, n), "pattern"
    if t == "AST.SquareOp":
        base, kind = compile_expr(e["var"], scope, where, table)
        args = e["arguments"]
        if len(args) != 1 or args[0]["_type"] != "AST.Integer":
            PROBLEMS.add(where, f"unsupported slice {json.dumps(e)[:200]}")
            return "0", ("bits", 1)
        return f"(({base} >> {args[0]['value']}) & 1)", ("bits", 1)
    if t == "AST.UnaryOp":
        inner, kind = compile_expr(e["expr"], scope, where, table)
        if e["op"] == "!" and kind == "bool":
            return f"!({inner})", "bool"
        PROBLEMS.add(where, f"unsupported unary {e['op']}")
        return "false", "bool"
    if t == "AST.Function":
        return compile_call(e, scope, where, table)
    if t == "AST.BinaryOp":
        op = e["op"]
        if op in ("&&", "||"):
            a, ka = compile_expr(e["left"], scope, where, table)
            b, kb = compile_expr(e["right"], scope, where, table)
            if ka != "bool" or kb != "bool":
                PROBLEMS.add(where, f"non-boolean operand of {op}")
            if op == "&&":
                if a == "true":
                    return b, "bool"
                if b == "true":
                    return a, "bool"
            else:
                if a == "true" or b == "true":
                    return "true", "bool"
            return f"({a} {op} {b})", "bool"
        if op == "::":
            a, ka = compile_expr(e["left"], scope, where, table)
            b, kb = compile_expr(e["right"], scope, where, table)
            if not (isinstance(ka, tuple) and isinstance(kb, tuple)):
                PROBLEMS.add(where, "concatenation of non-bits")
                return "0", ("bits", 1)
            return f"(({a} << {kb[1]}) | {b})", ("bits", ka[1] + kb[1])
        if op in ("==", "!="):
            a, ka = compile_expr(e["left"], scope, where, table)
            r = e["right"]
            if r["_type"] == "AST.Identifier" and re.match(r"Sysl?_", r["value"]):
                # SysOp(...) == Sys_DC: the kind of system instruction an encoding names.
                kind = r["value"].split("_", 1)[1]
                return f"({a} {op} SysKind::{kind.capitalize()})", "bool"
            b, kb = compile_expr(e["right"], scope, where, table)
            if kb == "pattern":
                m, v, n = b
                if isinstance(ka, tuple) and ka[1] != n:
                    PROBLEMS.add(where, f"pattern width {n} vs {ka[1]}")
                full = (1 << n) - 1
                lhs = a if m == full else f"({a} & {m:#x})"
                return f"({lhs} {op} {v:#x})", "bool"
            return f"({a} {op} {b})", "bool"
        if op == "IN":
            a, ka = compile_expr(e["left"], scope, where, table)
            alts = []
            for v in e["right"]["values"]:
                m, val, n = pattern(v["value"])
                full = (1 << n) - 1
                alts.append(f"({a} == {val:#x})" if m == full else f"(({a} & {m:#x}) == {val:#x})")
            return "(" + " || ".join(alts) + ")", "bool"
        if op in ("<", ">", "<=", ">=", "+", "-"):
            a, ka = compile_expr(e["left"], scope, where, table)
            b, kb = compile_expr(e["right"], scope, where, table)
            if ka != "int" or kb != "int":
                PROBLEMS.add(where, f"arithmetic on bits ({op})")
            if op in ("+", "-"):
                return f"({a} {op} {b})", "int"
            return f"({a} {op} {b})", "bool"
        PROBLEMS.add(where, f"unsupported operator {op}")
        return "false", "bool"
    PROBLEMS.add(where, f"unsupported expression {t}")
    return "false", "bool"


# ASL helper functions used by the conditions; implemented by hand in `helpers.rs`.
HELPERS = {
    "BFXPreferred": ("h::bfx_preferred", "bool"),
    "MoveWidePreferred": ("h::move_wide_preferred", "bool"),
    "SVEMoveMaskPreferred": ("h::sve_move_mask_preferred", "bool"),
    "SysOp": ("h::sys_op", "sysop"),
    "SysOp128": ("h::sys_op128", "sysop"),
    "SysLOp": ("h::sysl_op", "sysop"),
    "BitCount": ("h::bit_count", "int"),
}


def compile_call(e, scope, where, table):
    name = e["name"]
    args = e["arguments"]
    if name == "IsFeatureImplemented":
        # The decoder accepts every architecture feature; which features a
        # binary may use is a property of the target, not of the encoding.
        return "true", "bool"
    if name == "UInt":
        a, ka = compile_expr(args[0], scope, where, table)
        return f"({a} as i64)", "int"
    if name in ("IsZero", "IsOnes"):
        a, ka = compile_expr(args[0], scope, where, table)
        if not isinstance(ka, tuple):
            PROBLEMS.add(where, f"{name} of non-bits")
            return "false", "bool"
        target = 0 if name == "IsZero" else (1 << ka[1]) - 1
        return f"({a} == {target:#x})", "bool"
    if name in HELPERS:
        fn, kind = HELPERS[name]
        parts = []
        for a in args:
            code, k = compile_expr(a, scope, where, table)
            if k == "pattern":
                m, v, n = code
                code = f"{v:#x}"
                k = ("bits", n)
            if isinstance(k, tuple):
                code = f"{code} as u32"
            parts.append(code)
        table.helpers.add(name)
        return f"{fn}({', '.join(parts)})", {"int": "int", "bool": "bool"}.get(kind, kind)
    PROBLEMS.add(where, f"unsupported function {name}")
    return "false", "bool"


# ---------------------------------------------------------------------------
# Small ASL expressions found in the XML prose and value tables
# ("UInt(immh :: immb) - 64", "imm5<4:1>", "UInt('0' :: Rm)", "64 - UInt(imm6)").


class AslError(Exception):
    pass


def asl_tokens(text):
    toks = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("::", i):
            toks.append("::")
            i += 2
        elif c == "'":
            j = text.index("'", i + 1)
            toks.append(("bits", text[i + 1 : j]))
            i = j + 1
        elif c.isdigit():
            j = i
            while j < len(text) and text[j].isdigit():
                j += 1
            toks.append(("int", int(text[i:j])))
            i = j
        elif c.isalpha() or c == "_":
            j = i
            while j < len(text) and (text[j].isalnum() or text[j] == "_"):
                j += 1
            toks.append(("id", text[i:j]))
            i = j
        elif text[i : i + 2] in ("==", "!=", "&&", "||", "<=", ">="):
            toks.append(text[i : i + 2])
            i += 2
        elif c in "()[]<>:+-*,!{}":
            toks.append(c)
            i += 1
        else:
            raise AslError(f"unexpected {c!r} in {text!r}")
    return toks


class AslParser:
    """expr := term (('+'|'-') term)*; term := atom ('*' atom)*;
    atom := concat; concat := primary ('::' primary)*;
    primary := int | bits | field slice? | UInt(expr) | SInt(expr) | '(' expr ')'"""

    def __init__(self, text, scope, where):
        self.toks = asl_tokens(text)
        self.i = 0
        self.scope = scope
        self.where = where

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, want=None):
        t = self.peek()
        if t is None or (want is not None and t != want):
            raise AslError(f"expected {want!r}, found {t!r}")
        self.i += 1
        return t

    def parse(self):
        v = self.expr()
        if self.peek() is not None:
            raise AslError(f"trailing {self.peek()!r}")
        return v

    # Values are (rust code, width or None for integers).
    def expr(self):
        a = self.term()
        while self.peek() in ("+", "-"):
            op = self.take()
            b = self.term()
            a = (f"({int_of(a)} {op} {int_of(b)})", None)
        return a

    def term(self):
        a = self.concat()
        while self.peek() == "*":
            self.take()
            b = self.concat()
            a = (f"({int_of(a)} * {int_of(b)})", None)
        return a

    def concat(self):
        a = self.primary()
        while self.peek() == "::":
            self.take()
            b = self.primary()
            if a[1] is None or b[1] is None:
                raise AslError("concatenation of an integer")
            a = (f"(({a[0]} << {b[1]}) | {b[0]})", a[1] + b[1])
        return a

    def primary(self):
        t = self.take()
        if t == "(":
            v = self.expr()
            self.take(")")
            return v
        if isinstance(t, tuple) and t[0] == "int":
            return (f"{t[1]}", None)
        if isinstance(t, tuple) and t[0] == "bits":
            return (f"{int(t[1], 2) if t[1] else 0:#x}", len(t[1]))
        if isinstance(t, tuple) and t[0] == "id":
            name = t[1]
            if name in ("UInt", "SInt") and self.peek() == "(":
                self.take("(")
                v = self.expr()
                self.take(")")
                if v[1] is None:
                    return v
                if name == "UInt":
                    return (f"({v[0]} as i64)", None)
                return (f"sext({v[0]} as i64, {v[1]})", None)
            if name not in self.scope:
                raise AslError(f"unknown field {name}")
            lo, width = self.scope[name]
            code = f"((w >> {lo}) & {(1 << width) - 1:#x})"
            if self.peek() == "[" or (self.peek() == "<" and self.is_slice()):
                close = ">" if self.take() == "<" else "]"
                hi = self.take()[1]
                low = hi
                if self.peek() == ":":
                    self.take(":")
                    low = self.take()[1]
                self.take(close)
                if not (0 <= low <= hi < width):
                    raise AslError(f"bad slice {name}<{hi}:{low}>")
                return (f"((w >> {lo + low}) & {(1 << (hi - low + 1)) - 1:#x})", hi - low + 1)
            return (code, width)
        raise AslError(f"unexpected {t!r}")


    def is_slice(self):
        """'<' after a field starts a slice (imm5<4:1>), not a comparison."""
        t = self.toks[self.i + 1 : self.i + 5]
        if len(t) >= 2 and isinstance(t[0], tuple) and t[0][0] == "int":
            return t[1] == ">" or (len(t) >= 4 and t[1] == ":" and t[3] == ">")
        return False


class AslCond(AslParser):
    """Boolean ASL conditions of decode pseudocode, compiled to Rust.

    cond := or; or := and ('||' and)*; and := unary ('&&' unary)*;
    unary := '!' unary | '(' cond ')' | cmp | call; cmp := expr op (expr | bits) | expr IN set
    """

    def parse_cond(self):
        v = self.or_()
        if self.peek() is not None:
            raise AslError(f"trailing {self.peek()!r}")
        return v

    def or_(self):
        a = self.and_()
        while self.peek() == "||":
            self.take()
            a = f"({a} || {self.and_()})"
        return a

    def and_(self):
        a = self.unary()
        while self.peek() == "&&":
            self.take()
            a = f"({a} && {self.unary()})"
        return a

    def unary(self):
        t = self.peek()
        if t == "!":
            self.take()
            return f"!{self.unary()}"
        if t == "(":
            # A parenthesised condition, or a parenthesised value in a comparison.
            save = self.i
            self.take()
            try:
                inner = self.or_()
                self.take(")")
                if self.peek() not in ("==", "!=", "<", ">", "<=", ">=", "IN", "+", "-", "*", "::"):
                    return f"({inner})"
            except AslError:
                pass
            self.i = save
        if isinstance(t, tuple) and t[0] == "id":
            nxt = self.toks[self.i + 1] if self.i + 1 < len(self.toks) else None
            if t[1] == "IsFeatureImplemented" or t[1].startswith("Have"):
                # Every feature is accepted (see compile_call).
                self.take()
                depth = 0
                while True:
                    x = self.take()
                    depth += x == "("
                    depth -= x == ")"
                    if depth == 0:
                        break
                return "true"
            if t[1] in ("TRUE", "FALSE"):
                self.take()
                return "true" if t[1] == "TRUE" else "false"
        return self.cmp()

    def cmp(self):
        a = self.expr()
        op = self.take()
        if op == ("id", "IN"):
            self.take("{")
            alts = []
            while True:
                b = self.take()
                if not (isinstance(b, tuple) and b[0] in ("bits", "int")):
                    raise AslError(f"set element {b!r}")
                alts.append(self.compare(a, "==", b))
                if self.peek() == ",":
                    self.take()
                    continue
                self.take("}")
                break
            return "(" + " || ".join(alts) + ")"
        if op not in ("==", "!=", "<", ">", "<=", ">="):
            raise AslError(f"expected comparison, found {op!r}")
        if isinstance(self.peek(), tuple) and self.peek()[0] == "bits":
            return self.compare(a, op, self.take())
        b = self.expr()
        if a[1] is not None and b[1] is not None and op in ("==", "!="):
            return f"({a[0]} {op} {b[0]})"
        return f"({int_of(a)} {op} {int_of(b)})"

    def compare(self, a, op, b):
        if b[0] == "int":
            return f"({int_of(a)} {op} {b[1]})"
        bits = b[1].replace(" ", "")
        m, v, n = pattern(bits)
        if a[1] is not None and a[1] != n:
            raise AslError(f"comparing {a[1]} bits with '{bits}'")
        if op not in ("==", "!="):
            raise AslError(f"ordered comparison with bits '{bits}'")
        full = (1 << n) - 1
        lhs = a[0] if m == full else f"({a[0]} & {m:#x})"
        return f"({lhs} {op} {v:#x})"


def int_of(v):
    code, width = v
    return code if width is None else f"({code} as i64)"


def asl_value(text, scope, where):
    """Compiles an ASL expression to Rust code producing an i64."""
    v = AslParser(text, scope, where).parse()
    return int_of(v), v[1]


# ---------------------------------------------------------------------------
# Decode pseudocode: when an encoding is UNDEFINED
#
# The decode section of each instruction is translated to a Rust function that
# returns true when the pseudocode reaches EndOfDecode(Decode_UNDEF). Only a
# subset of ASL is needed: let/var, assignments, if/elsif/else, case/when, and
# expressions over encoding fields. A condition the translator cannot express
# (CONSTRAINED UNPREDICTABLE choices, implementation-defined vector lengths)
# makes it skip that statement: the encoding then decodes, which is how
# Fulgurite treats CONSTRAINED UNPREDICTABLE encodings everywhere.


class Untranslatable(Exception):
    pass


ASL_PUNCT = ["==", "!=", "<=", ">=", "&&", "||", "::", "=>", "<<", ">>", "..",
             "(", ")", "[", "]", "{", "}", ",", ";", ":", "=", "<", ">", "+", "-", "*", "/", "!"]


def asl_lex(text):
    text = re.sub(r"//[^\n]*", "", text)
    toks = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == "'":
            j = text.index("'", i + 1)
            toks.append(("bits", text[i + 1 : j].replace(" ", "")))
            i = j + 1
            continue
        if c.isdigit():
            m = re.match(r"0x[0-9a-fA-F_]+|\d+", text[i:])
            v = m.group(0)
            toks.append(("int", int(v.replace("_", ""), 0)))
            i += len(v)
            continue
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", text[i:])
            toks.append(("id", m.group(0)))
            i += len(m.group(0))
            continue
        if c == '"':
            j = text.index('"', i + 1)
            toks.append(("str", text[i + 1 : j]))
            i = j + 1
            continue
        for pnc in ASL_PUNCT:
            if text.startswith(pnc, i):
                toks.append(pnc)
                i += len(pnc)
                break
        else:
            # Unknown punctuation: the statement using it is skipped.
            toks.append(("?", c))
            i += 1
    return toks


class AslProgram:
    """Parses a decode section into statements."""

    def __init__(self, text):
        self.toks = asl_lex(text)
        self.i = 0

    def peek(self, k=0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def take(self, want=None):
        t = self.peek()
        if t is None or (want is not None and t != want):
            raise Untranslatable(f"expected {want!r}, found {t!r}")
        self.i += 1
        return t

    def kw(self, word):
        return self.peek() == ("id", word)

    def statements(self, stop=()):
        out = []
        while self.peek() is not None and not any(self.kw(w) for w in stop):
            out.append(self.statement())
        return out

    def skip_statement(self):
        """Skips to the end of the current simple statement."""
        depth = 0
        while True:
            t = self.take()
            if t in ("(", "[", "{"):
                depth += 1
            elif t in (")", "]", "}"):
                depth -= 1
            elif t == ";" and depth == 0:
                return

    def statement(self):
        start = self.i
        try:
            return self._statement()
        except Untranslatable as e:
            # Recover at the statement level: an unparsable if/case block is
            # skipped as a whole by tracking its 'end;'.
            self.i = start
            self.skip_block()
            return ("skip", str(e))

    def skip_block(self):
        first = self.take()
        if first in (("id", "if"), ("id", "case"), ("id", "for"), ("id", "while")):
            depth = 1
            while depth:
                t = self.take()
                if t in (("id", "if"), ("id", "case"), ("id", "for"), ("id", "while")):
                    # 'if' inside an expression ('x = if c then a else b;') has no 'end'.
                    if t == ("id", "if") and self.expr_if_ahead():
                        continue
                    depth += 1
                elif t == ("id", "end"):
                    depth -= 1
            self.take(";")
        else:
            self.i -= 1
            self.skip_statement()

    def expr_if_ahead(self):
        """True if the 'if' just taken is an expression (then ... else ..., no end)."""
        depth = 0
        j = self.i
        while j < len(self.toks):
            t = self.toks[j]
            if t == ("id", "then"):
                # statement ifs have statements (ending in ';') before else/end
                k = j + 1
                d2 = 0
                while k < len(self.toks):
                    u = self.toks[k]
                    if u in ("(", "["):
                        d2 += 1
                    elif u in (")", "]"):
                        d2 -= 1
                    elif d2 == 0 and u == ";":
                        return False
                    elif d2 == 0 and u == ("id", "else"):
                        return True
                    k += 1
                return False
            j += 1
        return False

    def _statement(self):
        t = self.peek()
        if t == ("id", "if"):
            self.take()
            arms = []
            cond = self.expr()
            self.take(("id", "then"))
            body = self.statements(("elsif", "else", "end"))
            arms.append((cond, body))
            other = []
            while True:
                if self.kw("elsif"):
                    self.take()
                    c = self.expr()
                    self.take(("id", "then"))
                    arms.append((c, self.statements(("elsif", "else", "end"))))
                elif self.kw("else"):
                    self.take()
                    other = self.statements(("end",))
                else:
                    break
            self.take(("id", "end"))
            self.take(";")
            return ("if", arms, other)
        if t == ("id", "case"):
            self.take()
            subject = self.expr()
            self.take(("id", "of"))
            arms, other = [], None
            while self.kw("when"):
                self.take()
                pats = [self.expr()]
                while self.peek() == ",":
                    self.take()
                    pats.append(self.expr())
                self.take("=>")
                arms.append((pats, self.statements(("when", "otherwise", "end"))))
            if self.kw("otherwise"):
                self.take()
                self.take("=>")
                other = self.statements(("end",))
            self.take(("id", "end"))
            self.take(";")
            return ("case", subject, arms, other)
        if t == ("id", "EndOfDecode"):
            self.take()
            self.take("(")
            kind = self.take()[1]
            self.take(")")
            self.take(";")
            return ("end", kind)
        if t in (("id", "let"), ("id", "var"), ("id", "constant")):
            self.take()
            name = self.take()
            if not (isinstance(name, tuple) and name[0] == "id"):
                raise Untranslatable("tuple binding")
            if self.peek() == ":":
                self.take()
                self.type_()
            if self.peek() == "=":
                self.take()
                e = self.expr()
                self.take(";")
                return ("let", name[1], e)
            self.take(";")
            return ("let", name[1], None)
        if isinstance(t, tuple) and t[0] == "id" and self.peek(1) == "=":
            self.take()
            self.take("=")
            e = self.expr()
            self.take(";")
            return ("set", t[1], e)
        if t in (("id", "assert"),):
            self.skip_statement()
            return ("nop",)
        raise Untranslatable(f"statement starting {t!r}")

    def type_(self):
        """Skips a type: integer{..}, bits(N), boolean, Constraint..."""
        self.take()
        if self.peek() == "{":
            depth = 0
            while True:
                t = self.take()
                depth += t == "{"
                depth -= t == "}"
                if depth == 0:
                    break
        if self.peek() == "(":
            depth = 0
            while True:
                t = self.take()
                depth += t == "("
                depth -= t == ")"
                if depth == 0:
                    break

    # Expressions: precedence climbing.
    BINARY = [
        ("||",), ("&&",), ("==", "!=", "<", ">", "<=", ">=", ("id", "IN")),
        ("+", "-", ("id", "OR"), ("id", "XOR")), ("*", "/", ("id", "DIV"), ("id", "MOD"), ("id", "AND"), "<<", ">>"),
        ("::",),
    ]

    def expr(self, level=0):
        if self.kw("if"):
            self.take()
            c = self.expr()
            self.take(("id", "then"))
            a = self.expr()
            self.take(("id", "else"))
            b = self.expr()
            return ("ifx", c, a, b)
        if level == len(self.BINARY):
            return self.unary()
        left = self.expr(level + 1)
        while self.peek() in self.BINARY[level]:
            op = self.take()
            op = op[1] if isinstance(op, tuple) else op
            if op == "IN":
                right = self.set_()
            else:
                right = self.expr(level + 1)
            left = ("bin", op, left, right)
        return left

    def set_(self):
        self.take("{")
        vals = [self.expr()]
        while self.peek() == ",":
            self.take()
            vals.append(self.expr())
        self.take("}")
        return ("set", vals)

    def unary(self):
        t = self.peek()
        if t == "!":
            self.take()
            return ("not", self.unary())
        if t == "-":
            self.take()
            return ("neg", self.unary())
        return self.postfix(self.primary())

    def postfix(self, e):
        while self.peek() == "[":
            self.take()
            hi = self.expr()
            lo = hi
            if self.peek() == ":":
                self.take()
                lo = self.expr()
            self.take("]")
            e = ("slice", e, hi, lo)
        return e

    def primary(self):
        t = self.take()
        if t == "(":
            e = self.expr()
            if self.peek() == ",":
                raise Untranslatable("tuple")
            self.take(")")
            return e
        if isinstance(t, tuple) and t[0] in ("int", "bits"):
            return t
        if isinstance(t, tuple) and t[0] == "id":
            if self.peek() == "{":
                # Function with a width parameter: Zeros{N}(), Ones{N}
                self.take()
                width = self.expr()
                self.take("}")
                args = []
                if self.peek() == "(":
                    args = self.args()
                return ("call", t[1], args, width)
            if self.peek() == "(":
                return ("call", t[1], self.args(), None)
            return ("id", t[1])
        raise Untranslatable(f"unexpected {t!r}")

    def args(self):
        self.take("(")
        out = []
        if self.peek() != ")":
            out.append(self.expr())
            while self.peek() == ",":
                self.take()
                out.append(self.expr())
        self.take(")")
        return out


class RustGen:
    """Translates parsed decode statements to Rust returning true on UNDEFINED
    (or, with `unpredictable`, on reaching a CONSTRAINED UNPREDICTABLE choice)."""

    def __init__(self, scope, unpredictable=False):
        self.unpredictable = unpredictable
        self.scope = scope  # field -> (lo, width)
        self.locals = {}  # name -> ('int'|'bool'|('bits', w)) of translatable locals
        self.dead = set()  # locals that could not be translated
        self.lines = []
        self.undef_paths = 0

    # Values are (code, type): type 'int' (i64), 'bool', ('bits', width) as u64.
    def e(self, x):
        k = x[0]
        if k == "int":
            return f"{x[1]}i64", "int"
        if k == "bits":
            if "x" in x[1]:
                raise Untranslatable("pattern outside comparison")
            return (f"{int(x[1], 2) if x[1] else 0:#x}u64", ("bits", len(x[1])))
        if k == "id":
            n = x[1]
            if n in ("TRUE", "FALSE"):
                return ("true" if n == "TRUE" else "false"), "bool"
            if n in self.locals:
                return f"l_{n}", self.locals[n]
            if n in self.dead:
                raise Untranslatable(f"local {n}")
            if n in self.scope:
                lo, w = self.scope[n]
                return f"(((w >> {lo}) & {(1 << w) - 1:#x}) as u64)", ("bits", w)
            raise Untranslatable(f"name {n}")
        if k == "not":
            c, t = self.e(x[1])
            if t != "bool":
                raise Untranslatable("NOT of bits")
            return f"!{c}", "bool"
        if k == "neg":
            c, t = self.e(x[1])
            return f"(-{self.int(c, t)})", "int"
        if k == "ifx":
            c = self.cond(x[1])
            a, ta = self.e(x[2])
            b, tb = self.e(x[3])
            if ta != tb:
                if {ta, tb} <= {"int"} or (isinstance(ta, tuple) and isinstance(tb, tuple)):
                    pass
                else:
                    a, b = self.int(a, ta), self.int(b, tb)
                    ta = "int"
            return f"(if {c} {{ {a} }} else {{ {b} }})", ta
        if k == "slice":
            base, t = self.e(x[1])
            hi = self.const_int(x[2])
            lo = self.const_int(x[3])
            if not isinstance(t, tuple):
                if t != "int":
                    raise Untranslatable("slice of bool")
                base = f"({base} as u64)"
            width = hi - lo + 1
            return f"(({base} >> {lo}) & {(1 << width) - 1:#x})", ("bits", width)
        if k == "call":
            return self.call(x)
        if k == "bin":
            return self.binary(x)
        raise Untranslatable(f"expression {k}")

    def const_int(self, x):
        if x[0] == "int":
            return x[1]
        if x[0] == "bin" and x[1] in ("+", "-") and x[2][0] == "int" and x[3][0] == "int":
            return x[2][1] + x[3][1] if x[1] == "+" else x[2][1] - x[3][1]
        raise Untranslatable("non-constant slice bound")

    def int(self, c, t):
        if t == "int":
            return c
        if isinstance(t, tuple):
            return f"({c} as i64)"
        raise Untranslatable("bool used as integer")

    def cond(self, x):
        c, t = self.e(x)
        if t != "bool":
            raise Untranslatable("condition is not boolean")
        return c

    def call(self, x):
        _, name, args, width = x
        if name in ("IsFeatureImplemented",) or name.startswith("Have"):
            return "true", "bool"
        if name in ("UInt",):
            c, t = self.e(args[0])
            return self.int(c, t), "int"
        if name == "SInt":
            c, t = self.e(args[0])
            if not isinstance(t, tuple):
                raise Untranslatable("SInt of int")
            return f"sext({c} as i64, {t[1]})", "int"
        if name in ("IsZero", "IsOnes"):
            c, t = self.e(args[0])
            if not isinstance(t, tuple):
                raise Untranslatable(f"{name} of int")
            target = 0 if name == "IsZero" else (1 << t[1]) - 1
            return f"({c} == {target:#x})", "bool"
        if name in ("BitCount",):
            c, t = self.e(args[0])
            return f"(({c}).count_ones() as i64)", "int"
        if name in ("LowestSetBit", "LowestSetBitNZ"):
            c, t = self.e(args[0])
            w = t[1] if isinstance(t, tuple) else 64
            return f"(if {c} == 0 {{ {w}i64 }} else {{ ({c}).trailing_zeros() as i64 }})", "int"
        if name in ("HighestSetBit", "HighestSetBitNZ"):
            c, t = self.e(args[0])
            return f"(63 - ({c} as u64).leading_zeros() as i64)", "int"
        if name in ("ZeroExtend",) and len(args) == 1 and width is not None:
            c, t = self.e(args[0])
            return c, ("bits", self.const_int(width))
        if name == "Zeros" and width is not None:
            return "0u64", ("bits", self.const_int(width))
        if name == "Ones" and width is not None:
            n = self.const_int(width)
            return f"{(1 << n) - 1:#x}u64", ("bits", n)
        raise Untranslatable(f"function {name}")

    def binary(self, x):
        _, op, l, r = x
        if op in ("&&", "||"):
            return f"({self.cond(l)} {op} {self.cond(r)})", "bool"
        if op == "IN":
            a, ta = self.e(l)
            alts = [self.compare(a, ta, "==", v) for v in r[1]]
            return "(" + " || ".join(alts) + ")", "bool"
        if op in ("==", "!=", "<", ">", "<=", ">="):
            a, ta = self.e(l)
            return self.compare(a, ta, op, r), "bool"
        if op == "::":
            a, ta = self.e(l)
            b, tb = self.e(r)
            if not (isinstance(ta, tuple) and isinstance(tb, tuple)):
                raise Untranslatable("concatenation of integers")
            return f"(({a} << {tb[1]}) | {b})", ("bits", ta[1] + tb[1])
        a, ta = self.e(l)
        b, tb = self.e(r)
        if op in ("AND", "OR", "XOR") and isinstance(ta, tuple):
            rop = {"AND": "&", "OR": "|", "XOR": "^"}[op]
            return f"({a} {rop} {b})", ta
        ops = {"+": "+", "-": "-", "*": "*", "DIV": "/", "MOD": "%", "<<": "<<", ">>": ">>", "/": "/"}
        if op not in ops:
            raise Untranslatable(f"operator {op}")
        ai, bi = self.int(a, ta), self.int(b, tb)
        if op == "MOD":
            return f"({ai}).rem_euclid({bi})", "int"
        if op == "DIV":
            return f"({ai}).div_euclid({bi})", "int"
        if op in ("<<", ">>"):
            return f"({ai} {ops[op]} ({bi} as u32))", "int"
        return f"({ai} {ops[op]} {bi})", "int"

    def compare(self, a, ta, op, r):
        if r[0] == "bits" and "x" in r[1]:
            m, v, n = pattern(r[1])
            if op not in ("==", "!="):
                raise Untranslatable("ordered pattern comparison")
            full = (1 << n) - 1
            lhs = a if m == full else f"({a} & {m:#x})"
            return f"({lhs} {op} {v:#x})"
        b, tb = self.e(r)
        if isinstance(ta, tuple) and isinstance(tb, tuple):
            if ta[1] != tb[1]:
                raise Untranslatable("comparing bits of different widths")
            return f"({a} {op} {b})"
        if ta == "bool" and tb == "bool":
            return f"({a} {op} {b})"
        return f"({self.int(a, ta)} {op} {self.int(b, tb)})"

    # Statements
    def block(self, stmts, ind):
        for st in stmts:
            self.stmt(st, ind)

    def stmt(self, st, ind):
        pad = "    " * ind
        k = st[0]
        if k in ("nop", "skip"):
            return
        if k == "end":
            if st[1] == "Decode_UNDEF" and not self.unpredictable:
                self.lines.append(f"{pad}return true;")
                self.undef_paths += 1
            else:
                self.lines.append(f"{pad}return false;")
            return
        if k == "let":
            name, ex = st[1], st[2]
            if ex is None:
                self.dead.add(name)
                return
            if self.unpredictable and ex[0] == "call" and ex[1] == "ConstrainUnpredictable":
                self.lines.append(f"{pad}return true;")
                self.undef_paths += 1
                return
            try:
                c, t = self.e(ex)
            except Untranslatable:
                self.dead.add(name)
                self.locals.pop(name, None)
                return
            self.locals[name] = t
            ty = "bool" if t == "bool" else ("i64" if t == "int" else "u64")
            self.lines.append(f"{pad}let mut l_{name}: {ty} = {c};")
            return
        if k == "set":
            name, ex = st[1], st[2]
            if self.unpredictable and ex[0] == "call" and ex[1] == "ConstrainUnpredictable":
                self.lines.append(f"{pad}return true;")
                self.undef_paths += 1
                return
            if name not in self.locals:
                return
            try:
                c, t = self.e(ex)
            except Untranslatable:
                # The local's value is no longer known.
                self.locals.pop(name, None)
                self.dead.add(name)
                return
            self.lines.append(f"{pad}l_{name} = {c};")
            return
        if k == "if":
            arms, other = st[1], st[2]
            try:
                conds = [self.cond(c) for c, _ in arms]
            except Untranslatable:
                return
            for i, ((_, body), c) in enumerate(zip(arms, conds)):
                kw = "if" if i == 0 else "} else if"
                self.lines.append(f"{pad}{kw} {c} {{")
                self.block(body, ind + 1)
            if other:
                self.lines.append(f"{pad}}} else {{")
                self.block(other, ind + 1)
            self.lines.append(f"{pad}}}")
            return
        if k == "case":
            subject, arms, other = st[1], st[2], st[3]
            try:
                a, ta = self.e(subject)
                conds = [" || ".join(self.compare(a, ta, "==", p) for p in pats) for pats, _ in arms]
            except Untranslatable:
                return
            for i, ((_, body), c) in enumerate(zip(arms, conds)):
                kw = "if" if i == 0 else "} else if"
                self.lines.append(f"{pad}{kw} {c} {{")
                self.block(body, ind + 1)
            if other is not None:
                self.lines.append(f"{pad}}} else {{")
                self.block(other, ind + 1)
            if arms:
                self.lines.append(f"{pad}}}")
            return
        raise Untranslatable(f"statement {k}")


def decode_local(ctx, name):
    """Rust expression (i64) for a top-level local of the decode pseudocode,
    when it can be computed from the encoding fields, else None."""
    enc = ctx.encname if ctx.encname in ctx.spec.decode_ps else ctx.leaf.name
    code = ctx.spec.decode_ps.get(enc)
    if not code:
        return None
    try:
        prog = AslProgram(code).statements()
    except Untranslatable:
        return None
    gen = RustGen(ctx.scope)
    for st in prog:
        if st[0] != "let" or st[2] is None:
            continue
        try:
            c, t = gen.e(st[2])
        except Untranslatable:
            gen.dead.add(st[1])
            gen.locals.pop(st[1], None)
            continue
        if t == "bool":
            gen.locals[st[1]] = t
            gen.lines.append(f"let l_{st[1]}: bool = {c};")
            continue
        ci = gen.int(c, t)
        gen.locals[st[1]] = "int"
        gen.lines.append(f"let l_{st[1]}: i64 = {ci};")
        if st[1] == name:
            return "{ " + " ".join(gen.lines) + f" l_{name} }}"
    return None


def exec_unpredictable(spec, enc, decode, scope):
    """Condition for the register checks the execute pseudocode makes through
    Check{CPY,SET}ConstrainedUnpredictable(), with its parameters bound to the
    encoding fields the decode pseudocode assigns them from."""
    kind, args = spec.exec_checks[enc]
    params, conds = spec.shared_checks.get(kind, ([], []))
    if not conds or len(params) != len(args):
        PROBLEMS.add(enc, f"execute check {kind} not understood")
        return None
    # memcpy.n = UInt(Rn);  Parameters are bound to the call's arguments,
    # then struct members to the fields the decode pseudocode assigns them.
    fields = dict(re.findall(r"(\w+\.\w+) = UInt\((\w+)\);", decode))
    binding = dict(zip(params, args))
    parts = []
    for c in conds:
        text = re.sub(r"\b(\w+)\b(?!\.)", lambda m: binding.get(m.group(1), m.group(1)), c)
        text = re.sub(r"(?<![\w.])(\w+)\.(\w+)", lambda m: binding.get(m.group(1), m.group(1)) + "." + m.group(2), text)
        missing = [x for x in re.findall(r"\w+\.\w+", text) if x not in fields]
        if missing:
            PROBLEMS.add(enc, f"execute check: {missing} not assigned in decode")
            return None
        text = re.sub(r"\w+\.\w+", lambda m: f"UInt({fields[m.group(0)]})", text)
        try:
            parts.append(RustGen(scope).cond(AslProgram(text).expr()))
        except Untranslatable as e:
            PROBLEMS.add(enc, f"execute check: {e}")
            return None
    return "(" + " || ".join(parts) + ")"


def undef_function(code, scope, where, unpredictable=False):
    """Rust body (statements) of the UNDEFINED (or UNPREDICTABLE) check, or
    None if it never fires."""
    try:
        prog = AslProgram(code).statements()
    except Untranslatable as e:
        PROBLEMS.add(where, f"decode pseudocode: {e}")
        return None
    gen = RustGen(scope, unpredictable)
    gen.block(prog, 1)
    if gen.undef_paths == 0:
        return None
    return "\n".join(gen.lines)


# ---------------------------------------------------------------------------
# Operands


class Interned:
    """Deduplicated values, numbered from 0 in insertion order."""

    def __init__(self):
        self.ids = OrderedDict()

    def add(self, key):
        if key not in self.ids:
            self.ids[key] = len(self.ids)
        return self.ids[key]


class Operand:
    """One operand: how to compute its value and how to print it.

    kind is one of
      ('reg', prefix, suffix, r31)  register name: prefix + value + suffix, or r31 for 31
      ('imm', hex)                   '#' + value
      ('num',)                       value without '#'
      ('hex', hash)                  value in hexadecimal, with '#' if hash
      ('label',) / ('page',)         a code address: pc + value / page(pc) + value
      ('table', table id)            value looked up in a value table
      ('bitmask', width)             logical immediate (value = N:immr:imms)
      ('fpimm',)                     8-bit floating-point immediate
      ('sysreg',)                    system register (value = op0:op1:CRn:CRm:op2)
      ('flag', text)                 text when value is non-zero, nothing otherwise
      ('const', text)                fixed text (value unused)
      ('za_mask',)                   SME ZERO tile list
    """

    def __init__(self, kind, val, default=None, valid=None, when=0):
        self.kind = kind
        self.val = val  # value expression id
        self.default = default  # value at which an optional group is left out
        self.valid = valid  # (lo, hi): other values are reserved encodings
        self.when = when  # condition id: the operand applies only when it holds

    def key(self):
        return (self.kind, self.val, self.default, self.valid, self.when)


class Tables:
    """All generated data, shared between encodings."""

    def __init__(self):
        self.values = Interned()  # rust i64 expression over w
        self.ops = Interned()  # Operand.key()
        self.vtables = Interned()  # tuple of (mask, value, entry)
        self.strings = Interned()
        self.conds = CondTable()

    def value(self, code):
        return self.values.add(code)

    def op(self, operand):
        return self.ops.add(operand.key())


FIELD_LIST = re.compile(r'^\(?\s*([A-Za-z0-9_<>:\[\] ]+?)\s*\)?$')


def fields_of(encodedin, scope, where):
    """'(immhi :: immlo)', 'imms:immr', 'H:L:M' -> rust code, width."""
    s = encodedin.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1]
    parts = [p.strip() for p in re.split(r"::|:(?![0-9]+[>\]])", s) if p.strip()]
    p = AslParser(" :: ".join(parts), scope, where)
    v = p.concat()
    if p.peek() is not None:
        raise AslError(f"bad field list {encodedin!r}")
    return v


def variant_text(ex, label):
    """The part of an explanation that applies to one encoding.

    Shared explanations read 'For the "32-bit" variant: ... For the "64-bit"
    variant: ...'; this returns the paragraph naming `label`, or the whole text.
    """
    text = ex.text
    parts = re.split(r'(For the (?:"[^"]+"(?:,? and |, )?)+ variants?: )', text)
    if len(parts) == 1:
        return text
    chosen = None
    for i in range(1, len(parts), 2):
        names = re.findall(r'"([^"]+)"', parts[i])
        if label in names:
            chosen = parts[i + 1]
    if chosen is None:
        # The label is not mentioned: use the text before the first variant
        # paragraph if any, else the first paragraph.
        chosen = parts[0].strip() or parts[2]
    return chosen.strip()


NUM = r"(-?\d+)"


def prose_value(text, encodedin, scope, where):
    """Value of an operand described in prose.

    Returns (rust i64 code, signed, scale) or raises AslError.
    """
    t = text
    m = re.search(r'encoded (?:in|as) (?:the )?"([^"]+)"(?: and "([^"]+)")?(?: fields?)?', t)
    if m and m.group(2) and re.search(r"\bname of\b", t):
        # A register named by two fields that hold the same number (CINC: Rn = Rm).
        src = m.group(1)
    elif m:
        src = m.group(1) + (":" + m.group(2) if m.group(2) else "")
    elif encodedin:
        src = encodedin
    else:
        raise AslError("no encoding field")
    if (m2 := re.search(r'encoded as (\d+) (?:minus|-) (?:UInt\()?"([^"]+)"\)?', t)):
        raw, w = fields_of(m2.group(2), scope, where)
        return f"({m2.group(1)} - ({raw} as i64))", False, 1
    if (m2 := re.search(r'encoded as UInt\("([^"]+)"\) - (\d+)', t)) or (
        m2 := re.search(r'encoded as "([^"]+)" minus (\d+)', t)
    ):
        raw, w = fields_of(m2.group(1), scope, where)
        return f"(({raw} as i64) - {m2.group(2)})", False, 1
    raw, width = fields_of(src, scope, where)
    signed = bool(re.search(r"\bsigned\b|negative|offset from the (?:page )?address", t)) and not re.search(
        r"\bunsigned\b", t
    )
    val = f"sext({raw} as i64, {width})" if signed else f"({raw} as i64)"
    if re.search(r"negative offset", t) and re.search(r"unsigned value", t):
        val = f"(-{val})"
    scale = 1
    if (m2 := re.search(r"times (\d+)(?: plus (\d+))?", t)):
        scale = int(m2.group(1))
        val = f"({val} * {scale})"
        if m2.group(2):
            val = f"({val} + {m2.group(2)})"
    elif (m2 := re.search(r"as <\w+>/(\d+)", t)) or (m2 := re.search(r"a multiple of (\d+)", t)):
        scale = int(m2.group(1))
        val = f"({val} * {scale})"
    if (m2 := re.search(r'plus (\d+) modulo (\d+)', t)):
        val = f"(({val} + {m2.group(1)}) % {m2.group(2)})"
    elif (m2 := re.search(r'"(?: plus |\s*\+)(\d+)', t)):
        if re.search(r"if \"\w+\" = '11111'", t):
            # SYSP <Xt2>: Rt + 1, but XZR when Rt is XZR.
            val = f"(if {val} == 31 {{ 31 }} else {{ {val} + {m2.group(1)} }})"
        else:
            val = f"({val} + {m2.group(1)})"
    return val, signed, scale


def stated_range(text):
    m = re.search(r"in the range (?:of )?" + NUM + r" to " + NUM, text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def stated_default(text):
    m = re.search(r"default(?:ing|s)? (?:to|is) (?:'|#)?([-\w]+)", text, re.I)
    if m:
        return m.group(1)
    m = re.search(r"(\d+) \(the default\)", text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Assembler templates


class Ctx:
    """What a template is being compiled for."""

    def __init__(self, spec, tables, leaf, encname, scope, meta=None):
        self.spec = spec
        self.meta = meta or {}  # JSON encoded_in: operand symbol -> field names
        self.fallback = False  # the XML does not describe this encoding
        self.tables = tables
        self.leaf = leaf  # the encoding's tree node
        self.encname = encname  # XML encoding name (aliases: ALIAS_PARENT)
        self.scope = scope
        self.label = spec.label.get(encname, "")
        self.where = encname

    def fixed_field(self, name):
        """Value of a field that the encoding fixes, or None."""
        if name not in self.scope:
            return None
        lo, width = self.scope[name]
        m = ((1 << width) - 1) << lo
        if self.leaf.mask & m != m:
            return None
        return (self.leaf.value & m) >> lo


def rule_empty(spec, asm, depth=0):
    """True if an alternative prints nothing (NULL, or rules without symbols)."""
    if asm is None:
        return True
    for sym in asm.get("symbols") or []:
        if sym["_type"].endswith("Literal"):
            return False
        r = spec.rules.get(sym["rule_id"])
        if r is None:
            continue
        t = r["_type"].split(".")[-1]
        if t == "Token":
            return False
        if t == "Rule":
            if not rule_empty(spec, r["symbols"], depth + 1):
                return False
        elif t == "Choice":
            if not all(rule_empty(spec, c, depth + 1) for c in r["choices"]):
                return False
    return True


def flat_alts(spec, rid, depth=0):
    """Alternatives of a rule as lists of atoms ('lit', s) / ('tok', name)."""
    r = spec.rules.get(rid)
    if r is None:
        return [[]]
    if rid in ("OPT_SPACE", "SPACE"):
        return [[("lit", " ")]]
    t = r["_type"].split(".")[-1]
    if t == "Token":
        if rid in ("UInteger", "SInteger", "Real"):
            return [[("tok", rid)]]
        return [[("lit", r["default"] or "")]]
    if t == "Rule":
        return flat_seq(spec, r["symbols"], depth)
    out = []
    for c in r["choices"]:
        out.extend(flat_seq(spec, c, depth))
    return out


def flat_seq(spec, asm, depth):
    if asm is None:
        return [[]]
    alts = [[]]
    for sym in asm.get("symbols") or []:
        if sym["_type"].endswith("Literal"):
            alts = [a + [("lit", sym["value"])] for a in alts]
        elif sym["rule_id"] == "hash":
            alts = [a + [("lit", "#")] for a in alts]
        else:
            sub = flat_alts(spec, sym["rule_id"], depth + 1) if depth < 8 else [[("deep",)]]
            alts = [a + s for a in alts for s in sub][:64]
    return alts


def lookup_expl(ctx, rid, r):
    ex = ctx.spec.expl.get((ctx.encname, rid))
    if ex is None and r.get("display"):
        # Some new instructions link a differently numbered copy of a rule;
        # match on the symbol as written in the template instead.
        for (enc, link), cand in ctx.spec.expl.items():
            if enc == ctx.encname and cand.symbol == r["display"]:
                return cand
    return ex


def compile_template(ctx, asm):
    """Items of one assembler template:
    ('text', s) | ('space',) | ('op', id) | ('opt', items) | ('alt', [items...])."""
    out = []
    walk_symbols(ctx, asm, out)
    return out


def walk_symbols(ctx, asm, out):
    spec = ctx.spec
    for sym in (asm or {}).get("symbols") or []:
        if sym["_type"].endswith("Literal"):
            out.append(("text", sym["value"]))
            continue
        rid = sym["rule_id"]
        r = spec.rules.get(rid)
        if r is None:
            continue
        t = r["_type"].split(".")[-1]
        if t == "Token":
            if rid == "SPACE":
                out.append(("space",))
            elif rid in ("UInteger", "SInteger", "Real"):
                PROBLEMS.add(ctx.where, f"bare number token {rid} outside an operand")
            else:
                out.append(("text", r["default"]))
            continue
        ex = lookup_expl(ctx, rid, r)
        if ex is None and ctx.fallback and (r.get("display") or "").startswith("<"):
            out.append(("op", json_operand(ctx, rid, r)))
            continue
        if ex is not None:
            op = build_operand(ctx, rid, r, ex)
            if op is not None:
                if op.kind[0] == "imm" and out and out[-1] == ("text", "#"):
                    # "#<imm>" where <imm> itself starts with an optional '#'
                    # (CBEQ...): one '#'.
                    out.pop()
                out.append(("op", op))
            continue
        if rid == "hash":
            out.append(("text", "#"))
            continue
        if rid == "OPT_SPACE":
            out.append(("text", " "))
            continue
        if t == "Rule":
            walk_symbols(ctx, r["symbols"], out)
            continue
        # A choice that is not an operand: optional parts and alternatives.
        alts = r["choices"]
        full = [a for a in alts if not rule_empty(spec, a)]
        if len(full) == len(alts):
            if len(full) == 1:
                walk_symbols(ctx, full[0], out)
            else:
                subs = []
                for a in full:
                    sub = []
                    walk_symbols(ctx, a, sub)
                    subs.append(sub)
                out.append(("alt", subs))
            continue
        subs = []
        for a in full:
            sub = []
            walk_symbols(ctx, a, sub)
            for it in sub:
                # An optional immediate without a stated default is left out at 0.
                if it[0] == "op" and it[1].default is None and it[1].kind[0] in ("num", "imm"):
                    it[1].default = 0
            subs.append(sub)
        out.append(("opt", subs[0] if len(subs) == 1 else [("alt", subs)]))


REG_SPECIAL = {"SP", "WSP", "XZR", "WZR", "ZR"}


class SkipEncoding(Exception):
    pass


def json_operand(ctx, rid, r):
    """An operand of an encoding the XML does not describe yet, from the JSON
    alone: only registers named directly by their field qualify."""
    disp = r["display"]
    fields = [x["value"] for x in ctx.meta.get(disp, [])]
    if (op := json_sysop_operand(ctx, rid, r, fields)) is not None:
        return op
    if len(fields) != 1 or fields[0] not in ctx.scope:
        raise SkipEncoding(f"{disp}: no single field")
    alts = flat_alts(ctx.spec, rid)
    special = [a for a in alts if len(a) == 1 and a[0][0] == "lit" and a[0][1] in REG_SPECIAL]
    numbered = [a for a in alts if any(x[0] == "tok" for x in a)]
    if len(numbered) != 1 or numbered[0][0][0] != "lit" or numbered[0][0][1] in ("#", ""):
        raise SkipEncoding(f"{disp}: not a register")
    lo, width = ctx.scope[fields[0]]
    val = f"(((w >> {lo}) & {(1 << width) - 1:#x}) as i64)"
    op = number_operand(ctx, numbered, val, None, None, ctx.where, special)
    if op is None or op.kind[0] != "reg":
        raise SkipEncoding(f"{disp}: not a register")
    return op


SYSOP_RULE = re.compile(r"[a-z]+_op_([01_]+)_([A-Z0-9]+)")


def json_sysop_operand(ctx, rid, r, fields):
    """A system operation name (<plbi_op>) of an alias the XML does not
    describe yet: a choice of rules each named after its encoding,
    plbi_op_000_1010_0001_000_VMALLE1OS for op1:CRn:CRm:op2. None if the
    rule has another shape."""
    if r["_type"] != "Instruction.Rules.Choice" or not fields or any(f not in ctx.scope for f in fields):
        return None
    widths = [ctx.scope[f][1] for f in fields]
    entries = []
    for alt in r["choices"]:
        syms = alt.get("symbols") or []
        if len(syms) != 1 or not syms[0]["_type"].endswith("RuleReference"):
            return None
        m = SYSOP_RULE.fullmatch(syms[0]["rule_id"])
        if not m:
            return None
        parts = m.group(1).split("_")
        if [len(p) for p in parts] != widths:
            raise SkipEncoding(f"{rid}: {syms[0]['rule_id']} does not match fields {fields}")
        lits = ["".join(a[1] for a in x if a[0] == "lit") for x in flat_alts(ctx.spec, syms[0]["rule_id"])]
        if lits != [m.group(2)]:
            raise SkipEncoding(f"{rid}: {syms[0]['rule_id']} prints {lits}")
        bits = "".join(parts)
        entries.append(((1 << len(bits)) - 1, int(bits, 2), ("text", m.group(2).lower())))
    raw, _ = fields_of(":".join(fields), ctx.scope, ctx.where)
    vt = ctx.tables.vtables.add(tuple(entries))
    return Operand(("table", vt), ctx.tables.value(f"({raw} as i64)"), None)


def build_operand(ctx, rid, r, ex):
    if ex.kind == "definition":
        return table_operand(ctx, rid, r, ex)
    text = variant_text(ex, ctx.label)
    where = f"{ctx.where} {ex.symbol}"
    for pat, symbol, fn in OVERRIDES:
        if symbol == ex.symbol and re.fullmatch(pat, ctx.encname):
            return fn(ctx, text, ex, where)
    when = 0
    if (m := re.match(r"When (\w+)<(\d+)> is set to ([01]), ", text)):
        try:
            code = AslCond(f"{m.group(1)}<{m.group(2)}> == '{m.group(3)}'", ctx.scope, where).parse_cond()
        except AslError as e:
            PROBLEMS.add(where, f"operand condition: {e}")
            return None
        when = ctx.tables.conds.add_code(code)
        text = text[m.end():]
    if (m := RESTRICTED.search(text)):
        return restricted_operand(ctx, rid, ex, text[: m.start()].rstrip(), m, where)
    op = build_operand_inner(ctx, rid, r, ex, text, where)
    if op is not None and when:
        op.when = when
    return op


# "Restricted to the range 0 to 1, encoded in "CRm<0>", when <pstatefield> is
# ALLINT, PM, SVCRSM, SVCRSMZA, or SVCRZA." (MSR immediate): the operand's
# encoding depends on the value another operand's table gives.
RESTRICTED = re.compile(
    r'Restricted to the range (\d+) to (\d+), encoded in "(\w+)<(\d+)(?::(\d+))?>", '
    r"when (<\w+>) is ([^.]+)\.")


def restricted_operand(ctx, rid, ex, text, m, where):
    """A number whose encoding is a slice of its field when another operand
    names one of the listed table rows, and the whole field otherwise."""
    lo_s, hi_s, fname, hi_bit, lo_bit, other, names = m.groups()
    hi_bit = int(hi_bit)
    lo_bit = int(lo_bit) if lo_bit is not None else hi_bit
    names = {n.strip() for n in re.split(r",|\bor\b", names) if n.strip()}
    sibling = [x for _, x in ctx.spec.expl_by_enc(ctx.encname) if x.symbol == other and x.table]
    if len(sibling) != 1:
        PROBLEMS.add(where, f"restricted encoding: no single table for {other}")
        return None
    table = sibling[0].table
    header = table[0]
    cols = [i for i, (cls, _) in enumerate(header) if cls == "bitfield"]
    sym_col = next((i for i, (cls, _) in enumerate(header) if cls == "symbol"), None)
    if not cols or sym_col is None:
        PROBLEMS.add(where, f"restricted encoding: table of {other} has no bitfield/symbol columns")
        return None
    try:
        raw, _ = fields_of(":".join(header[i][1] for i in cols), ctx.scope, where)
        flo, fwidth = ctx.scope[fname]
    except (AslError, KeyError) as e:
        PROBLEMS.add(where, f"restricted encoding: {e}")
        return None
    terms, seen = [], set()
    for row in table[1:]:
        if sym_col >= len(row) or row[sym_col][1].strip() not in names:
            continue
        mask = value = 0
        for i in cols:
            mk, v, n = pattern(row[i][1].replace(" ", ""))
            mask, value = (mask << n) | mk, (value << n) | v
        terms.append(f"(({raw} as u32) & {mask:#x}) == {value:#x}")
        seen.add(row[sym_col][1].strip())
    if seen != names:
        PROBLEMS.add(where, f"restricted encoding: rows {sorted(names - seen)} not in the table of {other}")
        return None
    if hi_bit >= fwidth or lo_bit > hi_bit:
        PROBLEMS.add(where, f"restricted encoding: {fname}<{hi_bit}:{lo_bit}> outside the field")
        return None
    sub = f"((w >> {flo + lo_bit}) & {(1 << (hi_bit - lo_bit + 1)) - 1:#x})"
    if (int(lo_s), int(hi_s)) != (0, (1 << (hi_bit - lo_bit + 1)) - 1):
        PROBLEMS.add(where, f"restricted encoding: range {lo_s}..{hi_s} is not the slice's")
        return None
    try:
        whole, _, _ = prose_value(text, ex.encodedin, ctx.scope, where)
    except AslError as e:
        PROBLEMS.add(where, f"{e} :: {text}")
        return None
    alts = flat_alts(ctx.spec, rid)
    special = [a for a in alts if len(a) == 1 and a[0][0] == "lit" and a[0][1] in REG_SPECIAL]
    numbered = [a for a in alts if any(x[0] == "tok" for x in a)]
    val = f"(if {' || '.join(terms)} {{ ({sub} as i64) }} else {{ {whole} }})"
    return number_operand(ctx, numbered, val, stated_default(text), None, where, special)


def build_operand_inner(ctx, rid, r, ex, text, where):
    alts = flat_alts(ctx.spec, rid)
    special = [a for a in alts if len(a) == 1 and a[0][0] == "lit" and a[0][1] in REG_SPECIAL]
    numbered = [a for a in alts if any(x[0] == "tok" for x in a)]
    if (m := re.search(r"with implicit value (\d+)", text)):
        if not numbered:
            lits = ["".join(x[1] for x in a if x[0] == "lit") for a in alts]
            return Operand(("const", lits[0].lower()), ctx.tables.value(m.group(1)))
        return number_operand(ctx, numbered, m.group(1), None, None, where)
    if ex.kind != "account" or not (ex.encodedin or re.search(r'encoded (?:in|as) ', text)):
        lits = ["".join(x[1] for x in a if x[0] == "lit") for a in alts]
        if len(alts) == 1 and lits[0]:
            # Fixed text such as the width specifier "H" of FMAXNMV.
            return Operand(("const", lits[0].lower()), ctx.tables.value("0"))
        PROBLEMS.add(where, f"no encoding for {alts[:3]} :: {text}")
        return None
    if (m := re.search(r'it must be (#\d+), encoded in "(\w+)" as 0 if omitted, or as 1 if present', text)):
        raw, _ = fields_of(m.group(2), ctx.scope, where)
        return Operand(("flag", m.group(1)), ctx.tables.value(f"({raw} as i64)"), 0)
    if (m := re.fullmatch(r"<([WX])\((\w)\+1\)>", ex.symbol or "")):
        # <W(s+1)>: the register after the one in field R<s> (CASP pairs).
        raw, _ = fields_of("R" + m.group(2), ctx.scope, where)
        return number_operand(ctx, numbered, f"(({raw} as i64) + 1)", None, None, where, special)
    if "'aaaaaaaabbbbbbbb" in text:
        # MOVI 64-bit: every bit of imm8 becomes a byte of ones or zeros.
        raw, _ = fields_of(field_source(text, ex), ctx.scope, where)
        return Operand(("hex", False), ctx.tables.value(f"h::byte_mask({raw} as u32)"))
    if re.search(r"shift amount", text) and (local := decode_local(ctx, "shift")) is not None:
        return Operand(("num",), ctx.tables.value(local))
    if (op := tsz_operand(ctx, text, ex, where)) is not None:
        return op
    if (op := list_member_operand(ctx, numbered, special, text, ex, where)) is not None:
        return op
    try:
        if re.search(r"System register name", text):
            return sysreg_operand(ctx, text, ex, where)
        if re.search(r"\bbitmask\b", text):
            return bitmask_operand(ctx, text, ex, where)
        if re.search(r"floating-point (?:constant|immediate)", text):
            raw, width = fields_of(field_source(text, ex), ctx.scope, where)
            return Operand(("fpimm",), ctx.tables.value(f"({raw} as i64)"))
        val, signed, scale = prose_value(text, ex.encodedin, ctx.scope, where)
    except AslError as e:
        PROBLEMS.add(where, f"{e} :: {text}")
        return None
    default = stated_default(text)
    if re.search(r"program label", text):
        kind = ("page",) if re.search(r"page address", text) else ("label",)
        return Operand(kind, ctx.tables.value(val))
    return number_operand(ctx, numbered, val, default, text, where, special)


def tsz_operand(ctx, text, ex, where):
    """SVE shifts and indexes whose meaning depends on the element size, which
    the highest (shifts) or lowest (indexes) set bit of a 'tsz' field gives."""
    src = field_source(text, ex)
    if not src or "tsz" not in src:
        return None
    parts = [p for p in re.split(r"::|:", src.strip("() ")) if p.strip()]
    parts = [p.strip() for p in parts]
    try:
        raw, width = fields_of(src, ctx.scope, where)
    except AslError:
        return None
    tsz_bits = sum(ctx.scope[p][1] for p in parts if p.startswith("tsz"))
    last = max(i for i, p in enumerate(parts) if p.startswith("tsz"))
    low = sum(ctx.scope[p][1] for p in parts[last + 1 :])
    if re.search(r"shift amount, in the range 1 to number of bits per element", text):
        return Operand(("num",), ctx.tables.value(f"h::tsz_shift({raw} as u32, {low}, true)"))
    if re.search(r"shift amount, in the range 0 to number of bits per element minus 1", text):
        return Operand(("num",), ctx.tables.value(f"h::tsz_shift({raw} as u32, {low}, false)"))
    if re.search(r"index", text) and low == 0:
        return Operand(("num",), ctx.tables.value(f"h::tsz_index({raw} as u32, {tsz_bits})"))
    return None


def list_member_operand(ctx, numbered, special, text, ex, where):
    """<Zn2> of a register list '{ <Zn1>, <Zn2> }' that the XML describes as
    'encoded in the "Zn" field' like <Zn1>: the k-th register is (Zn + k - 1) mod 32."""
    m = re.fullmatch(r"<([A-Za-z]+)([2-4])>", ex.symbol or "")
    if not m or re.search(r"times|plus|minus", text):
        return None
    f = re.search(r'encoded in the "(\w+)" field', text)
    if not f:
        return None
    first = ctx.spec.expl.get((ctx.encname, None))
    siblings = [x for (e, _), x in ctx.spec.expl_by_enc(ctx.encname) if x.symbol == f"<{m.group(1)}1>"]
    if not siblings or f'"{f.group(1)}"' not in siblings[0].text:
        return None
    k = int(m.group(2))
    raw, _ = fields_of(f.group(1), ctx.scope, where)
    count = 16 if m.group(1).upper().startswith("P") else 32  # 16 predicate registers
    return number_operand(ctx, numbered, f"((({raw} as i64) + {k - 1}) % {count})", None, None, where, special)


# Immediates printed in hexadecimal: the 16-bit operands of the exception
# generating instructions (svc, hvc, smc, brk, hlt, dcps), as llvm-mc and GNU
# objdump print them.
HEX_IMMEDIATE = re.compile(r"(SVC|HVC|SMC|BRK|HLT|DCPS\d|TCANCEL)_.*")


def number_operand(ctx, numbered, val, default, text, where, special=()):
    """A register name or an immediate, from its grammar shape."""
    valid = None
    if text is not None:
        val, valid = fit_range(text, val, where)
    vid = ctx.tables.value(val)
    if len(numbered) != 1:
        PROBLEMS.add(where, f"cannot classify operand shape {numbered[:3]} :: {text}")
        return None
    atoms = numbered[0]
    k = [i for i, a in enumerate(atoms) if a[0] == "tok"][0]
    if any(a[0] == "tok" for a in atoms[k + 1 :]):
        PROBLEMS.add(where, f"two numbers in one operand {atoms}")
        return None
    prefix = "".join(a[1] for a in atoms[:k] if a[0] == "lit")
    suffix = "".join(a[1] for a in atoms[k + 1 :] if a[0] == "lit")
    tok = atoms[k][1]
    if tok == "Real":
        PROBLEMS.add(where, "real number from prose")
        return None
    r31 = special[0][0][1] if special else None
    if prefix in ("", "#") and not suffix and r31 is None:
        if HEX_IMMEDIATE.fullmatch(ctx.encname):
            return Operand(("hex", prefix == "#"), vid, int_default(default, where), valid)
        return Operand(("imm", False) if prefix == "#" else ("num",), vid, int_default(default, where), valid)
    if r31 is None and prefix.lower() in ("x", "w") and not suffix:
        # Register 31 of a general-purpose operand that cannot be SP is the zero register.
        r31 = prefix.lower() + "zr"
    if len(special) > 1:
        PROBLEMS.add(where, f"several special register names {special}")
    reg_default = None
    if default is not None:
        d = default.strip("'")
        if d.upper() in REG_SPECIAL or d == "11111":
            reg_default = 31
        elif re.fullmatch(r"[A-Za-z]+\d+", d):
            reg_default = int(re.sub(r"^[A-Za-z]+", "", d))
        elif re.fullmatch(r"[01]+", d):
            reg_default = int(d, 2)
        else:
            PROBLEMS.add(where, f"register default {default!r}")
    return Operand(("reg", prefix.lower(), suffix.lower(), r31.lower() if r31 else None), vid, reg_default, valid)


def datasize(ctx):
    return 32 if ctx.fixed_field("sf") == 0 else 64


def field(ctx, name):
    lo, width = ctx.scope[name]
    return f"(((w >> {lo}) & {(1 << width) - 1:#x}) as i64)"


def num_of(code):
    """An operand whose '#' is part of the template."""
    return lambda ctx, text, ex, where: Operand(("num",), ctx.tables.value(code(ctx)))


# Operands whose prose gives a range but not the encoding: the bitfield aliases
# (the pseudocode of their parent instruction defines them).
OVERRIDES = [
    (r"(SBFIZ|UBFIZ|BFI|BFC)_.*", "<lsb>",
     num_of(lambda c: f"(({datasize(c)} - {field(c, 'immr')}) % {datasize(c)})")),
    (r"(SBFIZ|UBFIZ|BFI|BFC)_.*", "<width>", num_of(lambda c: f"({field(c, 'imms')} + 1)")),
    (r"(SBFX|UBFX|BFXIL)_.*", "<lsb>", num_of(lambda c: field(c, "immr"))),
    (r"(SBFX|UBFX|BFXIL)_.*", "<width>",
     num_of(lambda c: f"({field(c, 'imms')} + 1 - {field(c, 'immr')})")),
    (r"LSL_UBFM_.*", "<shift>", num_of(lambda c: f"({datasize(c) - 1} - {field(c, 'imms')})")),
    # MOV (wide immediate): the value MOVZ / MOVN builds, printed signed at the
    # register width.
    (r"MOV_MOVZ_(32|64)_movewide", "<imm>",
     num_of(lambda c: f"(({field(c, 'imm16')} << ({field(c, 'hw')} * 16)) as {'i32' if datasize(c) == 32 else 'i64'} as i64)")),
    (r"MOV_MOVN_(32|64)_movewide", "<imm>",
     num_of(lambda c: f"(!({field(c, 'imm16')} << ({field(c, 'hw')} * 16)) as {'i32' if datasize(c) == 32 else 'i64'} as i64)")),
    # ISB: "SY" (CRm = 0b1111) is the only named option; it is the default.
    (r"ISB_BI_barriers", "<option>",
     lambda c, t, e, w: Operand(("table", c.tables.vtables.add(((0xF, 0xF, ("text", "sy")),))),
                                c.tables.value(field(c, "CRm")), "sy")),
    # SME ZERO: the list of 64-bit tiles in imm8, printed as the largest tiles that cover it.
    (r"zero_za_i_", "<mask>", lambda c, t, e, w: Operand(("za_mask",), c.tables.value(field(c, "imm8")))),
]


def int_default(default, where):
    if default is None:
        return None
    try:
        d = default.strip("'")
        return int(d, 2) if re.fullmatch(r"[01]{2,}", d) else int(d, 0)
    except ValueError:
        PROBLEMS.add(where, f"non-numeric default {default!r}")
        return None


def field_source(text, ex):
    m = re.search(r'encoded in (?:the )?"([^"]+)"', text)
    return m.group(1) if m else ex.encodedin


def eval_range(val, where):
    """(min, max) of a value expression over every setting of the bits it reads."""
    bits = []
    for m in re.finditer(r"\(w >> (\d+)\) & (0x[0-9a-f]+)", val):
        lo_bit, mask = int(m.group(1)), int(m.group(2), 16)
        bits.extend(range(lo_bit, lo_bit + mask.bit_length()))
    bits = sorted(set(bits))
    if len(bits) > 16:
        return None
    pycode = val.replace(" as i64", "")
    sext = lambda v, n: v - (1 << n) if v >> (n - 1) & 1 else v  # noqa: E731
    vals = []
    for i in range(1 << len(bits)):
        w = 0
        for j, b in enumerate(bits):
            if i >> j & 1:
                w |= 1 << b
        vals.append(eval(pycode, {"w": w, "sext": sext}))
    return min(vals), max(vals)


def fit_range(text, val, where):
    """Cross-checks a value against the range the prose states.

    Returns (value code, valid range or None). The prose is authoritative:
    when the field covers more than the stated range, values outside it are
    reserved encodings; when the field's range is the stated one shifted by a
    constant ("in the range 1 to 16, encoded in imm4"), the constant is added.
    """
    rng = stated_range(text)
    if rng is None:
        return val, None
    lo, hi = rng
    got = eval_range(val, where)
    if got is None:
        return val, (lo, hi)
    mn, mx = got
    if (mn, mx) == (lo, hi):
        return val, None
    if mn <= lo and hi <= mx:
        return val, (lo, hi)
    if mx - mn == hi - lo:
        return f"({val} + {lo - mn})", None
    PROBLEMS.add(where, f"range {mn}..{mx} but text says {lo}..{hi} :: {text}")
    return val, None


def table_operand(ctx, rid, r, ex):
    where = f"{ctx.where} {ex.symbol}"
    header = ex.table[0] if ex.table else []
    cols = [i for i, (cls, _) in enumerate(header) if cls == "bitfield"]
    sym_col = next((i for i, (cls, _) in enumerate(header) if cls == "symbol"), None)
    if not cols or sym_col is None:
        PROBLEMS.add(where, f"table without bitfield/symbol columns: {header}")
        return None
    names = [header[i][1] for i in cols]
    try:
        raw, width = fields_of(":".join(names), ctx.scope, where)
    except AslError as e:
        PROBLEMS.add(where, f"table fields {names}: {e}")
        return None
    alts = flat_alts(ctx.spec, rid)
    lits = ["".join(a[1] for a in alt if a[0] == "lit") for alt in alts]
    present = next((x for x in lits if x), None)
    # Separator every printed alternative starts with (OPT_SPACE, COMMA): the
    # XML table gives the bare symbol.
    leads = set()
    for x in lits:
        if x:
            m = re.match(r"[ ,]*", x)
            leads.add(re.sub(r" +", " ", m.group(0)))
    lead = leads.pop() if len(leads) == 1 else ""
    entries = []
    for row in ex.table[1:]:
        mask = value = 0
        bad = False
        for i in cols:
            if i >= len(row):
                bad = True
                break
            try:
                m, v, n = pattern(row[i][1].replace(" ", ""))
            except ValueError:
                bad = True
                break
            mask = (mask << n) | m
            value = (value << n) | v
        if bad or sym_col >= len(row):
            PROBLEMS.add(where, f"bad table row {row}")
            continue
        cell = row[sym_col][1]
        e = table_entry(ctx, cell, present, where, ctx.tables.value(f"({raw} as i64)"), ex.after)
        if lead and e[0] == "text" and e[1]:
            e = ("text", lead + e[1])
        entries.append((mask, value, e))
    if ex.symbol == "<prfop>" and names == ["Rt"] and not any(v == 0b11000 for _, v, _ in entries):
        # PRFM IR (FEAT_PCDPHINT) is in the JSON grammar (rule Rt_IR) but not in
        # the XML's value table.
        entries.append((0x1F, 0b11000, ("text", "ir")))
    default = None
    d = re.search(r"default(?:ing|s)? (?:to|is) ([^,.]+?)(?: and|,|\.|$)", ex.text)
    if d:
        default = d.group(1).strip().lower()
    elif any(e[0] == "text" and e[1].startswith("lsl|") for _, _, e in entries):
        # "LSL is preferred, but may be omitted when imm3 is '000'".
        default = "lsl"
    elif any(e == ("text", "") for _, _, e in entries):
        # '[absent]' rows: the optional part is left out for them.
        default = ""
    else:
        zero = [e[1] for _, _, e in entries if e[0] == "text" and e[1].strip(" ,#") in ("0", "lsl #0")]
        if zero:
            default = zero[0]
    vt = ctx.tables.vtables.add(tuple(entries))
    return Operand(("table", vt), ctx.tables.value(f"({raw} as i64)"), default)


def table_entry(ctx, cell, present, where, raw_id=None, after=""):
    """('text', s) | ('reserved',) | ('value', value id)."""
    c = cell.strip()
    if c == "RESERVED" or c == "":
        return ("reserved",)
    if c == "[absent]":
        return ("text", "")
    if (m := re.fullmatch(r"#(\w+)", c)) and not m.group(1).isdigit():
        # '#uimm4': the encoded value itself, as an immediate.
        if m.group(1) in ctx.scope:
            lo, width = ctx.scope[m.group(1)]
            return ("hash", ctx.tables.value(f"(((w >> {lo}) & {(1 << width) - 1:#x}) as i64)"))
        return ("hash", raw_id)
    if c == "[present]":
        if present is None:
            PROBLEMS.add(where, "[present] without text")
        return ("text", (present or "").lower())
    if c in ("LSL|UXTW", "LSL|UXTX"):
        # "If Rd or Rn is '11111' (SP) and option is UXTW/UXTX, LSL is preferred"
        # (only Rn for the flag-setting forms, where Rd 31 is the zero
        # register): the renderer picks by the registers.
        if 'If "Rd" or "Rn"' in after:
            return ("text", c.lower())
        if 'If "Rn"' in after:
            return ("text", c.lower() + "|n")
        PROBLEMS.add(where, f"no rule for {c}: {after}")
        return ("text", c.split("|")[-1].lower())
    if "|" in c:
        # Two spellings of one value (CS|HS, CC|LO): the second, as LLVM and
        # GNU print condition codes.
        c = c.split("|")[-1]
    if re.search(r"UInt\(|SInt\(|<\d|\[\d|::", c) or re.fullmatch(r"\d+ - .*|.* - \d+", c):
        try:
            code, _ = asl_value(c, ctx.scope, where)
        except AslError as e:
            PROBLEMS.add(where, f"table cell {c!r}: {e}")
            return ("reserved",)
        return ("value", ctx.tables.value(code))
    return ("text", c.lower())


def bitmask_operand(ctx, text, ex, where):
    sc = ctx.scope
    if "imm13" in sc:
        lo, _ = sc["imm13"]
        n, immr, imms = f"((w >> {lo + 12}) & 1)", f"((w >> {lo + 6}) & 0x3f)", f"((w >> {lo}) & 0x3f)"
        width = 0  # SVE: printed at the element size the immediate implies
    else:
        get = lambda f: f"((w >> {sc[f][0]}) & {(1 << sc[f][1]) - 1:#x})" if f in sc else "0"
        n, immr, imms = get("N"), get("immr"), get("imms")
        sf = ctx.fixed_field("sf")
        width = 32 if sf == 0 else 64
    val = f"((({n} << 12) | ({immr} << 6) | {imms}) as i64)"
    return Operand(("bitmask", width), ctx.tables.value(val))


def sysreg_operand(ctx, text, ex, where):
    sc = ctx.scope
    get = lambda f: f"((w >> {sc[f][0]}) & {(1 << sc[f][1]) - 1:#x})"
    if "o0" in sc:
        op0 = f"(2 + {get('o0')})"
    elif "op0" in sc:
        op0 = get("op0")
    else:
        raise AslError("system register without op0")
    val = f"((({op0} << 14) | ({get('op1')} << 11) | ({get('CRn')} << 7) | ({get('CRm')} << 3) | {get('op2')}) as i64)"
    write = ctx.encname.startswith(("MSR", "MSRR"))
    return Operand(("sysreg", "w" if write else "r"), ctx.tables.value(val))


# ---------------------------------------------------------------------------
# System registers and system instructions (Registers.json)


def takes_input(reg):
    """Whether a system instruction always reads its register operand:
    Registers.json gives it a named field outside any feature condition
    (TLBI VAE1: ASID, VA). Fields present only with an optional feature
    (TLBI VMALLE1IS: TLBID when FEAT_TLBID), all reserved (GIC CDEOI) or no
    fields (TLBI VMALLE1) do not count: such an operation is written without
    its register, which then defaults to XZR."""

    def named(v):
        t = v.get("_type", "")
        if t == "Fields.ConditionalField":
            return False
        if t in ("Fields.Field", "Fields.Array", "Fields.Vector"):
            return bool(v.get("name"))
        if t == "Fields.Dynamic":
            return any(named(x) for fs in v.get("instances") or [] for x in fs.get("values") or [])
        if t in ("Fields.Reserved", "Fields.ImplementationDefined", "Fields.ConstantField"):
            return t != "Fields.Reserved" and bool(v.get("name"))
        raise SystemExit(f"{reg['name']}: unknown field type {t}")

    return any(named(v) for fs in reg.get("fieldsets") or [] for v in fs.get("values") or [])


def accessor_encodings(acc):
    """Yields (asm name, {field: (mask, value)}) for every instance of an accessor."""
    for enc in acc.get("encoding") or []:
        name = enc["asmvalue"]
        fields = enc["encodings"]
        var = acc.get("index_variable")
        indexes = [None]
        if var:
            indexes = []
            for rng in acc.get("indexes") or []:
                indexes.extend(range(rng["start"], rng["start"] + rng["width"]))
        for idx in indexes:
            out = {}
            ok = True
            for f, v in fields.items():
                if v["_type"] == "Values.Value":
                    m, val, n = pattern(v["value"])
                    out[f] = (m, val, n)
                elif v["_type"] == "Values.Group" and idx is not None:
                    bits = width = 0
                    for part in re.split(r":(?![^\[]*\])", v["value"]):
                        part = part.strip()
                        if part.startswith("'"):
                            m_, v_, n_ = pattern(part)
                            bits, width = (bits << n_) | v_, width + n_
                        elif (sl := re.fullmatch(r"\w+\[(\d+)(?::(\d+))?\]", part)):
                            hi = int(sl.group(1))
                            lo = int(sl.group(2)) if sl.group(2) else hi
                            n_ = hi - lo + 1
                            bits = (bits << n_) | ((idx >> lo) & ((1 << n_) - 1))
                            width += n_
                        else:
                            ok = False
                    out[f] = ((1 << width) - 1, bits, width)
                elif v["_type"] == "Values.EquationValue" and idx is not None:
                    bits = 0
                    width = 0
                    for sl in v["slice"]:
                        part = (idx >> sl["start"]) & ((1 << sl["width"]) - 1)
                        bits = (bits << sl["width"]) | part
                        width += sl["width"]
                    out[f] = ((1 << width) - 1, bits, width)
                else:
                    ok = False
            if not ok:
                continue
            nm = name
            if var and idx is not None:
                nm = re.sub(r"<\w+>", str(idx), name)
            yield nm, out


def system_tables(spec):
    """(MRS names, MSR names) as sorted lists."""
    reads, writes = {}, {}
    for reg in spec.registers:
        for acc in reg.get("accessors") or []:
            if not acc["_type"].startswith("Accessors.SystemAccessor"):
                continue
            kind = acc.get("name")
            for name, f in accessor_encodings(acc):
                if kind in ("A64.MRS", "A64.MSRregister"):
                    try:
                        if any(f[k][0] != (1 << f[k][2]) - 1 for k in ("op0", "op1", "CRn", "CRm", "op2")):
                            continue
                        enc = (f["op0"][1] << 14) | (f["op1"][1] << 11) | (f["CRn"][1] << 7) | (f["CRm"][1] << 3) | f["op2"][1]
                    except KeyError:
                        continue
                    (reads if kind == "A64.MRS" else writes).setdefault(enc, name.lower())
    return sorted(reads.items()), sorted(writes.items())


# ---------------------------------------------------------------------------
# Rust output


def rs_str(s):
    return json.dumps(s, ensure_ascii=False)


def emit(comp, out_path):
    spec = comp.spec
    t = comp.tables
    lines = []
    w = lines.append
    meta = spec.meta
    lic = meta["license"]
    w("// @generated by tools/arm64/gen.py. Do not edit; regenerate instead.")
    w("//")
    w(f"// Source: Arm A-profile Machine Readable Specification {meta['version']['ref']}")
    w(f"// (architecture {meta['version']['architecture']}, schema {meta['version']['schema']}) and the")
    w("// A64 ISA XML release of the same version.")
    w("//")
    w(f"// {lic['copyright']}")
    w(f"// {lic['info']}")
    w("//")
    for line in BSD_TEXT.strip().splitlines():
        w(("// " + line).rstrip())
    w("")
    w("#![allow(clippy::all, clippy::pedantic, unused, unreachable_code, unused_parens, nonstandard_style)]")
    w("")
    w("use crate::helpers::{self as h, sext};")
    w("use crate::model::{Alias, Dflt, Enc, Item, Kind, Node, Op, Entry};")
    w("")

    # Items of every template, flattened.
    items = []

    def flatten(seq):
        start = len(items)
        last_text = None  # index of the previous item if it is text at this level
        for it in seq:
            if it[0] == "text":
                txt = it[1].lower()
                if last_text is not None:
                    items[last_text] = ("Text", items[last_text][1] + txt)
                else:
                    last_text = len(items)
                    items.append(("Text", txt))
                continue
            last_text = None
            if it[0] == "space":
                items.append(("Space",))
            elif it[0] == "op":
                items.append(("Op", t.op(it[1])))
                OPS[t.op(it[1])] = it[1]
            elif it[0] == "opt":
                pos = len(items)
                items.append(None)
                flatten(it[1])
                items[pos] = ("Opt", len(items) - pos - 1)
            elif it[0] == "alt":
                items.append(("Alt", len(it[1])))
                for alt in it[1]:
                    pos = len(items)
                    items.append(None)
                    flatten(alt)
                    items[pos] = ("Branch", len(items) - pos - 1)
        return start, len(items) - start

    OPS = {}
    enc_rows = []
    alias_rows = []
    for node in comp.encodings:
        if node.name in comp.skipped:
            enc_rows.append(None)
            continue
        st, ln = flatten(comp.templates[node.name])
        a0 = len(alias_rows)
        for name, cond, pref, tmpl in comp.alias[node.name]:
            ast, aln = flatten(tmpl)
            alias_rows.append((name, cond, pref, ast, aln))
        enc_rows.append((node.name, st, ln, a0, len(alias_rows) - a0, node.mask, node.value, node.sb_mask, node.sb_value))

    # Decode tree, breadth first so that children are contiguous.
    order = [comp.root]
    index = {id(comp.root): 0}
    i = 0
    while i < len(order):
        n = order[i]
        for c in n.children:
            index[id(c)] = len(order)
            order.append(c)
        i += 1
    w(f"pub(crate) static NODES: [Node; {len(order)}] = [")
    for n in order:
        first = index[id(n.children[0])] if n.children else 0
        enc = n.enc_id if n.enc_id is not None and enc_rows[n.enc_id] is not None else 0xFFFF
        if n.enc_id is not None and enc == 0xFFFF:
            # Skipped encoding: a node that never matches.
            w(f"    Node {{ mask: 0, value: 1, cond: 0, first: 0, count: 0, enc: 0xFFFF }}, // {n.name} (skipped)")
            continue
        w(
            f"    Node {{ mask: {n.mask:#010x}, value: {n.value:#010x}, cond: {comp.node_conds[id(n)]}, "
            f"first: {first}, count: {len(n.children)}, enc: {enc:#x} }}, // {n.name}"
        )
    w("];")
    w("")
    w(f"pub(crate) static ENCODINGS: [Enc; {len(enc_rows)}] = [")
    for row in enc_rows:
        if row is None:
            w('    Enc { name: "", mask: 0, value: 1, sb_mask: 0, sb_value: 0, items: 0, len: 0, alias: 0, aliases: 0, undef: 0, unpred: 0 },')
            continue
        name, st, ln, a0, an, mask, value, sbm, sbv = row
        w(
            f"    Enc {{ name: {rs_str(name)}, mask: {mask:#010x}, value: {value:#010x}, sb_mask: {sbm:#010x}, "
            f"sb_value: {sbv:#010x}, items: {st}, len: {ln}, alias: {a0}, aliases: {an}, "
            f"undef: {comp.undef[name]}, unpred: {comp.unpred[name]} }},"
        )
    w("];")
    w("")
    skipped = [n for n in comp.encodings if n.name in set(comp.skipped)]
    w("/// Encodings left out: newer than the XML release, which does not describe")
    w("/// their operands yet. (name, fixed-bit mask, value)")
    w(f"pub(crate) static NOT_DECODED: [(&str, u32, u32); {len(skipped)}] = [")
    for n in skipped:
        w(f"    ({rs_str(n.name)}, {n.mask:#010x}, {n.value:#010x}),")
    w("];")
    w("")
    w(f"pub(crate) static ALIASES: [Alias; {len(alias_rows)}] = [")
    for name, cond, pref, st, ln in alias_rows:
        w(f"    Alias {{ cond: {cond}, preferred: {pref}, items: {st}, len: {ln} }}, // {name.lower()}")
    w("];")
    w("")
    w(f"pub(crate) static ITEMS: [Item; {len(items)}] = [")
    for it in items:
        if it[0] == "Text":
            w(f"    Item::Text({rs_str(it[1])}),")
        elif it[0] == "Space":
            w("    Item::Space,")
        else:
            w(f"    Item::{it[0]}({it[1]}),")
    w("];")
    w("")
    ops = sorted(OPS.items())
    if [k for k, _ in ops] != list(range(len(ops))):
        raise SystemExit("operand numbering has gaps")
    w(f"pub(crate) static OPS: [Op; {len(ops)}] = [")
    for _, op in ops:
        w(f"    {rs_op(op)},")
    w("];")
    w("")
    vts = list(t.vtables.ids.keys())
    w(f"pub(crate) static VTABLES: [&[Entry]; {len(vts)}] = [")
    for entries in vts:
        parts = []
        for mask, value, e in entries:
            if e[0] == "text":
                ent = f"Some({rs_str(e[1])})"
                parts.append(f"Entry {{ mask: {mask:#x}, value: {value:#x}, text: {ent}, value_of: 0xFFFF }}")
            elif e[0] == "reserved":
                parts.append(f"Entry {{ mask: {mask:#x}, value: {value:#x}, text: None, value_of: 0xFFFF }}")
            elif e[0] == "hash":
                parts.append(f'Entry {{ mask: {mask:#x}, value: {value:#x}, text: Some("#"), value_of: {e[1]} }}')
            else:
                parts.append(f"Entry {{ mask: {mask:#x}, value: {value:#x}, text: None, value_of: {e[1]} }}")
        w("    &[" + ", ".join(parts) + "],")
    w("];")
    w("")
    w("/// Conditions of the decode tree, aliases and alias preferences.")
    w("pub(crate) fn cond(id: u16, w: u32) -> bool {")
    w("    match id {")
    w("        0 => true,")
    for code, i in t.conds.exprs.items():
        w(f"        {i} => {code},")
    w("        _ => unreachable!(),")
    w("    }")
    w("}")
    w("")
    w("/// Operand values.")
    w("pub(crate) fn value(id: u16, w: u32) -> i64 {")
    w("    match id {")
    for code, i in t.values.ids.items():
        w(f"        {i} => {code},")
    w("        _ => unreachable!(),")
    w("    }")
    w("}")
    w("")
    w("/// Checks from the decode pseudocode: true if the word is UNDEFINED")
    w("/// (or reaches a CONSTRAINED UNPREDICTABLE choice, for the `unpred` checks).")
    w("pub(crate) fn undefined(id: u16, w: u32) -> bool {")
    w("    match id {")
    w("        0 => false,")
    for body, i in comp.undef_bodies.ids.items():
        w(f"        {i + 1} => undef_{i + 1}(w),")
    w("        _ => unreachable!(),")
    w("    }")
    w("}")
    w("")
    for body, i in comp.undef_bodies.ids.items():
        w(f"fn undef_{i + 1}(w: u32) -> bool {{")
        w(body)
        w("    false")
        w("}")
        w("")
    reads, writes = system_tables(spec)
    for name, rows in (("SYSREG_READ", reads), ("SYSREG_WRITE", writes)):
        w(f"/// System register names by op0:op1:CRn:CRm:op2 ({'MRS' if 'READ' in name else 'MSR'}).")
        w(f"pub(crate) static {name}: [(u16, &str); {len(rows)}] = [")
        for enc, nm in rows:
            w(f"    ({enc:#06x}, {rs_str(nm)}),")
        w("];")
        w("")
    kinds = sorted({k for rows in spec.sys_cases.values() for _, _, k in rows})
    w("/// Kinds of system instruction (the `SystemOp` values of the pseudocode).")
    w("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
    w("pub(crate) enum SysKind {")
    for k in kinds:
        w(f"    {k},")
    w("    Sys,")
    w("}")
    w("")
    for fn, name in (("SysOp", "SYS_OP"), ("SysOp128", "SYS_OP128"), ("SysLOp", "SYSL_OP")):
        rows = spec.sys_cases[fn]
        w(f"/// `{fn}()`: op1:CRn:CRm:op2 (mask, value) to kind.")
        w(f"pub(crate) static {name}: [(u16, u16, SysKind); {len(rows)}] = [")
        for mask, val, kind in rows:
            w(f"    ({mask:#06x}, {val:#06x}, SysKind::{kind}),")
        w("];")
        w("")
    src = "\n".join(lines) + "\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(src)
    print(
        f"{out_path}: {sum(1 for r in enc_rows if r)} encodings, {len(alias_rows)} aliases, "
        f"{len(ops)} operands, {len(t.values.ids)} values, {len(t.conds.exprs)} conditions, "
        f"{len(comp.from_json)} from the JSON alone, {len(comp.skipped)} skipped (not in the XML)",
        file=sys.stderr,
    )


def rs_op(op):
    k = op.kind
    if k[0] == "reg":
        r31 = f"Some({rs_str(k[3])})" if k[3] else "None"
        kind = f"Kind::Reg {{ prefix: {rs_str(k[1])}, suffix: {rs_str(k[2])}, r31: {r31} }}"
    elif k[0] == "imm":
        kind = "Kind::Imm"
    elif k[0] == "num":
        kind = "Kind::Num"
    elif k[0] == "hex":
        kind = f"Kind::Hex({'true' if k[1] else 'false'})"
    elif k[0] == "label":
        kind = "Kind::Label"
    elif k[0] == "page":
        kind = "Kind::Page"
    elif k[0] == "table":
        kind = f"Kind::Table({k[1]})"
    elif k[0] == "bitmask":
        kind = f"Kind::Bitmask({k[1]})"
    elif k[0] == "fpimm":
        kind = "Kind::FpImm"
    elif k[0] == "sysreg":
        kind = f"Kind::SysReg({'true' if k[1] == 'w' else 'false'})"
    elif k[0] == "flag":
        kind = f"Kind::Flag({rs_str(k[1].lower())})"
    elif k[0] == "const":
        kind = f"Kind::Const({rs_str(k[1])})"
    elif k[0] == "za_mask":
        kind = "Kind::ZaMask"
    else:
        raise SystemExit(f"unknown operand kind {k}")
    d = op.default
    if d is None:
        dflt = "Dflt::None"
    elif isinstance(d, tuple):
        dflt = f"Dflt::IntUnless({d[1]}, {d[2]})"
    elif isinstance(d, str):
        dflt = f"Dflt::Text({rs_str(d)})"
    else:
        dflt = f"Dflt::Int({d})"
    valid = f"Some(({op.valid[0]}, {op.valid[1]}))" if op.valid else "None"
    return f"Op {{ kind: {kind}, val: {op.val}, default: {dflt}, valid: {valid}, when: {op.when} }}"


BSD_TEXT = """
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list
   of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this
   list of conditions and the following disclaimer in the documentation and/or other
   materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be
   used to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
"""


def py_cond(code):
    """A generated Rust condition as a Python expression (for analysis only)."""
    c = code.replace("&&", " and ").replace("||", " or ")
    c = re.sub(r"!(?!=)", " not ", c)
    c = re.sub(r" as (?:i64|u32|u64)", "", c)
    c = re.sub(r"h::(\w+)\(", r"H_\1(", c)
    c = c.replace("SysKind::", "SYS_")
    c = re.sub(r"\btrue\b", "True", c)
    c = re.sub(r"\bfalse\b", "False", c)
    c = re.sub(r"(\d)i64\b", r"\1", c)
    return c


def H_bfx_preferred(sf, uns, imms, immr):
    if imms < immr:
        return False
    if imms == (sf << 5) | 0x1F:
        return False
    if immr == 0:
        if sf == 0 and imms in (0b000111, 0b001111):
            return False
        if sf == 1 and uns == 0 and imms in (0b000111, 0b001111, 0b011111):
            return False
    return True


def H_decode_bit_masks(n, imms, immr, m):
    combined = (n << 6) | (~imms & 0x3F)
    if combined & 0x7E == 0:
        return None
    length = combined.bit_length() - 1
    esize = 1 << length
    if esize > m:
        return None
    levels = esize - 1
    if imms & levels == levels:
        return None
    sv, r = imms & levels, immr & levels
    welem = (1 << (sv + 1)) - 1
    emask = (1 << esize) - 1
    rot = ((welem >> r) | (welem << (esize - r))) & emask if r else welem
    out = 0
    for i in range(0, m, esize):
        out |= rot << i
    return out


def H_move_wide_preferred(sf, n, imms, immr):
    """Same test as helpers::move_wide_preferred (representability)."""
    width = 64 if sf == 1 else 32
    if sf == 1 and n != 1:
        return False
    if sf == 0 and (n != 0 or imms & 0x20):
        return False
    v = H_decode_bit_masks(n, imms, immr, width)
    if v is None:
        return False
    mask = (1 << width) - 1
    one = lambda x: any(x & ~(0xFFFF << (16 * h)) & mask == 0 for h in range(width // 16))  # noqa: E731
    return one(v) or one(~v & mask)


def H_bit_count(v):
    return bin(v).count("1")


# System instruction encodings -> the pseudocode function naming their operation.
SYS_BASES = {
    "SYS_CR_systeminstrs": "SysOp",
    "SYSL_RC_systeminstrs": "SysLOp",
    "SYSP_CR_syspairinstrs": "SysOp128",
}
RT = "(((w >> 0) & 0x1f) as i64)"


def sys_alias_register(tables, spec, fn, pref, items):
    """The Rt register of a system instruction alias, so that no alias hides
    an encoded bit.

    * An alias without a register operand (GCSPUSHX, BRB IALL, GSB ACK) is
      preferred only when Rt is 31: Arm calls it the preferred disassembly
      unconditionally, but for any other Rt the register would vanish from
      the text, so SYS shows it.
    * The optional {, <Xt>} is left out at XZR only for an operation that
      reads no register (TLBI VMALLE1, IC IALLU); TLBI VAE1 or DC ZVA with
      XZR show it, since the operation does use its value (Registers.json).
    """
    rt = tables.values.add(RT)
    uses_rt = False

    def walk(seq, optional):
        nonlocal uses_rt
        out = []
        for it in seq:
            if it[0] == "op":
                op = it[1]
                if op.val == rt or RT in value_code(tables, op.val):
                    uses_rt = True
                if optional and op.val == rt and op.kind[0] == "reg" and op.default in (None, 31):
                    c = inputs_cond(tables, spec, fn)
                    op = Operand(op.kind, op.val, ("unless", 31, c) if c else 31, op.valid, op.when)
                out.append(("op", op))
            elif it[0] == "opt":
                out.append(("opt", walk(it[1], True)))
            elif it[0] == "alt":
                out.append(("alt", [walk(s, optional) for s in it[1]]))
            else:
                out.append(it)
        return out

    items = walk(items, False)
    if not uses_rt:
        rt31 = "(((w >> 0) & 0x1f) == 0x1f)"
        code = next((c for c, i in tables.conds.exprs.items() if i == pref), None) if pref else None
        pref = tables.conds.add_code(f"({code}) && {rt31}" if code else rt31)
    return pref, items


def value_code(tables, vid):
    return next(k for k, i in tables.values.ids.items() if i == vid)


def inputs_cond(tables, spec, fn):
    """Condition: the operation op1:CRn:CRm:op2 reads its register."""
    keys = sorted(k for (f, k), v in spec.sys_inputs.items() if f == fn and v)
    if not keys:
        return 0
    alts = " | ".join(f"{k:#06x}" for k in keys)
    return tables.conds.add_code(f"matches!((w >> 5) & 0x3fff, {alts})")


def order_aliases(aliases, conds, where):
    """Orders aliases most specific first.

    Arm's alias conditions can overlap (LSL is a special case of UBFIZ); the
    alias that applies to fewer encodings is the more specific one. Aliases
    whose conditions cannot be evaluated here keep their order.
    """
    if len(aliases) < 2:
        return aliases
    by_id = {i: c for c, i in conds.exprs.items()}
    codes = []
    bits = set()
    for name, cond, pref, items in aliases:
        parts = [by_id[i] for i in (cond, pref) if i]
        code = " and ".join(f"({py_cond(p)})" for p in parts) or "True"
        codes.append(code)
        for p in parts:
            for m in re.finditer(r"\(w >> (\d+)\) & (0x[0-9a-f]+)", p):
                lo, mask = int(m.group(1)), int(m.group(2), 16)
                bits.update(range(lo, lo + mask.bit_length()))
    bits = sorted(bits)
    if len(bits) > 16 or any("SYS_" in c or "H_sve" in c or "H_sys" in c for c in codes):
        return aliases
    counts = []
    env = {k: v for k, v in globals().items() if k.startswith("H_")}
    env["sext"] = lambda v, n: v - (1 << n) if v >> (n - 1) & 1 else v
    for code in codes:
        n = 0
        for i in range(1 << len(bits)):
            w = 0
            for j, b in enumerate(bits):
                if i >> j & 1:
                    w |= 1 << b
            env["w"] = w
            try:
                n += bool(eval(code, env))
            except Exception as e:  # noqa: BLE001 - diagnostics only
                PROBLEMS.add(where, f"alias order: cannot evaluate {code}: {e}")
                return aliases
        counts.append(n)
    order = sorted(range(len(aliases)), key=lambda i: (counts[i], i))
    return [aliases[i] for i in order]


# ---------------------------------------------------------------------------
# Driver


class Compiled:
    def __init__(self, spec):
        self.spec = spec
        self.tables = Tables()
        self.root, self.encodings = build_tree(spec)
        self.templates = {}  # encoding name -> items
        self.undef = {}  # encoding name -> UNDEFINED check id (0: none)
        self.unpred = {}  # encoding name -> UNPREDICTABLE check id (0: none)
        self.undef_bodies = Interned()
        self.alias = {}  # encoding name -> [(name, cond id, preferred id, items)]
        described = set(spec.label) | {enc for enc, _ in spec.expl}
        self.skipped = []
        self.from_json = []  # encodings compiled from the JSON alone
        for node in self.encodings:
            scope = node.scope()
            if node.name not in described:
                # Newer than the XML release: usable only if every operand is a
                # plain register (the JSON gives fields, not meanings).
                ctx = Ctx(spec, self.tables, node, node.name, scope, (node.raw.get("_meta") or {}).get("encoded_in"))
                ctx.fallback = True
                try:
                    self.templates[node.name] = compile_template(ctx, node.raw["assembly"])
                    covered = node.mask | node.sb_mask
                    for fl in ctx.meta.values():
                        for x in fl:
                            lo, wd = scope[x["value"]]
                            covered |= ((1 << wd) - 1) << lo
                    if covered != 0xFFFFFFFF:
                        # A free field no operand uses may have reserved values
                        # that only the (missing) decode pseudocode names.
                        raise SkipEncoding("free bits outside operands")
                except SkipEncoding:
                    self.skipped.append(node.name)
                    self.templates.pop(node.name, None)
                    continue
                self.from_json.append(node.name)
                self.undef[node.name] = self.unpred[node.name] = 0
                self.alias[node.name] = []
                continue
            code = spec.decode_ps.get(node.name)
            # UDF is UNDEFINED by definition; it is still an instruction to show.
            body = undef_function(code, scope, node.name) if code and not node.name.startswith("UDF_") else None
            self.undef[node.name] = self.undef_bodies.add(body) + 1 if body else 0
            ub = undef_function(code, scope, node.name, True) if code else None
            if node.name in spec.exec_checks:
                extra = exec_unpredictable(spec, node.name, code or "", scope)
                if extra:
                    ub = (ub or "") + f"\n    if {extra} {{\n        return true;\n    }}"
            self.unpred[node.name] = self.undef_bodies.add(ub) + 1 if ub else 0
            ctx = Ctx(spec, self.tables, node, node.name, scope)
            self.templates[node.name] = compile_template(ctx, node.raw["assembly"])
            al = []
            for a in node.aliases:
                aname = f"{a['name']}_{node.name}"
                if aname not in described:
                    # Newer than the XML (PLBI): from the JSON, when every
                    # operand is a register or a named system operation.
                    actx = Ctx(spec, self.tables, node, aname, scope, (a.get("_meta") or {}).get("encoded_in"))
                    actx.fallback = True
                    try:
                        items = compile_template(actx, a["assembly"])
                        if node.name not in SYS_BASES or any(it[0] == "alt" for it in items):
                            raise SkipEncoding("not a system instruction alias")
                    except SkipEncoding:
                        self.skipped.append(aname)
                        continue
                    self.from_json.append(aname)
                else:
                    actx = Ctx(spec, self.tables, node, aname, scope)
                    items = compile_template(actx, a["assembly"])
                cond = self.tables.conds.add(a.get("condition"), scope, aname)
                pref = self.tables.conds.add(a.get("preferred"), scope, aname)
                if node.name in SYS_BASES:
                    pref, items = sys_alias_register(self.tables, spec, SYS_BASES[node.name], pref, items)
                al.append((a["name"], cond, pref, items))
            self.alias[node.name] = order_aliases(al, self.tables.conds, node.name)
        self.node_conds = {}

        def conds(n):
            self.node_conds[id(n)] = self.tables.conds.add(n.cond, n.scope(), n.path())
            for c in n.children:
                conds(c)

        conds(self.root)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mrs", required=True, help="unpacked AARCHMRS JSON directory")
    ap.add_argument("--xml", required=True, help="unpacked ISA_A64_xml directory")
    ap.add_argument("--out", default="crates/fg-arch-arm64/src/tables.rs")
    ap.add_argument("--check", action="store_true", help="report problems only")
    args = ap.parse_args()
    spec = Spec(args.mrs, args.xml)
    comp = Compiled(spec)
    PROBLEMS.stop_if_any()
    if args.check:
        return
    emit(comp, args.out)


if __name__ == "__main__":
    main()
