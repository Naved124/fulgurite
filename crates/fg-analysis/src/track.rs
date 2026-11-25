// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Following register values along one path of instructions, symbolically,
//! far enough to read a jump table (design §8.3) without a lifter.
//!
//! Every register starts as its unknown value at the path's start
//! ([`Sym::Init`]); each instruction's [`Effect`] rewrites the registers it
//! writes as expressions over those. A compare followed by the branch the path
//! takes bounds an expression: `cmp eax, 7; ja default` on the not-taken path
//! means `eax <= 7`, whatever is later done with the register. An indirect
//! jump's target is then an expression too, and when its only unknown is a
//! bounded expression, the table is read by evaluating the target for every
//! value the bound allows. Nothing is assumed about how the compiler laid
//! the table out: gcc's `movsxd`/`add`, clang's, an absolute `jmp [8*rax+T]`
//! and AArch64's `ldrb`/`add ..., sxtb #2` are all the same evaluation.

use fg_core::Va;
use fg_ir::{Addr, BinOp, Cond, Effect, Flags, Reg, RegPart, Value};
use std::collections::BTreeMap;

/// Most entries read from one table. Switches over a byte (interpreters) have
/// 256; a bound past this is more likely a misread than a switch.
pub const MAX_ENTRIES: u64 = 1 << 12;

/// A value as an expression over the registers at the path's start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sym {
    /// A constant.
    Const(u64),
    /// A register's value where the path starts.
    Init(Reg),
    /// A value not followed (written by an instruction the effects do not
    /// describe). Equal only to itself.
    Unknown(u32),
    /// Memory at an address, extended to 64 bits.
    Load {
        /// The address.
        addr: Box<Sym>,
        /// Bytes read.
        bytes: u8,
        /// True if sign-extended.
        signed: bool,
    },
    /// Sum, wrapping.
    Add(Box<Sym>, Box<Sym>),
    /// Left shift.
    Shl(Box<Sym>, u8),
    /// The low bits, zero-extended.
    Low(Box<Sym>, u8),
    /// The low bits, sign-extended.
    Sext(Box<Sym>, u8),
}

fn mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

fn sign_extend(v: u64, bits: u8) -> u64 {
    if bits >= 64 {
        v
    } else {
        let s = 64 - u32::from(bits);
        (((v << s) as i64) >> s) as u64
    }
}

fn add(a: Sym, b: Sym) -> Sym {
    match (a, b) {
        (Sym::Const(x), Sym::Const(y)) => Sym::Const(x.wrapping_add(y)),
        (Sym::Const(x), b) => add(b, Sym::Const(x)),
        (a, Sym::Const(0)) => a,
        (Sym::Add(p, q), Sym::Const(y)) if matches!(*q, Sym::Const(_)) => {
            let Sym::Const(x) = *q else { unreachable!() };
            add(*p, Sym::Const(x.wrapping_add(y)))
        }
        (a, b) => Sym::Add(Box::new(a), Box::new(b)),
    }
}

fn shl(a: Sym, s: u8) -> Sym {
    match a {
        _ if s == 0 => a,
        _ if s >= 64 => Sym::Const(0),
        Sym::Const(x) => Sym::Const(x << s),
        Sym::Shl(p, t) if s + t < 64 => Sym::Shl(p, s + t),
        a => Sym::Shl(Box::new(a), s),
    }
}

fn low(a: Sym, bits: u8) -> Sym {
    match a {
        _ if bits >= 64 => a,
        Sym::Const(x) => Sym::Const(x & mask(bits)),
        Sym::Low(p, j) => Sym::Low(p, j.min(bits)),
        Sym::Load {
            bytes,
            signed: false,
            ..
        } if u32::from(bytes) * 8 <= u32::from(bits) => a,
        a => Sym::Low(Box::new(a), bits),
    }
}

fn sext(a: Sym, bits: u8) -> Sym {
    match a {
        _ if bits >= 64 => a,
        Sym::Const(x) => Sym::Const(sign_extend(x, bits)),
        Sym::Load { addr, bytes, .. } if u32::from(bytes) * 8 == u32::from(bits) => Sym::Load {
            addr,
            bytes,
            signed: true,
        },
        Sym::Low(p, j) if j == bits => Sym::Sext(p, bits),
        Sym::Sext(p, j) if j <= bits => Sym::Sext(p, j),
        a => Sym::Sext(Box::new(a), bits),
    }
}

impl Sym {
    /// True if `x` occurs in this expression.
    fn contains(&self, x: &Sym) -> bool {
        self == x
            || match self {
                Sym::Load { addr, .. } => addr.contains(x),
                Sym::Add(a, b) => a.contains(x) || b.contains(x),
                Sym::Shl(a, _) | Sym::Low(a, _) | Sym::Sext(a, _) => a.contains(x),
                _ => false,
            }
    }

    /// True if, with `x` taken as known, nothing unknown remains (with `x` a
    /// constant: if the expression is constant).
    fn known_but(&self, x: &Sym) -> bool {
        self == x
            || match self {
                Sym::Const(_) => true,
                Sym::Init(_) | Sym::Unknown(_) => false,
                Sym::Load { addr, .. } => addr.known_but(x),
                Sym::Add(a, b) => a.known_but(x) && b.known_but(x),
                Sym::Shl(a, _) | Sym::Low(a, _) | Sym::Sext(a, _) => a.known_but(x),
            }
    }

    /// The value with `x` set to `v`, reading memory through `read`.
    fn eval(&self, x: &Sym, v: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Option<u64> {
        if self == x {
            return Some(v);
        }
        Some(match self {
            Sym::Const(c) => *c,
            Sym::Init(_) | Sym::Unknown(_) => return None,
            Sym::Load {
                addr,
                bytes,
                signed,
            } => {
                let raw = read(addr.eval(x, v, read)?, *bytes)?;
                if *signed {
                    sign_extend(raw, bytes * 8)
                } else {
                    raw
                }
            }
            Sym::Add(a, b) => a.eval(x, v, read)?.wrapping_add(b.eval(x, v, read)?),
            Sym::Shl(a, s) => a.eval(x, v, read)? << s,
            Sym::Low(a, b) => a.eval(x, v, read)? & mask(*b),
            Sym::Sext(a, b) => sign_extend(a.eval(x, v, read)?, *b),
        })
    }

    /// The value modulo 2^`bits`: zero extensions at least that wide removed.
    fn modulo(&self, bits: u8) -> &Sym {
        match self {
            Sym::Low(a, j) if *j >= bits => a.modulo(bits),
            _ => self,
        }
    }

    /// The width a value is known to fit in (`Low(_, 32)` is 32 bits).
    fn width(&self) -> u8 {
        match self {
            Sym::Low(_, b) => *b,
            _ => 64,
        }
    }

    /// The first load whose address depends on `x`: the table's (address
    /// expression, entry size).
    fn table_load(&self, x: &Sym) -> Option<(&Sym, u8)> {
        match self {
            Sym::Load { addr, bytes, .. } if addr.contains(x) => {
                addr.table_load(x).or(Some((addr, *bytes)))
            }
            Sym::Load { addr, .. } => addr.table_load(x),
            Sym::Add(a, b) => a.table_load(x).or_else(|| b.table_load(x)),
            Sym::Shl(a, _) | Sym::Low(a, _) | Sym::Sext(a, _) => a.table_load(x),
            _ => None,
        }
    }
}

/// What is known of a register on every path into a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// It holds this constant.
    Const(u64),
    /// It fits in this many bits (a 32-bit write cleared the upper half).
    Below(u8),
}

impl Known {
    /// What holds on both of two paths, if anything.
    pub fn meet(self, other: Known) -> Option<Known> {
        let bits = |k: Known| match k {
            Known::Const(c) => 64 - c.leading_zeros() as u8,
            Known::Below(b) => b,
        };
        match (self, other) {
            (a, b) if a == b => Some(a),
            (a, b) => {
                let w = bits(a).max(bits(b));
                (w < 64).then_some(Known::Below(w))
            }
        }
    }
}

/// An expression known to be at most `max`, unsigned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The bounded expression.
    pub value: Sym,
    /// Its largest value.
    pub max: u64,
    /// The instruction that proves it: the branch after a compare, or an `and`.
    pub at: Va,
}

/// A jump table read through a bounded index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    /// Where control goes for each index, 0 to the bound.
    pub targets: Vec<u64>,
    /// The table's address (index 0) and entry size, when the target is read
    /// from memory.
    pub table: Option<(u64, u8)>,
    /// The bound used.
    pub bound: Bound,
}

/// Register values along a path.
#[derive(Debug)]
pub struct Tracker {
    regs: BTreeMap<Reg, Sym>,
    /// The operands of the last compare.
    flags: Option<(Sym, Sym)>,
    /// True once an instruction may have written any register.
    clobbered: bool,
    unknowns: u32,
    addr_bits: u8,
    /// True if a register set to an integer constant is taken as unknown.
    forget_integers: bool,
    /// Bounds proven so far, in path order.
    pub bounds: Vec<Bound>,
    /// Lower bounds: (value, least value, where proven). Only useful when an
    /// addition wraps the range back to 0 (`cmp edx, -8; jb default; lea
    /// eax, [rdx+8]`: `eax` is 0 to 7).
    lower: Vec<(Sym, u64, Va)>,
    /// An assumption to make once the next instruction is applied (see
    /// [`Tracker::assume_after_next`]).
    deferred: Option<(Reg, Known)>,
}

impl Tracker {
    /// A tracker for code with `addr_bits`-bit addresses.
    pub fn new(addr_bits: u8) -> Tracker {
        Tracker {
            regs: BTreeMap::new(),
            flags: None,
            clobbered: false,
            unknowns: 0,
            addr_bits,
            forget_integers: false,
            bounds: Vec::new(),
            lower: Vec::new(),
            deferred: None,
        }
    }

    /// A tracker that takes a register set to an integer constant (`mov r12d,
    /// 1`) as unknown, while addresses (`lea`, `adrp`) stay known. The only
    /// path known into a jump may be a loop's first iteration, where the
    /// index is a constant; a table's base is an address, its index is not.
    pub fn forgetting_integers(addr_bits: u8) -> Tracker {
        Tracker {
            forget_integers: true,
            ..Tracker::new(addr_bits)
        }
    }

    fn fresh(&mut self) -> Sym {
        self.unknowns += 1;
        Sym::Unknown(self.unknowns)
    }

    fn read(&mut self, reg: Reg) -> Sym {
        if let Some(v) = self.regs.get(&reg) {
            return v.clone();
        }
        let v = if self.clobbered {
            self.fresh()
        } else {
            Sym::Init(reg)
        };
        self.regs.insert(reg, v.clone());
        v
    }

    fn write(&mut self, dst: RegPart, v: Sym) {
        // A write of fewer than 32 bits keeps the rest of the register: the
        // result is not followed.
        let v = if dst.bits >= 32 {
            low(v, dst.bits)
        } else {
            self.fresh()
        };
        self.regs.insert(dst.reg, v);
    }

    fn addr(&mut self, a: &Addr) -> Sym {
        let mut s = Sym::Const(a.disp as u64);
        if let Some(b) = a.base {
            s = add(self.read(b), s);
        }
        if let Some(i) = a.index {
            let v = self.value(&Value::Reg {
                part: i.reg,
                signed: i.signed,
                shift: i.shift,
            });
            s = add(v, s);
        }
        low(s, self.addr_bits)
    }

    /// A bound from a lower bound and an addition that wraps: when `reg` now
    /// holds `a + k` at `w` bits and `a >= n` with `n + k = 2^w`, it holds 0 to
    /// `k - 1`.
    fn wrapped(&mut self, reg: Reg) {
        let Some(v) = self.regs.get(&reg) else { return };
        let w = v.width();
        let Sym::Add(b, k) = v.modulo(w) else { return };
        let Sym::Const(k) = **k else { return };
        if k == 0 {
            return;
        }
        let proof = self.lower.iter().find_map(|(a, n, at)| {
            (a.width() == w && a.modulo(w) == b.modulo(w) && n.wrapping_add(k) & mask(w) == 0)
                .then_some(*at)
        });
        if let Some(at) = proof {
            self.bounds.push(Bound {
                value: v.clone(),
                max: k - 1,
                at,
            });
        }
    }

    /// The expression for a value read now.
    pub fn value(&mut self, v: &Value) -> Sym {
        match *v {
            Value::Imm { value } => Sym::Const(value),
            Value::Reg {
                part,
                signed,
                shift,
            } => {
                let r = self.read(part.reg);
                let r = if signed {
                    sext(r, part.bits)
                } else {
                    low(r, part.bits)
                };
                shl(r, shift)
            }
            Value::Address { addr } => self.addr(&addr),
            Value::Load {
                addr,
                bytes,
                signed,
            } => Sym::Load {
                addr: Box::new(self.addr(&addr)),
                bytes,
                signed,
            },
        }
    }

    /// Applies one instruction's effect. `taken` says, for a conditional
    /// branch, which way the path goes.
    pub fn step(&mut self, at: Va, e: &Effect, taken: Option<bool>) {
        let deferred = self.deferred.take();
        self.apply(at, e, taken);
        if let Some((r, k)) = deferred {
            self.assume(r, k);
        }
    }

    /// Like [`Tracker::assume`], once the next instruction is applied: `call
    /// next; pop r` reads the instruction pointer, and `r` holds it only
    /// after the `pop`.
    pub fn assume_after_next(&mut self, reg: Reg, k: Known) {
        self.deferred = Some((reg, k));
    }

    fn apply(&mut self, at: Va, e: &Effect, taken: Option<bool>) {
        match e {
            Effect::Move { dst, src } => {
                let v = match src {
                    Value::Imm { .. } if self.forget_integers => self.fresh(),
                    _ => self.value(src),
                };
                self.write(*dst, v);
                self.wrapped(dst.reg);
            }
            Effect::Binary {
                op,
                dst,
                a,
                b,
                flags,
            } => {
                let (a, b) = (self.value(a), self.value(b));
                let r = match (op, &b) {
                    (BinOp::Add, _) => add(a.clone(), b.clone()),
                    (BinOp::Sub, Sym::Const(c)) => add(a.clone(), Sym::Const(c.wrapping_neg())),
                    (BinOp::Shl, Sym::Const(c)) => shl(a.clone(), (*c).min(64) as u8),
                    // `and` with a low mask is a bound in itself.
                    (BinOp::And, Sym::Const(m)) if *m != 0 && m.wrapping_add(1) & m == 0 => {
                        let k = 64 - m.leading_zeros() as u8;
                        let r = low(low(a.clone(), dst.bits), k);
                        self.bounds.push(Bound {
                            value: r.clone(),
                            max: *m,
                            at,
                        });
                        r
                    }
                    _ => self.fresh(),
                };
                self.write(*dst, r);
                self.wrapped(dst.reg);
                match flags {
                    Flags::Kept => {}
                    Flags::Compare => self.flags = Some((a, b)),
                    _ => self.flags = None,
                }
            }
            Effect::Compare { a, b } => {
                let (a, b) = (self.value(a), self.value(b));
                self.flags = Some((a, b));
            }
            Effect::Branch { cond } => {
                let (Some(taken), Some((a, Sym::Const(n)))) = (taken, &self.flags) else {
                    return;
                };
                let holds = if taken { *cond } else { cond.negate() };
                let max = match holds {
                    Cond::BelowOrEqual => *n,
                    Cond::Below if *n > 0 => n - 1,
                    Cond::AboveOrEqual => {
                        self.lower.push((a.clone(), *n, at));
                        return;
                    }
                    Cond::Above if *n < mask(a.width()) => {
                        self.lower.push((a.clone(), n + 1, at));
                        return;
                    }
                    _ => return,
                };
                self.bounds.push(Bound {
                    value: a.clone(),
                    max,
                    at,
                });
            }
            Effect::Other { writes, all, flags } => {
                if *all {
                    self.regs.clear();
                    self.clobbered = true;
                }
                for &r in writes {
                    let v = self.fresh();
                    self.regs.insert(r, v);
                }
                if *flags || *all {
                    self.flags = None;
                }
            }
            // A jump changes nothing on the path; anything else is unknown.
            Effect::Jump { .. } => {}
            _ => {
                self.regs.clear();
                self.clobbered = true;
                self.flags = None;
            }
        }
    }

    /// A register's value now, if it was written or read on the path.
    pub fn reg(&self, r: Reg) -> Option<&Sym> {
        self.regs.get(&r)
    }

    /// Starts a register with what is known of it where the path starts.
    pub fn assume(&mut self, reg: Reg, k: Known) {
        let v = match k {
            Known::Const(c) => Sym::Const(c),
            Known::Below(bits) => low(Sym::Init(reg), bits),
        };
        self.regs.insert(reg, v);
    }

    /// What is known of each register now: constants, and values that fit in
    /// fewer than 64 bits.
    pub fn known(&self) -> BTreeMap<Reg, Known> {
        self.regs
            .iter()
            .filter_map(|(&r, v)| {
                Some((
                    r,
                    match v {
                        Sym::Const(c) => Known::Const(*c),
                        Sym::Low(_, b) => Known::Below(*b),
                        Sym::Load {
                            bytes,
                            signed: false,
                            ..
                        } if *bytes < 8 => Known::Below(bytes * 8),
                        _ => return None,
                    },
                ))
            })
            .collect()
    }

    /// A call: every register but `kept` (the callee-saved ones) and the
    /// flags may change.
    pub fn call(&mut self, kept: &[Reg]) {
        self.deferred = None;
        let keep: Vec<(Reg, Sym)> = kept.iter().map(|&r| (r, self.read(r))).collect();
        self.regs.clear();
        self.regs.extend(keep);
        self.clobbered = true;
        self.flags = None;
    }

    /// The jump table behind a jump to `target`: the latest bound whose
    /// expression is the target's only unknown, with every entry read through
    /// `read` (address, bytes → little-endian value; `None` if not readable).
    /// `None` if there is no such bound, the bound is too large, or an entry
    /// cannot be read.
    pub fn table(&self, target: &Sym, read: &dyn Fn(u64, u8) -> Option<u64>) -> Option<Table> {
        let free = |b: &&Bound| !b.value.known_but(&Sym::Const(0));
        if let Some(b) = self
            .bounds
            .iter()
            .rev()
            .filter(free)
            .find(|b| target.known_but(&b.value))
        {
            return Self::read_entries(target, b, self.addr_bits, read);
        }
        None
    }

    /// Reads every entry `bound` allows.
    fn read_entries(
        target: &Sym,
        bound: &Bound,
        addr_bits: u8,
        read: &dyn Fn(u64, u8) -> Option<u64>,
    ) -> Option<Table> {
        if bound.max >= MAX_ENTRIES {
            return None;
        }
        let x = &bound.value;
        let am = mask(addr_bits);
        let targets = (0..=bound.max)
            .map(|i| target.eval(x, i, read).map(|t| t & am))
            .collect::<Option<Vec<u64>>>()?;
        let table = target
            .table_load(x)
            .and_then(|(addr, bytes)| Some((addr.eval(x, 0, read)? & am, bytes)));
        Some(Table {
            targets,
            table,
            bound: bound.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_ir::Index;

    const RAX: Reg = Reg(0);
    const RDX: Reg = Reg(2);
    const RDI: Reg = Reg(7);

    fn p(reg: Reg, bits: u8) -> RegPart {
        RegPart { reg, bits }
    }
    fn r(reg: Reg, bits: u8) -> Value {
        Value::Reg {
            part: p(reg, bits),
            signed: false,
            shift: 0,
        }
    }

    /// A little-endian memory image at 0x2000.
    fn reader(mem: Vec<u8>) -> impl Fn(u64, u8) -> Option<u64> {
        move |a, n| {
            let off = usize::try_from(a.checked_sub(0x2000)?).ok()?;
            let b = mem.get(off..off + usize::from(n))?;
            Some(b.iter().rev().fold(0, |v, &x| (v << 8) | u64::from(x)))
        }
    }

    /// gcc's position-independent table: offsets from the table itself.
    fn gcc_pic(t: &mut Tracker, cmp_bits: u8) -> Sym {
        let at = Va(0x1000);
        t.step(
            at,
            &Effect::Compare {
                a: r(RDI, cmp_bits),
                b: Value::Imm { value: 3 },
            },
            None,
        );
        t.step(at, &Effect::Branch { cond: Cond::Above }, Some(false));
        t.step(
            at,
            &Effect::Move {
                dst: p(RDX, 64),
                src: Value::Address {
                    addr: Addr {
                        base: None,
                        index: None,
                        disp: 0x2000,
                    },
                },
            },
            None,
        );
        t.step(
            at,
            &Effect::Move {
                dst: p(RAX, 64),
                src: Value::Load {
                    addr: Addr {
                        base: Some(RDX),
                        index: Some(Index {
                            reg: p(RDI, 64),
                            signed: false,
                            shift: 2,
                        }),
                        disp: 0,
                    },
                    bytes: 4,
                    signed: true,
                },
            },
            None,
        );
        t.step(
            at,
            &Effect::Binary {
                op: BinOp::Add,
                dst: p(RAX, 64),
                a: r(RAX, 64),
                b: r(RDX, 64),
                flags: Flags::Changed,
            },
            None,
        );
        t.value(&r(RAX, 64))
    }

    fn offsets(v: &[i32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    #[test]
    fn a_relative_table_is_read_for_every_index_the_bound_allows() {
        let mut t = Tracker::new(64);
        let target = gcc_pic(&mut t, 64);
        let read = reader(offsets(&[-0x100, -0xf0, -0x100, -0xe0, 0x55]));
        let table = t.table(&target, &read).unwrap();
        assert_eq!(table.targets, vec![0x1f00, 0x1f10, 0x1f00, 0x1f20]);
        assert_eq!(table.table, Some((0x2000, 4)));
        assert_eq!(table.bound.max, 3);
    }

    #[test]
    fn a_bound_on_the_32_bit_register_does_not_bound_the_64_bit_one() {
        // `cmp edi, 3` says nothing about the upper half of `rdi`.
        let mut t = Tracker::new(64);
        let target = gcc_pic(&mut t, 32);
        assert_eq!(t.table(&target, &reader(offsets(&[0; 4]))), None);
    }

    #[test]
    fn the_branch_direction_decides_the_bound() {
        for (cond, taken, max) in [
            (Cond::Above, false, Some(3)),
            (Cond::Above, true, None),
            (Cond::BelowOrEqual, true, Some(3)),
            (Cond::AboveOrEqual, false, Some(2)),
            (Cond::Below, true, Some(2)),
            (Cond::Other, false, None),
        ] {
            let mut t = Tracker::new(64);
            t.step(
                Va(1),
                &Effect::Compare {
                    a: r(RDI, 32),
                    b: Value::Imm { value: 3 },
                },
                None,
            );
            t.step(Va(2), &Effect::Branch { cond }, Some(taken));
            assert_eq!(t.bounds.first().map(|b| b.max), max, "{cond:?} {taken}");
        }
    }

    #[test]
    fn a_zero_extending_move_keeps_the_bound_and_a_clobber_loses_it() {
        // cmp edi, 1; ja; mov eax, edi; jmp [8*rax + 0x2000]
        let jump = |clobber: bool| {
            let mut t = Tracker::new(64);
            t.step(
                Va(1),
                &Effect::Compare {
                    a: r(RDI, 32),
                    b: Value::Imm { value: 1 },
                },
                None,
            );
            t.step(Va(2), &Effect::Branch { cond: Cond::Above }, Some(false));
            t.step(
                Va(3),
                &Effect::Move {
                    dst: p(RAX, 32),
                    src: r(RDI, 32),
                },
                None,
            );
            if clobber {
                t.step(Va(4), &Effect::UNKNOWN, None);
            }
            let target = t.value(&Value::Load {
                addr: Addr {
                    base: None,
                    index: Some(Index {
                        reg: p(RAX, 64),
                        signed: false,
                        shift: 3,
                    }),
                    disp: 0x2000,
                },
                bytes: 8,
                signed: false,
            });
            let mem: Vec<u8> = [0x1100u64, 0x1200, 0x1300]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            t.table(&target, &reader(mem)).map(|t| t.targets)
        };
        assert_eq!(jump(false), Some(vec![0x1100, 0x1200]));
        assert_eq!(jump(true), None);
    }

    #[test]
    fn a_bound_in_a_callee_saved_register_survives_a_call() {
        // and r13d, 3; call ...; jmp [8*r13 + 0x2000]
        const R13: Reg = Reg(13);
        let jump = |kept: &[Reg]| {
            let mut t = Tracker::new(64);
            t.step(
                Va(1),
                &Effect::Binary {
                    op: BinOp::And,
                    dst: p(R13, 32),
                    a: r(R13, 32),
                    b: Value::Imm { value: 3 },
                    flags: Flags::Changed,
                },
                None,
            );
            t.call(kept);
            let target = t.value(&Value::Load {
                addr: Addr {
                    base: None,
                    index: Some(Index {
                        reg: p(R13, 64),
                        signed: false,
                        shift: 3,
                    }),
                    disp: 0x2000,
                },
                bytes: 8,
                signed: false,
            });
            t.table(&target, &reader(vec![0; 32])).is_some()
        };
        assert!(jump(&[R13]));
        assert!(!jump(&[RDI]));
    }

    #[test]
    fn a_lower_bound_and_a_wrapping_addition_bound_the_index() {
        // glibc mallopt: cmp edx, -8; jb default; lea eax, [rdx+8];
        // jmp [8*rax + 0x2000]
        let jump = |n: u64| {
            let mut t = Tracker::new(64);
            t.step(
                Va(1),
                &Effect::Compare {
                    a: r(RDX, 32),
                    b: Value::Imm { value: n },
                },
                None,
            );
            t.step(Va(2), &Effect::Branch { cond: Cond::Below }, Some(false));
            t.step(
                Va(3),
                &Effect::Move {
                    dst: p(RAX, 32),
                    src: Value::Address {
                        addr: Addr {
                            base: Some(RDX),
                            index: None,
                            disp: 8,
                        },
                    },
                },
                None,
            );
            let target = t.value(&Value::Load {
                addr: Addr {
                    base: None,
                    index: Some(Index {
                        reg: p(RAX, 64),
                        signed: false,
                        shift: 3,
                    }),
                    disp: 0x2000,
                },
                bytes: 8,
                signed: false,
            });
            t.table(&target, &reader(vec![0; 64]))
                .map(|t| t.targets.len())
        };
        assert_eq!(jump(0xffff_fff8), Some(8));
        // -9 + 8 does not wrap to 0: the range is not 0 to 7.
        assert_eq!(jump(0xffff_fff7), None);
    }

    #[test]
    fn an_index_read_from_another_table_reads_both() {
        // cmp edi, 3; ja; movzx eax, byte [0x2000 + rdi]; jmp [0x2100 + 8*rax]
        let mut t = Tracker::new(64);
        t.step(
            Va(1),
            &Effect::Compare {
                a: r(RDI, 32),
                b: Value::Imm { value: 3 },
            },
            None,
        );
        t.step(Va(2), &Effect::Branch { cond: Cond::Above }, Some(false));
        t.step(
            Va(3),
            &Effect::Move {
                dst: p(RDI, 32),
                src: r(RDI, 32),
            },
            None,
        );
        t.step(
            Va(4),
            &Effect::Move {
                dst: p(RAX, 32),
                src: Value::Load {
                    addr: Addr {
                        base: None,
                        index: Some(Index {
                            reg: p(RDI, 64),
                            signed: false,
                            shift: 0,
                        }),
                        disp: 0x2000,
                    },
                    bytes: 1,
                    signed: false,
                },
            },
            None,
        );
        let target = t.value(&Value::Load {
            addr: Addr {
                base: None,
                index: Some(Index {
                    reg: p(RAX, 64),
                    signed: false,
                    shift: 3,
                }),
                disp: 0x2100,
            },
            bytes: 8,
            signed: false,
        });
        // Classes 0, 2, 1, 2: each index goes through its class.
        let mut mem = vec![0u8; 0x100 + 3 * 8];
        mem[..4].copy_from_slice(&[0, 2, 1, 2]);
        for (i, v) in [0x1100u64, 0x1200, 0x1300].iter().enumerate() {
            mem[0x100 + 8 * i..0x108 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        let table = t.table(&target, &reader(mem)).unwrap();
        assert_eq!(table.targets, vec![0x1100, 0x1300, 0x1200, 0x1300]);
    }

    #[test]
    fn an_and_mask_bounds_and_an_unreadable_entry_fails() {
        let mut t = Tracker::new(64);
        t.step(
            Va(1),
            &Effect::Binary {
                op: BinOp::And,
                dst: p(RAX, 32),
                a: r(RAX, 32),
                b: Value::Imm { value: 7 },
                flags: Flags::Changed,
            },
            None,
        );
        let target = t.value(&Value::Load {
            addr: Addr {
                base: None,
                index: Some(Index {
                    reg: p(RAX, 64),
                    signed: false,
                    shift: 3,
                }),
                disp: 0x2000,
            },
            bytes: 8,
            signed: false,
        });
        assert_eq!(t.bounds[0].max, 7);
        // Eight entries are needed; only seven are there.
        assert_eq!(t.table(&target, &reader(vec![0; 56])), None);
        assert_eq!(
            t.table(&target, &reader(vec![0; 64]))
                .unwrap()
                .targets
                .len(),
            8
        );
    }
}
