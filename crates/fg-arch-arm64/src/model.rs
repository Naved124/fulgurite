//! Types of the generated tables (`tables.rs`).

/// A node of the decode tree: a group of encodings or one encoding.
pub(crate) struct Node {
    /// Bits this node fixes.
    pub mask: u32,
    /// Their values.
    pub value: u32,
    /// Extra condition on fields (0: none).
    pub cond: u16,
    /// First child in `NODES`.
    pub first: u16,
    /// Number of children (0 for an encoding).
    pub count: u16,
    /// Encoding index for a leaf, `0xFFFF` for a group.
    pub enc: u16,
}

/// One encoding: its assembler template and aliases.
pub(crate) struct Enc {
    /// Arm's name for the encoding (`ADD_64_addsub_imm`); empty for an
    /// encoding left out (not described by the XML release).
    pub name: &'static str,
    /// Bits the encoding fixes, and their values.
    pub mask: u32,
    pub value: u32,
    /// Bits that should have a value (CONSTRAINED UNPREDICTABLE otherwise).
    pub sb_mask: u32,
    pub sb_value: u32,
    /// Template: `ITEMS[items..items + len]`.
    pub items: u32,
    pub len: u16,
    /// Aliases: `ALIASES[alias..alias + aliases]`.
    pub alias: u16,
    pub aliases: u16,
    /// UNDEFINED check from the decode pseudocode (`undefined(undef, word)`).
    pub undef: u16,
    /// CONSTRAINED UNPREDICTABLE check (`undefined(unpred, word)`).
    pub unpred: u16,
}

/// An alias (`MOV` for `ORR`, `LSL` for `UBFM`...).
pub(crate) struct Alias {
    /// When the alias can express the encoding.
    pub cond: u16,
    /// When the alias is the preferred disassembly.
    pub preferred: u16,
    pub items: u32,
    pub len: u16,
}

/// One element of an assembler template.
#[derive(Clone, Copy)]
pub(crate) enum Item {
    /// Fixed text (lower case).
    Text(&'static str),
    /// The separator between mnemonic and operands.
    Space,
    /// An operand (`OPS` index).
    Op(u16),
    /// The next n items are optional: left out when every operand in them has
    /// its default value.
    Opt(u16),
    /// n alternatives follow, each introduced by `Branch`: the first that can
    /// be printed is used.
    Alt(u16),
    /// One alternative of `Alt`, n items long.
    Branch(u16),
}

/// An operand.
pub(crate) struct Op {
    pub kind: Kind,
    /// Value expression (`value(val, word)`).
    pub val: u16,
    /// Value at which an optional part is left out.
    pub default: Dflt,
    /// Valid values; others are reserved encodings.
    pub valid: Option<(i64, i64)>,
    /// Condition under which the operand applies (0: always); otherwise the
    /// alternative that holds it is not taken.
    pub when: u16,
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    /// Register: prefix, number, suffix; `r31` names register 31 (SP or ZR).
    Reg {
        prefix: &'static str,
        suffix: &'static str,
        r31: Option<&'static str>,
    },
    /// `#value`.
    Imm,
    /// Value without `#`.
    Num,
    /// Value in hexadecimal, with `#` if set.
    Hex(bool),
    /// PC-relative code or data address.
    Label,
    /// PC-relative 4 KiB page address (`adrp`).
    Page,
    /// Value looked up in `VTABLES`.
    Table(u16),
    /// Logical immediate of the given register width.
    Bitmask(u8),
    /// 8-bit floating-point immediate.
    FpImm,
    /// System register; `true` for writes (MSR).
    SysReg(bool),
    /// Text if the value is non-zero.
    Flag(&'static str),
    /// Fixed text.
    Const(&'static str),
    /// SME `ZERO` tile list.
    ZaMask,
}

#[derive(Clone, Copy)]
pub(crate) enum Dflt {
    None,
    Int(i64),
    /// The value, unless the condition holds (a system operation that reads
    /// its register shows XZR).
    IntUnless(i64, u16),
    Text(&'static str),
}

/// A row of a value table.
pub(crate) struct Entry {
    pub mask: u32,
    pub value: u32,
    /// Text, or `None` with `value_of == 0xFFFF` for a reserved value.
    pub text: Option<&'static str>,
    /// Value expression printed as a number instead of text.
    pub value_of: u16,
}
