//! String tables: NUL-terminated names referenced by offset.

use fg_core::{ByteView, Field, Span};

/// A bounds-checked view of one string table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StringTable<'a> {
    view: ByteView<'a>,
    span: Span,
    max_len: u64,
}

impl<'a> StringTable<'a> {
    /// A table occupying `span` of the file. The span is clamped to the file, so a
    /// lying size can never make lookups read past the end.
    pub fn new(view: ByteView<'a>, span: Span, max_len: u64) -> StringTable<'a> {
        let start = span.offset.0.min(view.len());
        let len = span.len.min(view.len() - start);
        StringTable {
            view,
            span: Span::new(start, len),
            max_len,
        }
    }

    /// The name at `offset` within the table, or `None` if the offset is outside
    /// the table or the name has no terminator inside it.
    pub fn get(&self, offset: u32) -> Option<Field<String>> {
        let rel = u64::from(offset);
        if rel >= self.span.len {
            return None;
        }
        // The table's offset and size come from the file: no wrap-around.
        let at = self.span.offset.0.checked_add(rel)?;
        let limit = (self.span.len - rel).min(self.max_len.saturating_add(1));
        self.view
            .cstr(at, limit)
            .ok()
            .flatten()
            .map(|f| f.map(|b| String::from_utf8_lossy(b).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::Endian;

    #[test]
    fn lookups_stay_inside_the_table() {
        let data = b"\0abc\0def\0ghi";
        let v = ByteView::new(data, Endian::Little);
        let t = StringTable::new(v, Span::new(0, 9), 64);
        assert_eq!(t.get(0).unwrap().value, "");
        assert_eq!(t.get(1).unwrap().value, "abc");
        assert_eq!(t.get(5).unwrap().span, Span::new(5, 3));
        assert!(t.get(9).is_none(), "offset 9 is past the 9-byte table");
        assert!(t.get(u32::MAX).is_none());
    }

    #[test]
    fn lying_size_is_clamped_and_unterminated_names_rejected() {
        let data = b"\0abc";
        let v = ByteView::new(data, Endian::Little);
        let t = StringTable::new(v, Span::new(0, 1_000_000), 64);
        assert!(
            t.get(1).is_none(),
            "'abc' has no terminator before end of file"
        );
        let t = StringTable::new(v, Span::new(50, 10), 64);
        assert!(t.get(0).is_none(), "table starting past EOF is empty");
    }

    #[test]
    fn max_len_is_enforced() {
        let data = b"\0abcdefgh\0";
        let v = ByteView::new(data, Endian::Little);
        let t = StringTable::new(v, Span::new(0, 10), 4);
        assert!(t.get(1).is_none(), "8-character name exceeds max_len 4");
    }
}
