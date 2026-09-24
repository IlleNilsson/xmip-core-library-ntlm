//! The two things every message is built of: the fixed-width numbers of
//! its header, and the `Len, MaxLen, BufferOffset` fields ([MS-NLMP]
//! 2.2.1.1) that point from the header into the payload after it.

use crate::{NtlmError, Result};

/// A little-endian `u16` at `at`, where the message reaches that far.
pub(crate) fn u16_at(message: &[u8], at: usize) -> Option<u16> {
    let bytes = message.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// A little-endian `u32` at `at`, where the message reaches that far.
pub(crate) fn u32_at(message: &[u8], at: usize) -> Option<u32> {
    let bytes = message.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The bytes the field at `at` points to, named `name` in a refusal of
/// `kind`, the message it is part of.
pub(crate) fn read<'a>(message: &'a [u8], at: usize, name: &str, kind: &str) -> Result<&'a [u8]> {
    let (Some(length), Some(offset)) = (u16_at(message, at), u32_at(message, at + 4)) else {
        return Err(NtlmError::new(format!(
            "the NTLM {kind} message is truncated before its {name} field"
        )));
    };
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    message
        .get(offset..offset.saturating_add(usize::from(length)))
        .ok_or_else(|| {
            NtlmError::new(format!(
                "the NTLM {kind} message's {name} points outside the message"
            ))
        })
}

/// A name field's text: UTF-16 where Unicode was negotiated, else one
/// character a byte.
pub(crate) fn text(bytes: &[u8], unicode: bool, name: &str) -> Result<String> {
    if unicode {
        codec::utf16::decode(bytes)
            .map_err(|error| NtlmError::new(format!("the NTLM {name}: {error}")))
    } else {
        Ok(bytes.iter().map(|byte| char::from(*byte)).collect())
    }
}

/// `text` as a name field holds it: UTF-16 where Unicode was negotiated,
/// else one byte a character, `?` for one outside a byte.
pub(crate) fn encode_text(text: &str, unicode: bool) -> Vec<u8> {
    if unicode {
        codec::utf16::encode(text)
    } else {
        text.chars()
            .map(|character| u8::try_from(character).unwrap_or(b'?'))
            .collect()
    }
}

/// A message being written: the header in order, and the payload its
/// fields point into, which begins at `base`.
pub(crate) struct Layout {
    header: Vec<u8>,
    payload: Vec<u8>,
    base: usize,
}

impl Layout {
    /// A message whose header opens with `head` and whose payload begins
    /// `base` bytes in.
    pub(crate) const fn new(head: Vec<u8>, base: usize) -> Self {
        Self {
            header: head,
            payload: Vec::new(),
            base,
        }
    }

    /// Header bytes as they are.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.header.extend_from_slice(bytes);
        self
    }

    /// A field pointing at `bytes`, which join the payload. Longer than a
    /// field can say is cut to what it can.
    pub(crate) fn field(&mut self, bytes: &[u8]) -> &mut Self {
        let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        let offset = u32::try_from(self.base + self.payload.len()).unwrap_or(u32::MAX);
        self.header.extend_from_slice(&length.to_le_bytes());
        self.header.extend_from_slice(&length.to_le_bytes());
        self.header.extend_from_slice(&offset.to_le_bytes());
        self.payload
            .extend_from_slice(&bytes[..usize::from(length)]);
        self
    }

    /// The message: the header, zero-filled to `base`, then the payload.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut message = core::mem::take(&mut self.header);
        message.resize(self.base.max(message.len()), 0);
        message.append(&mut self.payload);
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_written_is_read_back_and_one_pointing_away_is_refused_by_name() {
        let message = Layout::new(vec![0xEE; 4], 30)
            .field(b"abc")
            .raw(&[1, 2])
            .field(b"")
            .finish();
        assert_eq!(message.len(), 33);
        assert_eq!(read(&message, 4, "first", "test").expect("read"), b"abc");
        assert_eq!(read(&message, 14, "second", "test").expect("read"), b"");

        let mut astray = message.clone();
        astray[8..12].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let refused = read(&astray, 4, "first", "test").expect_err("astray");
        assert!(
            refused.message.contains("first points outside"),
            "{refused}"
        );
        let short = read(&message[..10], 4, "first", "test").expect_err("short");
        assert!(
            short.message.contains("truncated before its first"),
            "{short}"
        );
    }

    #[test]
    fn a_name_is_utf_16_under_unicode_and_a_byte_a_character_without() {
        for unicode in [true, false] {
            let bytes = encode_text("Jürgen", unicode);
            assert_eq!(text(&bytes, unicode, "user").expect("text"), "Jürgen");
        }
        assert_eq!(encode_text("a\u{3000}", false), b"a?");
        let refused = text(&[0x41], true, "UserName").expect_err("odd");
        assert!(refused.message.contains("UserName"), "{refused}");
    }
}
