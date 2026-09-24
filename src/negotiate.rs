//! The NEGOTIATE message ([MS-NLMP] 2.2.1.1): the client's flags, and a
//! domain and workstation it may name.
//!
//! ```text
//!  0  Signature, MessageType (1)
//! 12  NegotiateFlags
//! 16  DomainNameFields         OEM, where the client names one
//! 24  WorkstationFields        OEM, where the client names one
//! 32  Version, where negotiated; the payload follows
//! ```

use crate::field::{self, Layout};
use crate::{MessageType, NtlmError, Result};

const FLAGS: usize = 12;
const DOMAIN_FIELDS: usize = 16;
const WORKSTATION_FIELDS: usize = 24;
const PAYLOAD: usize = 40;
const KIND: &str = "NEGOTIATE";

/// A NEGOTIATE message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Negotiate {
    /// What the client asks to negotiate ([`crate::flags`]).
    pub flags: u32,
    /// The domain the client names, empty where it names none.
    pub domain: String,
    /// The workstation the client names, empty where it names none.
    pub workstation: String,
}

impl Negotiate {
    /// A NEGOTIATE asking for `flags` and naming nothing.
    #[must_use]
    pub fn new(flags: u32) -> Self {
        Self {
            flags,
            ..Self::default()
        }
    }

    /// Read a NEGOTIATE. A message of the older, shorter form that ends
    /// after its flags names no domain and no workstation.
    ///
    /// # Errors
    ///
    /// Where the bytes are not a NEGOTIATE, end before its flags, or point
    /// outside themselves.
    pub fn parse(message: &[u8]) -> Result<Self> {
        MessageType::Negotiate.expect(message)?;
        let flags = field::u32_at(message, FLAGS).ok_or_else(|| {
            NtlmError::new("the NTLM NEGOTIATE message is truncated before its flags")
        })?;
        let name = |at: usize, name: &str| {
            if message.len() < at + 8 {
                return Ok(String::new());
            }
            field::text(field::read(message, at, name, KIND)?, false, name)
        };
        Ok(Self {
            flags,
            domain: name(DOMAIN_FIELDS, "DomainName")?,
            workstation: name(WORKSTATION_FIELDS, "Workstation")?,
        })
    }

    /// The message, its version zero.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Layout::new(MessageType::Negotiate.head(), PAYLOAD)
            .raw(&self.flags.to_le_bytes())
            .field(&field::encode_text(&self.domain, false))
            .field(&field::encode_text(&self.workstation, false))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{NEGOTIATE_NTLM, NEGOTIATE_UNICODE};

    #[test]
    fn a_negotiate_is_written_and_read_back() {
        let sent = Negotiate {
            flags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM,
            domain: "CORP".to_string(),
            workstation: "WS01".to_string(),
        };
        let bytes = sent.to_bytes();
        assert_eq!(
            MessageType::of(&bytes).expect("a type"),
            MessageType::Negotiate
        );
        assert_eq!(Negotiate::parse(&bytes).expect("read"), sent);
        let bare = Negotiate::new(NEGOTIATE_UNICODE);
        assert_eq!(Negotiate::parse(&bare.to_bytes()).expect("read"), bare);
    }

    #[test]
    fn the_short_form_reads_and_a_message_without_flags_or_of_another_type_does_not() {
        let mut short = MessageType::Negotiate.head();
        short.extend_from_slice(&0xE208_8297u32.to_le_bytes());
        assert_eq!(
            Negotiate::parse(&short).expect("read"),
            Negotiate::new(0xE208_8297)
        );
        let refused = |bytes: &[u8]| Negotiate::parse(bytes).expect_err("refused").message;
        assert!(refused(&short[..12]).contains("before its flags"));
        assert!(refused(&MessageType::Challenge.head()).contains("CHALLENGE"));
    }
}
