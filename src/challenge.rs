//! The CHALLENGE message ([MS-NLMP] 2.2.1.2): the server's flags, its
//! eight-byte nonce, and what it says of itself.
//!
//! ```text
//!  0  Signature, MessageType (2)
//! 12  TargetNameFields
//! 20  NegotiateFlags
//! 24  ServerChallenge          eight bytes
//! 32  Reserved                 eight bytes
//! 40  TargetInfoFields         attribute and value pairs (2.2.2.1)
//! 48  Version; the payload follows at 56
//! ```

use crate::field::{self, Layout};
use crate::flags::NEGOTIATE_UNICODE;
use crate::{MessageType, NtlmError, Result};

const TARGET_NAME_FIELDS: usize = 12;
const FLAGS: usize = 20;
const SERVER_CHALLENGE: usize = 24;
const TARGET_INFO_FIELDS: usize = 40;
const PAYLOAD: usize = 56;
const KIND: &str = "CHALLENGE";

/// A CHALLENGE message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Challenge {
    /// What the server agreed to ([`crate::flags`]).
    pub flags: u32,
    /// The nonce the client's response proves under.
    pub server_challenge: [u8; 8],
    /// The name the server gives itself, empty where it gives none.
    pub target_name: String,
    /// The target information, as attribute and value pairs, whole; empty
    /// where the server sends none.
    pub target_info: Vec<u8>,
}

impl Challenge {
    /// A CHALLENGE agreeing to `flags` under `server_challenge`, saying
    /// nothing of the server.
    #[must_use]
    pub fn new(flags: u32, server_challenge: [u8; 8]) -> Self {
        Self {
            flags,
            server_challenge,
            ..Self::default()
        }
    }

    /// Read a CHALLENGE. One that ends after its reserved bytes carries no
    /// target information.
    ///
    /// # Errors
    ///
    /// Where the bytes are not a CHALLENGE, end before its nonce, point
    /// outside themselves, or name the target in text that is not UTF-16
    /// where Unicode was agreed.
    pub fn parse(message: &[u8]) -> Result<Self> {
        MessageType::Challenge.expect(message)?;
        let (Some(flags), Some(nonce)) = (
            field::u32_at(message, FLAGS),
            message.get(SERVER_CHALLENGE..SERVER_CHALLENGE + 8),
        ) else {
            return Err(NtlmError::new(
                "the NTLM CHALLENGE message is truncated before its server challenge",
            ));
        };
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(nonce);
        let target_name = field::read(message, TARGET_NAME_FIELDS, "TargetName", KIND)?;
        let target_info = if message.len() < TARGET_INFO_FIELDS + 8 {
            Vec::new()
        } else {
            field::read(message, TARGET_INFO_FIELDS, "TargetInfo", KIND)?.to_vec()
        };
        Ok(Self {
            flags,
            server_challenge,
            target_name: field::text(target_name, flags & NEGOTIATE_UNICODE != 0, "TargetName")?,
            target_info,
        })
    }

    /// The message, its reserved bytes and version zero.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let unicode = self.flags & NEGOTIATE_UNICODE != 0;
        Layout::new(MessageType::Challenge.head(), PAYLOAD)
            .field(&field::encode_text(&self.target_name, unicode))
            .raw(&self.flags.to_le_bytes())
            .raw(&self.server_challenge)
            .raw(&[0; 8])
            .field(&self.target_info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_written_and_read_back_with_its_nonce_at_24() {
        let sent = Challenge {
            flags: NEGOTIATE_UNICODE,
            server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            target_name: "CORP".to_string(),
            target_info: vec![0, 0, 0, 0],
        };
        let bytes = sent.to_bytes();
        assert_eq!(&bytes[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(Challenge::parse(&bytes).expect("read"), sent);
        let bare = Challenge::new(0, [9; 8]);
        assert_eq!(Challenge::parse(&bare.to_bytes()).expect("read"), bare);
    }

    #[test]
    fn a_challenge_without_target_information_reads_and_one_cut_short_does_not() {
        // The oldest form: the header up to the reserved bytes, and nothing.
        let mut old = MessageType::Challenge.head();
        old.extend_from_slice(&[0, 0, 0, 0, 40, 0, 0, 0]);
        old.extend_from_slice(&0u32.to_le_bytes());
        old.extend_from_slice(&[7; 8]);
        old.extend_from_slice(&[0; 8]);
        let read = Challenge::parse(&old).expect("read");
        assert_eq!(read.server_challenge, [7; 8]);
        assert!(read.target_info.is_empty());

        let refused = Challenge::parse(&old[..28]).expect_err("short");
        assert!(refused.message.contains("server challenge"), "{refused}");
        let other = Challenge::parse(&MessageType::Negotiate.head()).expect_err("other");
        assert!(other.message.contains("NEGOTIATE"), "{other}");
    }
}
