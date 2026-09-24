#![forbid(unsafe_code)]

//! The NTLM message layout ([MS-NLMP] section 2.2): the three messages of
//! one handshake, read and written, and the `NTLMv2` client challenge a
//! response carries.
//!
//! ```text
//! NEGOTIATE      type 1  the client's flags                       Negotiate
//! CHALLENGE      type 2  the server's flags and eight-byte nonce  Challenge
//! AUTHENTICATE   type 3  the names, the responses, the MIC        Authenticate
//! ```
//!
//! Every message opens with [`SIGNATURE`] and its type, little-endian, and
//! points into its own payload with `Len, MaxLen, BufferOffset` fields.
//! Names are UTF-16 where [`flags::NEGOTIATE_UNICODE`] is set, else one
//! byte a character, as the specification's OEM encoding reads here.
//!
//! Until 2026-09-24 the layout was written three times: the identity
//! capability read the AUTHENTICATE message for both gates, the second gate
//! read the CHALLENGE's nonce and the MIC by offset, and the SMB transport
//! wrote and read a counted-field simplification of all three that no
//! other NTLM speaker would have understood. What a message proves — the
//! `NTLMv2` hash, the MIC's HMAC, whether a user is enough to claim by —
//! is the gate's, not this crate's.
//!
//! A capability turns an [`NtlmError`] into its own error with `From`, so a
//! technology writes `?` and the reason travels unchanged.

mod authenticate;
mod challenge;
mod client_challenge;
mod field;
pub mod flags;
mod negotiate;

pub use authenticate::{Authenticate, MIC_LENGTH, MIC_OFFSET};
pub use challenge::Challenge;
pub use client_challenge::ClientChallenge;
pub use negotiate::Negotiate;

/// The eight bytes every NTLMSSP message opens with. `Negotiate` carries
/// NTLM as well as Kerberos, and this is how a reader tells.
pub const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Which of the three messages a message says it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    /// `NtLmNegotiate`, type 1: the client's opening.
    Negotiate,
    /// `NtLmChallenge`, type 2: the server's answer.
    Challenge,
    /// `NtLmAuthenticate`, type 3: the client's credential.
    Authenticate,
}

impl MessageType {
    /// The number a message carries at offset 8.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Negotiate => 1,
            Self::Challenge => 2,
            Self::Authenticate => 3,
        }
    }

    /// Which message `message` is.
    ///
    /// # Errors
    ///
    /// Where it does not open with [`SIGNATURE`] and a type of 1, 2 or 3.
    pub fn of(message: &[u8]) -> Result<Self> {
        if !message.starts_with(SIGNATURE) {
            return Err(NtlmError::new("the NTLM message has no NTLMSSP signature"));
        }
        match field::u32_at(message, 8) {
            Some(1) => Ok(Self::Negotiate),
            Some(2) => Ok(Self::Challenge),
            Some(3) => Ok(Self::Authenticate),
            Some(other) => Err(NtlmError::new(format!(
                "the NTLM message type is {other}, not 1, 2 or 3"
            ))),
            None => Err(NtlmError::new("the NTLM message ends before its type")),
        }
    }

    /// The signature and this type, as every message opens.
    fn head(self) -> Vec<u8> {
        let mut head = SIGNATURE.to_vec();
        head.extend_from_slice(&self.number().to_le_bytes());
        head
    }

    /// Refuse a message that is another type than this.
    fn expect(self, message: &[u8]) -> Result<()> {
        let found = Self::of(message)?;
        if found == self {
            Ok(())
        } else {
            Err(NtlmError::new(format!(
                "the NTLM message is {}, not {}",
                found.name(),
                self.name()
            )))
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Negotiate => "a NEGOTIATE (type 1)",
            Self::Challenge => "a CHALLENGE (type 2)",
            Self::Authenticate => "an AUTHENTICATE (type 3)",
        }
    }
}

/// Why bytes are not the NTLM message they were read as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtlmError {
    /// What was wrong, in words.
    pub message: String,
}

impl NtlmError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for NtlmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for NtlmError {}

/// The result of reading a message.
pub type Result<T> = core::result::Result<T, NtlmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_says_its_type_and_a_stranger_is_refused_saying_why() {
        for kind in [
            MessageType::Negotiate,
            MessageType::Challenge,
            MessageType::Authenticate,
        ] {
            assert_eq!(MessageType::of(&kind.head()).expect("a type"), kind);
        }
        let refused = |bytes: &[u8]| MessageType::of(bytes).expect_err("refused").message;
        assert!(refused(b"not an NTLM message").contains("NTLMSSP signature"));
        assert!(refused(b"NTLMSSP\0\x01").contains("ends before its type"));
        assert!(refused(b"NTLMSSP\0\x04\0\0\0").contains("type is 4"));
        let wrong = MessageType::Challenge.expect(&MessageType::Negotiate.head());
        assert!(
            wrong
                .expect_err("wrong")
                .message
                .contains("NEGOTIATE (type 1)")
        );
    }
}
