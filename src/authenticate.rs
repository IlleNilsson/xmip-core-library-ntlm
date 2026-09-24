//! The AUTHENTICATE message ([MS-NLMP] 2.2.1.3): the client's names, its
//! two responses to the challenge, and the MIC over the handshake.
//!
//! ```text
//!  0  Signature, MessageType (3)
//! 12  LmChallengeResponseFields
//! 20  NtChallengeResponseFields
//! 28  DomainNameFields
//! 36  UserNameFields
//! 44  WorkstationFields
//! 52  EncryptedRandomSessionKeyFields
//! 60  NegotiateFlags
//! 64  Version
//! 72  MIC, sixteen bytes; the payload follows at 88
//! ```
//!
//! A client that set 0x2 in its response's `MsvAvFlags` wrote a MIC; one
//! that did not may have put its payload where the MIC would be, and the
//! gate that holds a client to its MIC reads [`ClientChallenge::integrity`]
//! first.

use crate::client_challenge::ClientChallenge;
use crate::field::{self, Layout};
use crate::flags::NEGOTIATE_UNICODE;
use crate::{MessageType, NtlmError, Result};

const LM_RESPONSE_FIELDS: usize = 12;
const NT_RESPONSE_FIELDS: usize = 20;
const DOMAIN_FIELDS: usize = 28;
const USER_FIELDS: usize = 36;
const WORKSTATION_FIELDS: usize = 44;
const SESSION_KEY_FIELDS: usize = 52;
const FLAGS: usize = 60;
const PAYLOAD: usize = 88;
const PROOF: usize = 16;
/// An `NTLMv1` NT response is exactly this long.
const NTLMV1: usize = 24;
const KIND: &str = "AUTHENTICATE";

/// Where the MIC is in an AUTHENTICATE message.
pub const MIC_OFFSET: usize = 72;
/// How long the MIC is.
pub const MIC_LENGTH: usize = 16;

/// An AUTHENTICATE message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Authenticate {
    /// The `UserName` field, as the client spelled it; empty for an
    /// anonymous logon.
    pub user: String,
    /// The `DomainName` field, as the client spelled it; it enters the
    /// `NTLMv2` hash exactly so.
    pub domain: String,
    /// The `Workstation` field.
    pub workstation: String,
    /// The flags the two ends negotiated, as the client states them.
    pub flags: u32,
    /// The whole `LmChallengeResponse`.
    pub lm_response: Vec<u8>,
    /// The whole `NtChallengeResponse`.
    pub nt_response: Vec<u8>,
    /// The `EncryptedRandomSessionKey`, empty where no key was exchanged.
    pub session_key: Vec<u8>,
}

impl Authenticate {
    /// Read an AUTHENTICATE.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an AUTHENTICATE, are truncated, point
    /// outside themselves, or spell a name in text that is not UTF-16 where
    /// Unicode was negotiated.
    pub fn parse(message: &[u8]) -> Result<Self> {
        MessageType::Authenticate.expect(message)?;
        let flags = field::u32_at(message, FLAGS).ok_or_else(|| {
            NtlmError::new("the NTLM AUTHENTICATE message is truncated before its flags")
        })?;
        let unicode = flags & NEGOTIATE_UNICODE != 0;
        let bytes = |at: usize, name: &str| field::read(message, at, name, KIND);
        let text = |at: usize, name: &str| field::text(bytes(at, name)?, unicode, name);

        Ok(Self {
            user: text(USER_FIELDS, "UserName")?,
            domain: text(DOMAIN_FIELDS, "DomainName")?,
            workstation: text(WORKSTATION_FIELDS, "Workstation")?,
            flags,
            lm_response: bytes(LM_RESPONSE_FIELDS, "LmChallengeResponse")?.to_vec(),
            nt_response: bytes(NT_RESPONSE_FIELDS, "NtChallengeResponse")?.to_vec(),
            session_key: bytes(SESSION_KEY_FIELDS, "EncryptedRandomSessionKey")?.to_vec(),
        })
    }

    /// The message, its version and MIC zero and its payload at 88; a
    /// client that writes a MIC writes it over [`MIC_OFFSET`] afterwards.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let unicode = self.flags & NEGOTIATE_UNICODE != 0;
        Layout::new(MessageType::Authenticate.head(), PAYLOAD)
            .field(&self.lm_response)
            .field(&self.nt_response)
            .field(&field::encode_text(&self.domain, unicode))
            .field(&field::encode_text(&self.user, unicode))
            .field(&field::encode_text(&self.workstation, unicode))
            .field(&self.session_key)
            .raw(&self.flags.to_le_bytes())
            .finish()
    }

    /// The MIC an AUTHENTICATE message carries at [`MIC_OFFSET`], where it
    /// reaches that far.
    #[must_use]
    pub fn mic(message: &[u8]) -> Option<&[u8; MIC_LENGTH]> {
        message
            .get(MIC_OFFSET..MIC_OFFSET + MIC_LENGTH)
            .and_then(|mic| mic.try_into().ok())
    }

    /// The NT response as `NTLMv2` lays it out (2.2.2.8): the sixteen bytes
    /// of `NTProofStr`, and the client's blob they cover.
    ///
    /// # Errors
    ///
    /// Where the response is `NTLMv1`, is too short to be `NTLMv2`, or its
    /// blob is not an `NTLMv2` client challenge.
    pub fn ntlmv2(&self) -> Result<(&[u8; PROOF], &[u8])> {
        if self.nt_response.len() == NTLMV1 {
            return Err(NtlmError::new("the NT response is NTLMv1, not NTLMv2"));
        }
        let Some((proof, blob)) = self.nt_response.split_first_chunk::<PROOF>() else {
            return Err(NtlmError::new(
                "the NTLM AUTHENTICATE message carries no NTLMv2 response",
            ));
        };
        if !ClientChallenge::is_blob(blob) {
            return Err(NtlmError::new(
                "the NT response's blob is not an NTLMv2 client challenge",
            ));
        }
        Ok((proof, blob))
    }

    /// The client's half of the NT response, where it is an `NTLMv2` one.
    ///
    /// # Errors
    ///
    /// As [`ClientChallenge::read`].
    pub fn client_challenge(&self) -> Result<Option<ClientChallenge>> {
        match self.nt_response.get(PROOF..) {
            Some(blob) if !blob.is_empty() => ClientChallenge::read(blob),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THEN: u64 = 1_800_000_000;

    fn made(nt_response: &[u8]) -> Authenticate {
        Authenticate {
            user: "alice".to_string(),
            domain: "CORP".to_string(),
            workstation: "WS01".to_string(),
            flags: NEGOTIATE_UNICODE,
            lm_response: vec![0; 24],
            nt_response: nt_response.to_vec(),
            session_key: Vec::new(),
        }
    }

    #[test]
    fn a_type_3_is_written_and_read_back_into_its_names_its_proof_and_its_blob() {
        let challenge = ClientChallenge {
            target: Some("HTTP/xmip.example".to_string()),
            ..ClientChallenge::at(THEN)
        };
        let blob = challenge.to_blob([0x22; 8]);
        let mut response = vec![7u8; 16];
        response.extend_from_slice(&blob);
        let sent = made(&response);

        let bytes = sent.to_bytes();
        assert_eq!(Authenticate::mic(&bytes), Some(&[0u8; MIC_LENGTH]));
        let read = Authenticate::parse(&bytes).expect("read");
        assert_eq!(read, sent);
        let (proof, covered) = read.ntlmv2().expect("NTLMv2");
        assert_eq!((proof, covered), (&[7u8; 16], blob.as_slice()));
        assert_eq!(read.client_challenge().expect("read"), Some(challenge));
    }

    #[test]
    fn names_are_one_byte_a_character_where_unicode_was_not_negotiated() {
        let sent = Authenticate {
            flags: 0,
            ..made(&[])
        };
        assert_eq!(Authenticate::parse(&sent.to_bytes()).expect("read"), sent);
    }

    #[test]
    fn a_message_of_another_type_cut_short_or_pointing_away_is_refused_by_name() {
        let refused = |bytes: &[u8]| Authenticate::parse(bytes).expect_err("refused").message;
        assert!(refused(&MessageType::Challenge.head()).contains("CHALLENGE"));
        assert!(refused(b"not an NTLM message").contains("NTLMSSP signature"));
        assert!(refused(&made(&[]).to_bytes()[..40]).contains("truncated"));
        assert!(refused(&made(&[]).to_bytes()[..70]).contains("points outside"));

        let mut astray = made(&[1; 30]).to_bytes();
        astray[24..28].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(refused(&astray).contains("NtChallengeResponse"));
    }

    #[test]
    fn an_ntlmv1_or_absent_response_is_no_ntlmv2_and_says_which() {
        let refused = |response: &[u8]| {
            let read = made(response);
            assert_eq!(read.client_challenge().expect("read"), None);
            read.ntlmv2().expect_err("refused").message
        };

        assert!(refused(&[0; 24]).contains("NTLMv1"));
        assert!(refused(&[0; 8]).contains("carries no NTLMv2 response"));
        let mut odd = vec![0; 16];
        odd.extend_from_slice(&[2; 30]);
        assert!(
            made(&odd)
                .ntlmv2()
                .expect_err("odd")
                .message
                .contains("blob")
        );
    }
}
