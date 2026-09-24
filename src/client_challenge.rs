//! The client's half of an `NTLMv2` response ([MS-NLMP] 2.2.2.7): when it
//! was made, and what the client says about the service and the channel it
//! meant.
//!
//! An NT response under `NTLMv2` is the 16-byte proof followed by this, the
//! part MS-NLMP calls the blob, or `temp`: a response type and its highest
//! supported type, one byte each and both 1; six reserved bytes; a
//! timestamp, eight bytes, in hundred-nanosecond ticks since 1601; the
//! client's challenge, eight bytes; four reserved bytes; and then a list of
//! attribute and value pairs (2.2.2.1), each an identifier and a length,
//! two bytes each and little-endian, and that many bytes of value, ending
//! at `MsvAvEOL`. `MsvAvTargetName`, 0x0009, is the service principal name
//! of the target server, UTF-16 and not null-terminated. `MsvAvFlags`,
//! 0x0006, carries a bit, 0x4, that says the client took that name from an
//! untrusted source, which section 3.2.5.1.2 has a server treat as no name
//! at all, and 0x2, which says the AUTHENTICATE message has a MIC.
//! `MsvAvChannelBindings`, 0x000A, is the MD5 of the channel the client
//! spoke over, sixteen bytes and all zero where it bound to none.

use crate::{NtlmError, Result};

const FIXED: usize = 28;
const TIMESTAMP: usize = 8;
const END_OF_LIST: u16 = 0x0000;
const FLAGS: u16 = 0x0006;
const TARGET_NAME: u16 = 0x0009;
const CHANNEL_BINDINGS: u16 = 0x000A;
const HAS_INTEGRITY: u32 = 0x0000_0002;
const UNTRUSTED_SOURCE: u32 = 0x0000_0004;

/// Seconds between 1601-01-01 and the Unix epoch.
const EPOCH_GAP: u64 = 11_644_473_600;
const TICKS_PER_SECOND: u64 = 10_000_000;

/// The most pairs a list is walked for. The specification names eleven
/// kinds; a list far longer than that is not one.
const MOST_PAIRS: usize = 64;

/// What the client put in its `NTLMv2` response besides its challenge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientChallenge {
    /// When the client made the response: hundred-nanosecond ticks since
    /// 1601-01-01, as it is on the wire.
    pub timestamp: u64,
    /// The service principal name of the server the client meant to reach,
    /// as the client wrote it.
    pub target: Option<String>,
    /// Whether the client says it took that name from an untrusted source.
    pub untrusted: bool,
    /// Whether the client says its AUTHENTICATE message carries a MIC.
    pub integrity: bool,
    /// The hash of the channel the client bound the response to, where it
    /// bound to one: all zero on the wire is none.
    pub channel: Option<[u8; 16]>,
}

/// An attribute's identifier, its value, and the bytes after it.
type Pair<'a> = (u16, &'a [u8], &'a [u8]);

impl ClientChallenge {
    /// A client challenge made at `unix_seconds`, saying nothing else.
    #[must_use]
    pub fn at(unix_seconds: u64) -> Self {
        Self {
            timestamp: (unix_seconds + EPOCH_GAP) * TICKS_PER_SECOND,
            ..Self::default()
        }
    }

    /// Read the blob of an NT response: everything after the 16-byte proof.
    /// `None` where it is not an `NTLMv2` client challenge — an `NTLMv1`
    /// response is eight bytes here and carries none of this.
    ///
    /// # Errors
    ///
    /// Where a pair runs past the end of the blob, or the target name is not
    /// UTF-16.
    pub fn read(blob: &[u8]) -> Result<Option<Self>> {
        // RespType and HiRespType are both 1 in the only version there is.
        if !Self::is_blob(blob) {
            return Ok(None);
        }

        let mut ticks = [0u8; 8];
        ticks.copy_from_slice(&blob[TIMESTAMP..TIMESTAMP + 8]);
        let mut read = Self {
            timestamp: u64::from_le_bytes(ticks),
            ..Self::default()
        };
        let mut rest = &blob[FIXED..];

        for _ in 0..MOST_PAIRS {
            let Some((id, value, after)) = pair(rest)? else {
                break;
            };

            match id {
                END_OF_LIST => break,
                TARGET_NAME => {
                    let name = codec::utf16::decode(value).map_err(|error| {
                        NtlmError::new(format!("the NTLMv2 response's target name: {error}"))
                    })?;
                    read.target = Some(name).filter(|name| !name.is_empty());
                }
                FLAGS => {
                    let flags = value.get(..4).map_or(0, |quad| {
                        u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
                    });
                    read.untrusted = flags & UNTRUSTED_SOURCE != 0;
                    read.integrity = flags & HAS_INTEGRITY != 0;
                }
                CHANNEL_BINDINGS => {
                    read.channel = <[u8; 16]>::try_from(value)
                        .ok()
                        .filter(|hash| hash != &[0u8; 16]);
                }
                _ => {}
            }

            rest = after;
        }

        Ok(Some(read))
    }

    /// Whether `blob` opens as an `NTLMv2` client challenge does: long
    /// enough for its fixed part, and both its types 1.
    #[must_use]
    pub fn is_blob(blob: &[u8]) -> bool {
        blob.len() >= FIXED && blob[..2] == [1, 1]
    }

    /// The blob a client writes, with `client_nonce` as its challenge: the
    /// flags where either is set, the target and the channel where there is
    /// one, and the end of the list.
    #[must_use]
    pub fn to_blob(&self, client_nonce: [u8; 8]) -> Vec<u8> {
        let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&self.timestamp.to_le_bytes());
        blob.extend_from_slice(&client_nonce);
        blob.extend_from_slice(&[0; 4]);

        let mut push = |id: u16, value: &[u8]| {
            let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
            blob.extend_from_slice(&id.to_le_bytes());
            blob.extend_from_slice(&length.to_le_bytes());
            blob.extend_from_slice(&value[..usize::from(length)]);
        };

        let flags = if self.integrity { HAS_INTEGRITY } else { 0 }
            | if self.untrusted { UNTRUSTED_SOURCE } else { 0 };
        if flags != 0 {
            push(FLAGS, &flags.to_le_bytes());
        }
        if let Some(target) = &self.target {
            push(TARGET_NAME, &codec::utf16::encode(target));
        }
        if let Some(channel) = &self.channel {
            push(CHANNEL_BINDINGS, channel);
        }
        push(END_OF_LIST, &[]);
        blob
    }

    /// The target a server may hold the client to: the name it wrote, unless
    /// it flagged the name as taken from an untrusted source, which
    /// [MS-NLMP] 3.2.5.1.2 has a server treat as no name.
    #[must_use]
    pub fn supplied_target(&self) -> Option<&str> {
        if self.untrusted {
            None
        } else {
            self.target.as_deref()
        }
    }

    /// When the response was made, in seconds since the Unix epoch. Zero
    /// where the client wrote a time before it.
    #[must_use]
    pub const fn made_at(&self) -> u64 {
        (self.timestamp / TICKS_PER_SECOND).saturating_sub(EPOCH_GAP)
    }
}

/// One attribute and value pair, and what follows it. `None` where nothing
/// is left to read.
fn pair(bytes: &[u8]) -> Result<Option<Pair<'_>>> {
    let Some(header) = bytes.get(..4) else {
        return Ok(None);
    };
    let id = u16::from_le_bytes([header[0], header[1]]);
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let Some(value) = bytes.get(4..4 + length) else {
        return Err(NtlmError::new(format!(
            "the NTLMv2 response's attribute {id:#06x} runs past the end of the response"
        )));
    };

    Ok(Some((id, value, &bytes[4 + length..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    const THEN: u64 = 1_800_000_000;
    const NONCE: [u8; 8] = [0x22; 8];

    fn made(target: Option<&str>, untrusted: bool, integrity: bool) -> ClientChallenge {
        ClientChallenge {
            target: target.map(str::to_string),
            untrusted,
            integrity,
            ..ClientChallenge::at(THEN)
        }
    }

    #[test]
    fn the_target_and_the_time_are_written_and_read_back() {
        let sent = made(Some("HTTP/Xmip.Example"), false, true);
        let read = ClientChallenge::read(&sent.to_blob(NONCE))
            .expect("read")
            .expect("NTLMv2");
        assert_eq!(read, sent);
        assert_eq!(read.supplied_target(), Some("HTTP/Xmip.Example"));
        assert_eq!(read.made_at(), THEN);
    }

    #[test]
    fn a_name_from_an_untrusted_source_is_read_and_is_no_supplied_target() {
        let blob = made(Some("HTTP/xmip.example"), true, true).to_blob(NONCE);

        let read = ClientChallenge::read(&blob).expect("read").expect("NTLMv2");
        assert!(read.untrusted);
        assert_eq!(read.target.as_deref(), Some("HTTP/xmip.example"));
        assert_eq!(read.supplied_target(), None);
    }

    #[test]
    fn the_channel_is_read_and_a_zero_channel_is_none() {
        let bound = ClientChallenge {
            channel: Some([0xC4; 16]),
            ..made(None, false, true)
        };
        let read = ClientChallenge::read(&bound.to_blob(NONCE))
            .expect("read")
            .expect("NTLMv2");
        assert_eq!(read.channel, Some([0xC4; 16]));

        let unbound = ClientChallenge {
            channel: Some([0; 16]),
            ..made(None, false, false)
        };
        let read = ClientChallenge::read(&unbound.to_blob(NONCE))
            .expect("read")
            .expect("NTLMv2");
        assert!(!read.integrity);
        assert_eq!(read.channel, None);
    }

    #[test]
    fn an_ntlmv1_response_is_no_client_challenge_and_a_list_may_name_no_target() {
        assert!(ClientChallenge::read(&[0x5A; 8]).expect("read").is_none());
        assert!(ClientChallenge::read(&[2u8; 40]).expect("read").is_none());

        let nameless = made(None, false, false).to_blob(NONCE);
        let read = ClientChallenge::read(&nameless)
            .expect("read")
            .expect("NTLMv2");
        assert_eq!(read.target, None);
    }

    #[test]
    fn a_pair_that_runs_past_the_blob_or_a_name_not_utf_16_is_an_error_naming_it() {
        let mut broken = made(None, false, false).to_blob(NONCE);
        broken.truncate(FIXED);
        broken.extend_from_slice(&[0x09, 0x00, 0xFF, 0x00, b'H', 0]);

        let failure = ClientChallenge::read(&broken).expect_err("truncated");
        assert!(failure.message.contains("0x0009"), "{failure}");
        assert!(failure.message.contains("runs past"), "{failure}");

        broken.truncate(FIXED);
        broken.extend_from_slice(&[0x09, 0x00, 0x01, 0x00, b'H']);
        let failure = ClientChallenge::read(&broken).expect_err("odd");
        assert!(failure.message.contains("target name"), "{failure}");
    }
}
