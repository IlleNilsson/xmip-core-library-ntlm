//! The negotiate flags ([MS-NLMP] 2.2.2.5) this estate reads or writes. A
//! message carries them as one little-endian `u32`; the rest of the
//! thirty-two are carried as they came and named by no one here.

/// Names are UTF-16: `NTLMSSP_NEGOTIATE_UNICODE`, bit A.
pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// Names are the OEM character set: `NTLM_NEGOTIATE_OEM`, bit B.
pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
/// The server is asked to name itself: `NTLMSSP_REQUEST_TARGET`, bit C.
pub const REQUEST_TARGET: u32 = 0x0000_0004;
/// NTLM session security: `NTLMSSP_NEGOTIATE_NTLM`, bit H.
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// Extended session security: `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`,
/// bit P.
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// The CHALLENGE carries target information:
/// `NTLMSSP_NEGOTIATE_TARGET_INFO`, bit S.
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// A 128-bit session key: `NTLMSSP_NEGOTIATE_128`, bit U.
pub const NEGOTIATE_128: u32 = 0x2000_0000;
/// The client sends an encrypted session key: `NTLMSSP_NEGOTIATE_KEY_EXCH`,
/// bit V.
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
