//! The `NTLMv2` response ([MS-NLMP] section 3.3.2): what a client computes
//! from a password and the server's challenge, and what a server that holds
//! the password, or its NT hash, computes again to prove it.
//!
//! ```text
//! NT hash        MD4(UTF-16LE(password))                       NTOWFv1
//! response key   HMAC-MD5(NT hash, UTF-16LE(UPPER(user) + domain))   NTOWFv2
//! NTProofStr     HMAC-MD5(response key, server challenge + blob)
//! NT response    NTProofStr + blob
//! ```
//!
//! Written once, here, beneath both of its callers: the `ntlm` gate, which
//! verifies a response against the hash a node holds, and the SMB
//! transport, whose client answers a challenge with the password its
//! Location's secret holds and whose far end checks it. Until 2026-11-25
//! the gate held the response key and the keyed hash, and nothing computed
//! a response.

use md4::Md4;
use md5::{Digest, Md5};

/// The NT hash of `password`: MD4 over its UTF-16LE form.
#[must_use]
pub fn nt_hash(password: &str) -> [u8; 16] {
    Md4::digest(codec::utf16::encode(password)).into()
}

/// HMAC-MD5 under `key` over `parts` in order, MS-NLMP's one keyed hash: the
/// estate's HMAC construction (`codec::digest::hmac_by`) over MD5.
#[must_use]
pub fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    codec::digest::hmac_by(|data| Md5::digest(data).into(), key, &parts.concat())
}

/// The response key, `NTOWFv2`: HMAC-MD5 under the NT `hash` over the
/// uppercased `user` then the `domain` as the client spells it, UTF-16LE.
#[must_use]
pub fn response_key(hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let user = codec::utf16::encode(&user.to_uppercase());
    hmac_md5(hash, &[&user, &codec::utf16::encode(domain)])
}

/// The `NTProofStr` under the response `key`: HMAC-MD5 over the server's
/// eight-byte `challenge` then the client's `blob`.
#[must_use]
pub fn proof(key: &[u8; 16], challenge: &[u8; 8], blob: &[u8]) -> [u8; 16] {
    hmac_md5(key, &[challenge, blob])
}

/// The `NtChallengeResponse` a client sends: the [`proof`] under `key`,
/// then the `blob` it covers.
#[must_use]
pub fn nt_response(key: &[u8; 16], challenge: &[u8; 8], blob: &[u8]) -> Vec<u8> {
    let mut response = proof(key, challenge, blob).to_vec();
    response.extend_from_slice(blob);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nt_hash_and_the_response_key_of_a_known_password_are_the_published_ones() {
        // MS-NLMP 4.2.1: the password "Password" hashes to this.
        assert_eq!(
            codec::hex::encode(&nt_hash("Password")),
            "a4f49c406510bdcab6824ee7c30fd852"
        );
        // MS-NLMP 4.2.4.1.1: NTOWFv2 for User, Domain, Password.
        assert_eq!(
            codec::hex::encode(&response_key(&nt_hash("Password"), "User", "Domain")),
            "0c868a403bfd7a93a3001ef22ef02e3f"
        );
    }

    #[test]
    fn a_response_is_its_proof_over_the_challenge_then_its_blob() {
        let key = response_key(&nt_hash("Password"), "User", "Domain");
        let blob = [0x22; 28];
        let response = nt_response(&key, &[1; 8], &blob);
        assert_eq!(response[..16], proof(&key, &[1; 8], &blob));
        assert_eq!(response[16..], blob);
        assert_ne!(
            proof(&key, &[2; 8], &blob),
            proof(&key, &[1; 8], &blob),
            "another challenge, another proof"
        );
    }
}
