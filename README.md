# xmip-core-library-ntlm

The NTLM message layout of [MS-NLMP] section 2.2, read and written: the three
messages of one handshake and the `NTLMv2` client challenge a response
carries; and the `NTLMv2` response itself, section 3.3.2. What a message
proves stays with the gate that proves it.

| Item | What it is |
| --- | --- |
| `MessageType` | Which of the three a message says it is, after the `NTLMSSP` signature |
| `Negotiate` | The client's NEGOTIATE (type 1): its flags, and a domain and workstation it may name |
| `Challenge` | The server's CHALLENGE (type 2): its flags, its eight-byte nonce, its name and target information |
| `Authenticate` | The client's AUTHENTICATE (type 3): its names, both responses, the session key, the flags, and the MIC at offset 72 |
| `ClientChallenge` | The blob of an `NTLMv2` response: when it was made, the target it names and whether that came from an untrusted source, whether a MIC was written, and the channel it is bound to |
| `flags` | The negotiate flags the estate reads or writes |
| `response` | The `NTLMv2` response: the NT hash (MD4), the response key `NTOWFv2`, the `NTProofStr` and the NT response, each HMAC-MD5 the estate's (`codec::digest::hmac_by`) |

Names are UTF-16 through `xmip-core-library-codec` where Unicode was
negotiated, else one byte a character.

`identify/ntlm` reads the claim out of an AUTHENTICATE message and
`authenticate/ntlm` verifies its response and its MIC, each through this
crate; the SMB transport writes and reads all three messages of its session
setup with it. Until 2026-09-24 the identity capability held the one reader
the two gates shared, the second gate read the CHALLENGE's nonce and the MIC
by offset, and the SMB transport carried a counted-field simplification of
its own that no other NTLM speaker would have understood (ADR-0050,
amendment 2026-09-24).

The `NTLMv2` response is computed once, in `response`: `authenticate/ntlm`
computes it again from the hash a node holds to verify one, and the SMB
transport's client answers a challenge with the password its Location's
secret holds, its far end checking it (ADR-0019, amendment 2026-11-25).
Until 2026-11-25 the gate held the response key and the keyed hash, and
nothing computed a response.

`architecture.toml` carries the maturity.
