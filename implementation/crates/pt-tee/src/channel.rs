//! Secure channel (SPEC section 7).
//!
//! `shared = X25519(client_eph, enclave_pk)`;
//! `k_req  = HKDF-SHA256(salt = client_pk || enclave_pk, ikm = shared, info = "platypus-tee/v1/req")`;
//! `k_resp = HKDF-SHA256(same, info = "platypus-tee/v1/resp")`;
//! ChaCha20-Poly1305 with a fresh random 12-byte nonce per message and the
//! direction's HKDF info as associated data.
//!
//! The client seals requests under `k_req` and opens responses under
//! `k_resp`; the enclave does the opposite. A message sealed in one direction
//! never opens in the other.
//!
//! Before sealing, a plaintext is framed as `u32 BE length || plaintext || zero
//! padding` up to a multiple of [`PAD_BLOCK_LEN`]. CBOR encodes integers in 1
//! to 9 bytes, so an unpadded `ProveJob` ciphertext would be a few bytes longer
//! for a large balance or amount than for a small one, and the host (which
//! sees and logs frame lengths) could bucket delegated payments by magnitude.
//! With padding every message of one shape seals to the same length.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{HKDF_INFO_REQ, HKDF_INFO_RESP};

/// X25519 public key length.
pub const PK_LEN: usize = 32;
/// ChaCha20-Poly1305 key length.
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag length (ciphertext = padded plaintext + TAG_LEN).
pub const TAG_LEN: usize = 16;
/// Padded plaintexts are a multiple of this length. A `ProveJob` is well under
/// 2 KiB for every config and role, so every job seals to exactly one block
/// whatever its `u64` fields hold; a `ProveResult` does too.
pub const PAD_BLOCK_LEN: usize = 2048;
/// Length prefix inside the padded plaintext.
const PAD_LEN_PREFIX: usize = 4;

/// Channel errors. Messages never include key or plaintext material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    /// The peer public key is a low-order point: the shared secret is zero.
    #[error("X25519 shared secret is non-contributory (low-order peer key)")]
    NonContributory,
    /// HKDF expand failed (cannot happen for 32-byte outputs, kept explicit).
    #[error("HKDF expansion failed: {0}")]
    Kdf(String),
    /// AEAD encryption failed.
    #[error("AEAD seal failed")]
    Seal,
    /// AEAD decryption failed: wrong key, wrong nonce or tampered ciphertext.
    #[error("AEAD open failed: key, nonce or ciphertext mismatch")]
    Open,
    /// The decrypted plaintext is not `u32 BE length || body || zero padding`
    /// of a whole number of blocks.
    #[error("padded plaintext is malformed")]
    Padding,
    /// The plaintext is too long to carry a `u32` length prefix.
    #[error("plaintext of {len} bytes is too long to seal")]
    TooLong { len: usize },
}

/// Sealed length of a `plaintext_len`-byte message: padded blocks plus the tag.
pub const fn sealed_len(plaintext_len: usize) -> usize {
    (PAD_LEN_PREFIX + plaintext_len).div_ceil(PAD_BLOCK_LEN) * PAD_BLOCK_LEN + TAG_LEN
}

/// `u32 BE length || plaintext || zeros` up to a multiple of [`PAD_BLOCK_LEN`].
fn pad(plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let len = u32::try_from(plaintext.len()).map_err(|_| ChannelError::TooLong {
        len: plaintext.len(),
    })?;
    let total = sealed_len(plaintext.len()) - TAG_LEN;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(total, 0);
    Ok(out)
}

/// Inverse of [`pad`]; rejects anything that is not a whole number of blocks,
/// a length beyond the buffer or non-zero padding bytes.
fn unpad(padded: &[u8]) -> Result<Vec<u8>, ChannelError> {
    if padded.len() < PAD_LEN_PREFIX || !padded.len().is_multiple_of(PAD_BLOCK_LEN) {
        return Err(ChannelError::Padding);
    }
    let mut prefix = [0u8; PAD_LEN_PREFIX];
    prefix.copy_from_slice(&padded[..PAD_LEN_PREFIX]);
    let len = u32::from_be_bytes(prefix) as usize;
    let rest = &padded[PAD_LEN_PREFIX..];
    let (body, padding) = rest.split_at_checked(len).ok_or(ChannelError::Padding)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(ChannelError::Padding);
    }
    Ok(body.to_vec())
}

/// A sealed message: random nonce plus ciphertext with its Poly1305 tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Direction-separated session keys derived from one X25519 agreement.
#[derive(Clone)]
pub struct SessionKeys {
    k_req: [u8; KEY_LEN],
    k_resp: [u8; KEY_LEN],
}

impl SessionKeys {
    /// Derives `(k_req, k_resp)` from the raw shared secret and both public keys.
    ///
    /// `shared` must already be checked for contributory behaviour by the caller
    /// when it comes from X25519 (see [`SessionKeys::from_x25519`]).
    pub fn derive(
        shared: &[u8; PK_LEN],
        client_pk: &[u8; PK_LEN],
        enclave_pk: &[u8; PK_LEN],
    ) -> Result<Self, ChannelError> {
        let mut salt = [0u8; 2 * PK_LEN];
        salt[..PK_LEN].copy_from_slice(client_pk);
        salt[PK_LEN..].copy_from_slice(enclave_pk);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
        let mut k_req = [0u8; KEY_LEN];
        let mut k_resp = [0u8; KEY_LEN];
        hk.expand(HKDF_INFO_REQ, &mut k_req)
            .map_err(|e| ChannelError::Kdf(e.to_string()))?;
        hk.expand(HKDF_INFO_RESP, &mut k_resp)
            .map_err(|e| ChannelError::Kdf(e.to_string()))?;
        Ok(Self { k_req, k_resp })
    }

    fn from_x25519(
        shared: SharedSecret,
        client_pk: &[u8; PK_LEN],
        enclave_pk: &[u8; PK_LEN],
    ) -> Result<Self, ChannelError> {
        if !shared.was_contributory() {
            return Err(ChannelError::NonContributory);
        }
        Self::derive(shared.as_bytes(), client_pk, enclave_pk)
    }

    /// Request key (client to enclave). Exposed for tests and key-check tooling.
    pub fn k_req(&self) -> &[u8; KEY_LEN] {
        &self.k_req
    }

    /// Response key (enclave to client).
    pub fn k_resp(&self) -> &[u8; KEY_LEN] {
        &self.k_resp
    }
}

/// Seals `pad(plaintext)` under `key` with the direction's info string as
/// associated data, so a request can never be presented as a response even if
/// the keys were ever equal.
fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, ChannelError> {
    let padded = pad(plaintext)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: &padded, aad })
        .map_err(|_| ChannelError::Seal)?;
    Ok(Sealed { nonce, ciphertext })
}

fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>, ChannelError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let padded = cipher
        .decrypt(
            &Nonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| ChannelError::Open)?;
    unpad(&padded)
}

/// The enclave's long-lived (per boot, never persisted) X25519 key pair.
pub struct EnclaveKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EnclaveKeypair {
    /// Fresh random key pair.
    pub fn generate() -> Self {
        let mut bytes = [0u8; PK_LEN];
        OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Public key bytes, to be bound into the attestation document.
    pub fn public_key(&self) -> [u8; PK_LEN] {
        self.public.to_bytes()
    }

    /// Derives the enclave side of a session with `client_pk`.
    pub fn accept(&self, client_pk: &[u8; PK_LEN]) -> Result<EnclaveChannel, ChannelError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*client_pk));
        let keys = SessionKeys::from_x25519(shared, client_pk, &self.public.to_bytes())?;
        Ok(EnclaveChannel { keys })
    }
}

/// Enclave side of a session: opens requests, seals responses.
pub struct EnclaveChannel {
    keys: SessionKeys,
}

impl EnclaveChannel {
    /// Decrypts a client request.
    pub fn open_request(&self, sealed: &Sealed) -> Result<Vec<u8>, ChannelError> {
        open(&self.keys.k_req, HKDF_INFO_REQ, sealed)
    }

    /// Encrypts a response for the client.
    pub fn seal_response(&self, plaintext: &[u8]) -> Result<Sealed, ChannelError> {
        seal(&self.keys.k_resp, HKDF_INFO_RESP, plaintext)
    }
}

/// Client side of a session: seals requests, opens responses.
pub struct ClientChannel {
    client_pk: [u8; PK_LEN],
    keys: SessionKeys,
}

impl ClientChannel {
    /// Generates an ephemeral X25519 key and derives the session with the
    /// (attested) enclave public key. The ephemeral secret is dropped here.
    pub fn connect(enclave_pk: &[u8; PK_LEN]) -> Result<Self, ChannelError> {
        let mut bytes = [0u8; PK_LEN];
        OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let client_pk = PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(*enclave_pk));
        let keys = SessionKeys::from_x25519(shared, &client_pk, enclave_pk)?;
        Ok(Self { client_pk, keys })
    }

    /// The ephemeral public key to send alongside the sealed request.
    pub fn client_pk(&self) -> [u8; PK_LEN] {
        self.client_pk
    }

    /// Encrypts a request for the enclave.
    pub fn seal_request(&self, plaintext: &[u8]) -> Result<Sealed, ChannelError> {
        seal(&self.keys.k_req, HKDF_INFO_REQ, plaintext)
    }

    /// Decrypts an enclave response.
    pub fn open_response(&self, sealed: &Sealed) -> Result<Vec<u8>, ChannelError> {
        open(&self.keys.k_resp, HKDF_INFO_RESP, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (EnclaveKeypair, ClientChannel, EnclaveChannel) {
        let enclave = EnclaveKeypair::generate();
        let client = ClientChannel::connect(&enclave.public_key()).unwrap();
        let server = enclave.accept(&client.client_pk()).unwrap();
        (enclave, client, server)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (_e, client, server) = session();
        let req = client.seal_request(b"prove job").unwrap();
        assert_eq!(req.ciphertext.len(), PAD_BLOCK_LEN + TAG_LEN);
        assert_eq!(req.ciphertext.len(), sealed_len(b"prove job".len()));
        assert_eq!(server.open_request(&req).unwrap(), b"prove job");
        let resp = server.seal_response(b"proof").unwrap();
        assert_eq!(client.open_response(&resp).unwrap(), b"proof");
        // Empty plaintexts are fine too.
        let empty = client.seal_request(b"").unwrap();
        assert_eq!(server.open_request(&empty).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn tampering_is_detected() {
        let (_e, client, server) = session();
        let sealed = client.seal_request(b"prove job").unwrap();
        for i in 0..sealed.ciphertext.len() {
            let mut bad = sealed.clone();
            bad.ciphertext[i] ^= 0x01;
            assert_eq!(
                server.open_request(&bad),
                Err(ChannelError::Open),
                "byte {i}"
            );
        }
        let mut bad_nonce = sealed.clone();
        bad_nonce.nonce[0] ^= 0x80;
        assert_eq!(server.open_request(&bad_nonce), Err(ChannelError::Open));
        let mut truncated = sealed.clone();
        truncated.ciphertext.pop();
        assert_eq!(server.open_request(&truncated), Err(ChannelError::Open));
        let mut extended = sealed;
        extended.ciphertext.push(0);
        assert_eq!(server.open_request(&extended), Err(ChannelError::Open));
    }

    /// M-1: the ciphertext length depends only on the size class of the
    /// plaintext, never on its exact length.
    #[test]
    fn ciphertext_length_hides_the_plaintext_length() {
        let (_e, client, server) = session();
        let one_block = PAD_BLOCK_LEN - PAD_LEN_PREFIX;
        let lengths = [0usize, 1, 9, 877, 901, 1300, one_block];
        let sealed: Vec<Sealed> = lengths
            .iter()
            .map(|n| client.seal_request(&vec![0xA5u8; *n]).unwrap())
            .collect();
        for (n, s) in lengths.iter().zip(&sealed) {
            assert_eq!(s.ciphertext.len(), PAD_BLOCK_LEN + TAG_LEN, "len {n}");
            assert_eq!(server.open_request(s).unwrap(), vec![0xA5u8; *n]);
        }
        // One byte more spills into a second block, still a fixed size.
        let two = client.seal_request(&vec![1u8; one_block + 1]).unwrap();
        assert_eq!(two.ciphertext.len(), 2 * PAD_BLOCK_LEN + TAG_LEN);
        assert_eq!(server.open_request(&two).unwrap(), vec![1u8; one_block + 1]);
        let resp = server.seal_response(b"proof").unwrap();
        assert_eq!(resp.ciphertext.len(), PAD_BLOCK_LEN + TAG_LEN);
    }

    #[test]
    fn padding_is_strict() {
        assert_eq!(unpad(&pad(b"abc").unwrap()).unwrap(), b"abc");
        assert_eq!(unpad(&pad(b"").unwrap()).unwrap(), b"");
        // Not a whole number of blocks.
        assert_eq!(unpad(&[0u8; 7]), Err(ChannelError::Padding));
        assert_eq!(unpad(&[0u8; PAD_BLOCK_LEN + 1]), Err(ChannelError::Padding));
        // Length prefix beyond the buffer.
        let mut too_long = pad(b"abc").unwrap();
        too_long[..4].copy_from_slice(&(PAD_BLOCK_LEN as u32).to_be_bytes());
        assert_eq!(unpad(&too_long), Err(ChannelError::Padding));
        // Non-zero padding byte.
        let mut dirty = pad(b"abc").unwrap();
        dirty[PAD_LEN_PREFIX + 3] = 1;
        assert_eq!(unpad(&dirty), Err(ChannelError::Padding));
        assert!(unpad(&[]).is_err());
    }

    /// L-6: the direction is bound as associated data, not only by the key.
    #[test]
    fn associated_data_binds_the_direction() {
        let (_e, client, server) = session();
        let req = client.seal_request(b"x").unwrap();
        // Same key, wrong AAD: a request re-labelled as a response does not open.
        assert_eq!(
            open(&client.keys.k_req, HKDF_INFO_RESP, &req),
            Err(ChannelError::Open)
        );
        assert_eq!(open(&server.keys.k_req, HKDF_INFO_REQ, &req).unwrap(), b"x");
    }

    #[test]
    fn wrong_key_fails() {
        let (_e, client, _server) = session();
        let other = EnclaveKeypair::generate();
        let impostor = other.accept(&client.client_pk()).unwrap();
        let sealed = client.seal_request(b"secret witness").unwrap();
        assert_eq!(impostor.open_request(&sealed), Err(ChannelError::Open));

        // A second client on the same enclave cannot read the first one's traffic.
        let (enclave, client_a, server_a) = session();
        let client_b = ClientChannel::connect(&enclave.public_key()).unwrap();
        let server_b = enclave.accept(&client_b.client_pk()).unwrap();
        let a_req = client_a.seal_request(b"a").unwrap();
        assert_eq!(server_b.open_request(&a_req), Err(ChannelError::Open));
        assert_eq!(server_a.open_request(&a_req).unwrap(), b"a");
    }

    #[test]
    fn directions_use_distinct_keys() {
        let (_e, client, server) = session();
        // A request opened as a response must fail: k_req != k_resp.
        let req = client.seal_request(b"x").unwrap();
        assert_eq!(client.open_response(&req), Err(ChannelError::Open));
        let resp = server.seal_response(b"y").unwrap();
        assert_eq!(server.open_request(&resp), Err(ChannelError::Open));
        assert_ne!(client.keys.k_req, client.keys.k_resp);
        assert_eq!(client.keys.k_req, server.keys.k_req);
        assert_eq!(client.keys.k_resp, server.keys.k_resp);
    }

    #[test]
    fn nonces_are_fresh_per_message() {
        let (_e, client, _s) = session();
        let a = client.seal_request(b"same").unwrap();
        let b = client.seal_request(b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn low_order_enclave_key_is_rejected() {
        let zero = [0u8; PK_LEN];
        assert_eq!(
            ClientChannel::connect(&zero).err(),
            Some(ChannelError::NonContributory)
        );
        let enclave = EnclaveKeypair::generate();
        assert_eq!(
            enclave.accept(&zero).err(),
            Some(ChannelError::NonContributory)
        );
        let mut one = [0u8; PK_LEN];
        one[0] = 1;
        assert_eq!(
            ClientChannel::connect(&one).err(),
            Some(ChannelError::NonContributory)
        );
    }

    /// Known answer: RFC 7748 section 6.1 X25519 vectors feed the KDF; the
    /// expected keys were computed independently with
    /// `openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:<shared>
    ///  -kdfopt hexsalt:<alice_pk||bob_pk> -kdfopt info:<info> HKDF`.
    #[test]
    fn hkdf_known_answer() {
        let alice_sk: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_sk: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let alice = StaticSecret::from(alice_sk);
        let bob = StaticSecret::from(bob_sk);
        let alice_pk = PublicKey::from(&alice).to_bytes();
        let bob_pk = PublicKey::from(&bob).to_bytes();
        assert_eq!(
            hex::encode(alice_pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex::encode(bob_pk),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let shared = alice.diffie_hellman(&PublicKey::from(bob_pk));
        assert_eq!(
            hex::encode(shared.as_bytes()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        // Alice plays the client, Bob the enclave.
        let keys = SessionKeys::from_x25519(shared, &alice_pk, &bob_pk).unwrap();
        assert_eq!(
            hex::encode(keys.k_req()),
            "3d48f924e81bba676a14a0e3870b682e4e3bd57fe1e2c11b650922df00981b26"
        );
        assert_eq!(
            hex::encode(keys.k_resp()),
            "388f483d6b3009ff711760b86acdab31bfe06f85452e0f4b7f44b568664ca8de"
        );
        // Salt order matters: swapping the public keys changes both keys.
        let shared_again = alice.diffie_hellman(&PublicKey::from(bob_pk));
        let swapped = SessionKeys::derive(shared_again.as_bytes(), &bob_pk, &alice_pk).unwrap();
        assert_ne!(swapped.k_req(), keys.k_req());
        assert_ne!(swapped.k_resp(), keys.k_resp());
    }
}
