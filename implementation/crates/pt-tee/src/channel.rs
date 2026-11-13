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
