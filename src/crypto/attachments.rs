//! Chunked AEAD for attachment payloads.
//!
//! A file is split into chunks on the client. Each chunk is sealed with
//! ChaCha20-Poly1305 under a per-file key. The nonce is derived from a
//! per-file base plus the chunk index, so every chunk under one key uses a
//! different nonce without the caller having to track state.
//!
//! The size of a sealed chunk is the plaintext size plus the 16-byte Poly1305
//! tag. The server records that sealed size; the recipient subtracts the tag
//! length when reconstructing the plaintext.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;

use crate::error::{Error, Result};

/// Length of the Poly1305 authentication tag appended to every sealed chunk.
pub const TAG_LEN: usize = 16;

/// Length of the symmetric key.
pub const KEY_LEN: usize = 32;

/// Length of the base nonce shared by all chunks of one file.
pub const BASE_NONCE_LEN: usize = 4;

/// Generates a fresh key and base nonce.
pub fn new_key_and_base() -> ([u8; KEY_LEN], [u8; BASE_NONCE_LEN]) {
    let mut rng = rand::rng();
    let mut key = [0u8; KEY_LEN];
    let mut base = [0u8; BASE_NONCE_LEN];
    rng.fill(&mut key);
    rng.fill(&mut base);
    (key, base)
}

/// Builds the 12-byte nonce for a chunk: 4-byte base followed by the chunk
/// index as a big-endian u64. Two chunks of the same file can never collide,
/// and two different files have different bases with overwhelming probability.
fn nonce_for(base: &[u8; BASE_NONCE_LEN], chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(base);
    nonce[4..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

/// Seals one chunk. The ciphertext is the plaintext followed by the tag.
pub fn seal_chunk(
    key: &[u8; KEY_LEN],
    base: &[u8; BASE_NONCE_LEN],
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = nonce_for(base, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // The chunk index is bound into the AEAD as associated data, so a chunk
    // swapped from one position to another fails authentication instead of
    // silently decrypting into the wrong offset.
    let aad = chunk_index.to_be_bytes();
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| Error::Internal(format!("chunk seal failed: {e}")))
}

/// Opens one chunk. The ciphertext is the sealed chunk as stored.
pub fn open_chunk(
    key: &[u8; KEY_LEN],
    base: &[u8; BASE_NONCE_LEN],
    chunk_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::InvalidPayload(format!(
            "sealed chunk is {} bytes, at least {} expected",
            ciphertext.len(),
            TAG_LEN
        )));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = nonce_for(base, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = chunk_index.to_be_bytes();

    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| Error::InvalidPayload("chunk failed authentication".into()))
}

/// Decodes a hex key and base nonce from the JSON carried by an
/// attachment-key envelope.
pub fn decode_key_and_base(
    key_hex: &str,
    base_hex: &str,
) -> Result<([u8; KEY_LEN], [u8; BASE_NONCE_LEN])> {
    let key_bytes = hex::decode(key_hex)
        .map_err(|e| Error::InvalidPayload(format!("key hex: {e}")))?;
    if key_bytes.len() != KEY_LEN {
        return Err(Error::InvalidPayload(format!(
            "key is {} bytes, expected {}",
            key_bytes.len(),
            KEY_LEN
        )));
    }

    let base_bytes = hex::decode(base_hex)
        .map_err(|e| Error::InvalidPayload(format!("base nonce hex: {e}")))?;
    if base_bytes.len() != BASE_NONCE_LEN {
        return Err(Error::InvalidPayload(format!(
            "base nonce is {} bytes, expected {}",
            base_bytes.len(),
            BASE_NONCE_LEN
        )));
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&key_bytes);
    let mut base = [0u8; BASE_NONCE_LEN];
    base.copy_from_slice(&base_bytes);
    Ok((key, base))
}
