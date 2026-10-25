//! Browser bindings for the core attachment AEAD implementation.

use friendshub_core::crypto::attachments;
use serde_json::json;
use wasm_bindgen::prelude::*;

fn decode_key_and_base(
    key_hex: &str,
    base_nonce_hex: &str,
) -> Result<([u8; 32], [u8; 4]), JsValue> {
    attachments::decode_key_and_base(key_hex, base_nonce_hex)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Generates the attachment key and base nonce as JSON, preserving the
/// existing WEB bridge shape `{ key_hex, base_nonce_hex }`.
#[wasm_bindgen]
pub fn generate_attachment_key() -> Result<String, JsValue> {
    let (key, base_nonce) = attachments::new_key_and_base();
    serde_json::to_string(&json!({
        "key_hex": hex::encode(key),
        "base_nonce_hex": hex::encode(base_nonce),
    }))
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Seals one file chunk with the shared core ChaCha20-Poly1305 implementation.
#[wasm_bindgen]
pub fn seal_chunk(
    key_hex: &str,
    base_nonce_hex: &str,
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (key, base_nonce) = decode_key_and_base(key_hex, base_nonce_hex)?;
    attachments::seal_chunk(&key, &base_nonce, chunk_index, plaintext)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Opens and authenticates one stored file chunk.
#[wasm_bindgen]
pub fn open_chunk(
    key_hex: &str,
    base_nonce_hex: &str,
    chunk_index: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (key, base_nonce) = decode_key_and_base(key_hex, base_nonce_hex)?;
    attachments::open_chunk(&key, &base_nonce, chunk_index, sealed)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_roundtrips_chunks_and_rejects_wrong_indices() {
        let generated: serde_json::Value =
            serde_json::from_str(&generate_attachment_key().unwrap()).unwrap();
        let key = generated["key_hex"].as_str().unwrap();
        let base = generated["base_nonce_hex"].as_str().unwrap();
        let sealed = seal_chunk(key, base, 5, b"attachment chunk").unwrap();
        assert_eq!(
            open_chunk(key, base, 5, &sealed).unwrap(),
            b"attachment chunk"
        );
        let (key, base) = attachments::decode_key_and_base(key, base).unwrap();
        assert!(attachments::open_chunk(&key, &base, 6, &sealed).is_err());
    }

    #[test]
    fn binding_rejects_invalid_key_lengths() {
        assert!(attachments::decode_key_and_base("00", "00000000").is_err());
    }
}
