//! Browser-compatible encrypted history framing and in-memory reassembly.
//!
//! Completed objects remain available for redelivery until the caller commits
//! them locally and acknowledges them. Item-specific validation and persistence
//! belong to the caller; a deterministic rejection should call `discard`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const HISTORY_FRAGMENT_BYTES: usize = 24 * 1024;
pub const HISTORY_MAX_ITEM_BYTES: usize = 2 * 1024 * 1024;
pub const HISTORY_MAX_PART_COUNT: usize = HISTORY_MAX_ITEM_BYTES.div_ceil(HISTORY_FRAGMENT_BYTES);
pub const HISTORY_MAX_ASSEMBLIES: usize = 32;
pub const HISTORY_ASSEMBLY_TTL: Duration = Duration::from_secs(10 * 60);

// Browser atob accepts nonzero unused padding bits; the standard Rust decoder
// rejects those by default even though the WEB wire validator accepts them.
const HISTORY_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryItemKind {
    Message,
    Attachment,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryChunk {
    pub kind: String,
    pub version: u8,
    pub transfer_id: String,
    pub conversation_id: String,
    pub item_kind: HistoryItemKind,
    pub item_id: String,
    pub part_index: usize,
    pub part_count: usize,
    pub data: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryProtocolError {
    #[error("invalid history chunk")]
    InvalidChunk,
    #[error("history item exceeds 2 MiB")]
    ItemTooLarge,
    #[error("inconsistent history fragment count")]
    InconsistentFragmentCount,
    #[error("too many incomplete history items")]
    TooManyIncompleteItems,
    #[error("invalid history item")]
    InvalidItem,
    #[error("history item serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_item_id(value: &str) -> bool {
    !value.is_empty() && value.encode_utf16().take(129).count() <= 128
}

fn valid_base64(value: &str) -> bool {
    if value.len() > HISTORY_FRAGMENT_BYTES * 4 / 3 || value.len() % 4 != 0 {
        return false;
    }
    let bytes = value.as_bytes();
    let unpadded = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    bytes[..unpadded]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && matches!(bytes.len() - unpadded, 0..=2)
        && bytes[unpadded..].iter().all(|byte| *byte == b'=')
}

impl HistoryChunk {
    /// Revalidate publicly constructed chunks before accepting any bytes.
    pub fn validate(&self) -> Result<(), HistoryProtocolError> {
        if self.kind != "history_sync"
            || self.version != 1
            || !is_uuid(&self.transfer_id)
            || !is_uuid(&self.conversation_id)
            || !valid_item_id(&self.item_id)
            || !(1..=HISTORY_MAX_PART_COUNT).contains(&self.part_count)
            || self.part_index >= self.part_count
            || !valid_base64(&self.data)
        {
            return Err(HistoryProtocolError::InvalidChunk);
        }
        Ok(())
    }
}

/// Parse the same wire fields as WEB's `parseHistoryChunk`.
///
/// JSON numbers such as `1.0` are accepted as JavaScript safe integers. Unknown
/// fields are ignored, and UUID spelling is preserved for assembly identity.
pub fn parse_history_chunk(value: &Value) -> Option<HistoryChunk> {
    let integer = |field: &str, max: usize| {
        let number = value.get(field)?.as_f64()?;
        (number.is_finite() && number >= 0.0 && number <= max as f64 && number.fract() == 0.0)
            .then_some(number as usize)
    };
    let chunk = HistoryChunk {
        kind: value.get("kind")?.as_str()?.into(),
        version: integer("version", 1)? as u8,
        transfer_id: value.get("transfer_id")?.as_str()?.into(),
        conversation_id: value.get("conversation_id")?.as_str()?.into(),
        item_kind: match value.get("item_kind")?.as_str()? {
            "message" => HistoryItemKind::Message,
            "attachment" => HistoryItemKind::Attachment,
            "complete" => HistoryItemKind::Complete,
            _ => return None,
        },
        item_id: value.get("item_id")?.as_str()?.into(),
        part_index: integer("part_index", HISTORY_MAX_PART_COUNT - 1)?,
        part_count: integer("part_count", HISTORY_MAX_PART_COUNT)?,
        data: value.get("data")?.as_str()?.into(),
    };
    chunk.validate().ok()?;
    Some(chunk)
}

/// Serialize an item into 24 KiB fragments using the WEB wire format.
pub fn history_chunks(
    transfer_id: &str,
    conversation_id: &str,
    item_kind: HistoryItemKind,
    item_id: &str,
    item: &Value,
) -> Result<Vec<HistoryChunk>, HistoryProtocolError> {
    let template = HistoryChunk {
        kind: "history_sync".into(),
        version: 1,
        transfer_id: transfer_id.into(),
        conversation_id: conversation_id.into(),
        item_kind,
        item_id: item_id.into(),
        part_index: 0,
        part_count: 1,
        data: String::new(),
    };
    template.validate()?;
    let bytes = serde_json::to_vec(item)?;
    if bytes.len() > HISTORY_MAX_ITEM_BYTES {
        return Err(HistoryProtocolError::ItemTooLarge);
    }
    let count = bytes.len().div_ceil(HISTORY_FRAGMENT_BYTES).max(1);
    Ok(bytes
        .chunks(HISTORY_FRAGMENT_BYTES)
        .enumerate()
        .map(|(index, part)| HistoryChunk {
            part_index: index,
            part_count: count,
            data: HISTORY_BASE64.encode(part),
            ..template.clone()
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AssemblyKey {
    account_id: String,
    source_device: u32,
    transfer_id: String,
    conversation_id: String,
    item_kind: HistoryItemKind,
    item_id: String,
}

impl AssemblyKey {
    fn new(account_id: &str, source_device: u32, chunk: &HistoryChunk) -> Self {
        Self {
            account_id: account_id.into(),
            source_device,
            transfer_id: chunk.transfer_id.clone(),
            conversation_id: chunk.conversation_id.clone(),
            item_kind: chunk.item_kind,
            item_id: chunk.item_id.clone(),
        }
    }
}

#[derive(Debug)]
struct Assembly {
    parts: Vec<Option<Vec<u8>>>,
    size: usize,
    updated_at: Instant,
}

/// Own one assembler for the client lifecycle, shared across source devices.
/// The bound includes completed items awaiting durable import acknowledgement.
#[derive(Debug, Default)]
pub struct HistoryAssembler {
    assemblies: HashMap<AssemblyKey, Assembly>,
}

impl HistoryAssembler {
    pub fn assemble(
        &mut self,
        account_id: &str,
        source_device: u32,
        chunk: &HistoryChunk,
    ) -> Result<Option<Value>, HistoryProtocolError> {
        self.assemble_at(account_id, source_device, chunk, Instant::now())
    }

    /// Accept a fragment at the supplied monotonic time, expiring stale items.
    /// Duplicate indices keep the first payload and refresh the expiry.
    pub fn assemble_at(
        &mut self,
        account_id: &str,
        source_device: u32,
        chunk: &HistoryChunk,
        now: Instant,
    ) -> Result<Option<Value>, HistoryProtocolError> {
        chunk.validate()?;
        self.assemblies.retain(|_, assembly| {
            now.saturating_duration_since(assembly.updated_at) <= HISTORY_ASSEMBLY_TTL
        });
        let key = AssemblyKey::new(account_id, source_device, chunk);
        if let Some(assembly) = self.assemblies.get(&key) {
            if assembly.parts.len() != chunk.part_count {
                return Err(HistoryProtocolError::InconsistentFragmentCount);
            }
        } else if self.assemblies.len() >= HISTORY_MAX_ASSEMBLIES {
            return Err(HistoryProtocolError::TooManyIncompleteItems);
        }
        let assembly = self
            .assemblies
            .entry(key.clone())
            .or_insert_with(|| Assembly {
                parts: vec![None; chunk.part_count],
                size: 0,
                updated_at: now,
            });
        if assembly.parts[chunk.part_index].is_none() {
            let bytes = HISTORY_BASE64
                .decode(&chunk.data)
                .map_err(|_| HistoryProtocolError::InvalidChunk)?;
            assembly.size += bytes.len();
            assembly.parts[chunk.part_index] = Some(bytes);
        }
        if assembly.size > HISTORY_MAX_ITEM_BYTES {
            self.assemblies.remove(&key);
            return Err(HistoryProtocolError::ItemTooLarge);
        }
        assembly.updated_at = now;
        if assembly.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut combined = Vec::with_capacity(assembly.size);
        for bytes in assembly.parts.iter().flatten() {
            combined.extend_from_slice(bytes);
        }
        // TextDecoder removes one leading UTF-8 BOM before WEB's JSON.parse.
        let json_bytes = combined.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&combined);
        match serde_json::from_slice::<Value>(json_bytes) {
            Ok(item) if item.is_object() => Ok(Some(item)),
            _ => {
                self.assemblies.remove(&key);
                Err(HistoryProtocolError::InvalidItem)
            }
        }
    }

    /// Release a completed item after its caller commits it locally.
    pub fn acknowledge(
        &mut self,
        account_id: &str,
        source_device: u32,
        chunk: &HistoryChunk,
    ) -> bool {
        self.discard(account_id, source_device, chunk)
    }

    /// Release an item rejected by deterministic validation.
    pub fn discard(&mut self, account_id: &str, source_device: u32, chunk: &HistoryChunk) -> bool {
        self.assemblies
            .remove(&AssemblyKey::new(account_id, source_device, chunk))
            .is_some()
    }

    /// Release every assembly belonging to the account, such as on logout.
    pub fn clear_account(&mut self, account_id: &str) {
        self.assemblies
            .retain(|key, _| key.account_id != account_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TRANSFER: &str = "019c6e27-e55b-73d1-87d8-4e01f1f75043";
    const CONVERSATION: &str = "019c7714-3b77-74d1-9866-e1f484aae2ab";

    fn wire_chunk() -> Value {
        json!({
            "kind": "history_sync", "version": 1,
            "transfer_id": TRANSFER, "conversation_id": CONVERSATION,
            "item_kind": "message", "item_id": "record-1",
            "part_index": 0, "part_count": 1, "data": "e30="
        })
    }

    fn chunk() -> HistoryChunk {
        parse_history_chunk(&wire_chunk()).unwrap()
    }

    fn pending(item_id: &str) -> HistoryChunk {
        let mut chunk = chunk();
        chunk.item_id = item_id.into();
        chunk.part_count = 2;
        chunk
    }

    #[test]
    fn parses_web_wire_fixture_and_serializes_unchanged() {
        let parsed = parse_history_chunk(&wire_chunk()).unwrap();
        assert_eq!(parsed.item_kind, HistoryItemKind::Message);
        assert_eq!(serde_json::to_value(parsed).unwrap(), wire_chunk());
    }

    #[test]
    fn rejects_invalid_wire_fields_before_allocating_assemblies() {
        let cases = [
            ("kind", json!("message")),
            ("version", json!(2)),
            ("transfer_id", json!("bad")),
            ("conversation_id", json!("bad")),
            ("item_kind", json!("other")),
            ("item_id", json!("")),
            ("item_id", json!("a".repeat(129))),
            ("item_id", json!("😀".repeat(65))),
            ("part_index", json!(-1)),
            ("part_index", json!(1)),
            ("part_index", json!(0.5)),
            ("part_count", json!(0)),
            ("part_count", json!(87)),
            ("part_count", json!(1.5)),
            ("data", json!("YQ")),
            ("data", json!("YQ=")),
            ("data", json!("YQ==\n")),
            ("data", json!("YQ--")),
            ("data", json!("A".repeat(32_772))),
            ("data", Value::Null),
        ];
        for (field, value) in cases {
            let mut wire = wire_chunk();
            wire[field] = value;
            assert!(
                parse_history_chunk(&wire).is_none(),
                "accepted {field}: {wire}"
            );
        }
        for field in wire_chunk().as_object().unwrap().keys() {
            let mut wire = wire_chunk();
            wire.as_object_mut().unwrap().remove(field);
            assert!(parse_history_chunk(&wire).is_none(), "missing {field}");
        }
        assert!(parse_history_chunk(&Value::Null).is_none());
    }

    #[test]
    fn accepts_uuid_shape_empty_base64_and_javascript_integer_numbers() {
        let mut wire = wire_chunk();
        wire["transfer_id"] = json!("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
        wire["data"] = json!("");
        wire["part_count"] = json!(86.0);
        wire["part_index"] = json!(85.0);
        wire["item_id"] = json!("😀".repeat(64));
        assert!(parse_history_chunk(&wire).is_some());
    }

    #[test]
    fn fragments_utf8_into_web_sized_base64_parts_and_reassembles_out_of_order() {
        let item = json!({"text": "😀".repeat(7_000)});
        let chunks =
            history_chunks(TRANSFER, CONVERSATION, HistoryItemKind::Message, "m", &item).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].data.len(), 32_768);
        assert_eq!(chunks[0].part_index, 0);
        assert_eq!(chunks[1].part_index, 1);
        assert!(chunks.iter().all(|part| part.part_count == 2));
        let mut assembler = HistoryAssembler::default();
        assert_eq!(assembler.assemble("account", 1, &chunks[1]).unwrap(), None);
        assert_eq!(
            assembler.assemble("account", 1, &chunks[0]).unwrap(),
            Some(item)
        );
    }

    #[test]
    fn fragmenter_enforces_exact_two_mebibyte_boundary() {
        let exact = json!({"s": "a".repeat(2_097_144)});
        let chunks = history_chunks(
            TRANSFER,
            CONVERSATION,
            HistoryItemKind::Attachment,
            "a",
            &exact,
        )
        .unwrap();
        assert_eq!(chunks.len(), 86);
        let too_large = json!({"s": "a".repeat(2_097_145)});
        assert!(matches!(
            history_chunks(
                TRANSFER,
                CONVERSATION,
                HistoryItemKind::Attachment,
                "a",
                &too_large
            ),
            Err(HistoryProtocolError::ItemTooLarge)
        ));
    }

    #[test]
    fn fragmenter_rejects_invalid_metadata() {
        assert!(
            history_chunks(
                "bad",
                CONVERSATION,
                HistoryItemKind::Message,
                "m",
                &json!({})
            )
            .is_err()
        );
        assert!(
            history_chunks(TRANSFER, "bad", HistoryItemKind::Message, "m", &json!({})).is_err()
        );
        assert!(
            history_chunks(
                TRANSFER,
                CONVERSATION,
                HistoryItemKind::Message,
                "",
                &json!({})
            )
            .is_err()
        );
    }

    #[test]
    fn completed_payload_is_retained_until_acknowledgement() {
        let chunk = chunk();
        let mut assembler = HistoryAssembler::default();
        assert_eq!(
            assembler.assemble("account", 1, &chunk).unwrap(),
            Some(json!({}))
        );
        let mut duplicate = chunk.clone();
        duplicate.data = "eyJ4IjoxfQ==".into();
        assert_eq!(
            assembler.assemble("account", 1, &duplicate).unwrap(),
            Some(json!({}))
        );
        assembler.acknowledge("account", 1, &chunk);
        assert_eq!(
            assembler.assemble("account", 1, &duplicate).unwrap(),
            Some(json!({"x": 1}))
        );
    }

    #[test]
    fn count_conflicts_preserve_the_original_assembly() {
        let first = pending("m");
        let mut conflicting = first.clone();
        conflicting.part_count = 3;
        let mut assembler = HistoryAssembler::default();
        assert_eq!(assembler.assemble("account", 1, &first).unwrap(), None);
        assert!(matches!(
            assembler.assemble("account", 1, &conflicting),
            Err(HistoryProtocolError::InconsistentFragmentCount)
        ));
        let mut last = first.clone();
        last.part_index = 1;
        last.data.clear();
        assert_eq!(
            assembler.assemble("account", 1, &last).unwrap(),
            Some(json!({}))
        );
    }

    #[test]
    fn overflow_drops_only_the_offending_assembly() {
        let mut fragment = pending("large");
        fragment.part_count = 86;
        fragment.data = "YWFh".repeat(8_192);
        let mut assembler = HistoryAssembler::default();
        assembler.assemble("account", 1, &pending("other")).unwrap();
        for index in 0..85 {
            fragment.part_index = index;
            assert_eq!(assembler.assemble("account", 1, &fragment).unwrap(), None);
        }
        fragment.part_index = 85;
        assert!(matches!(
            assembler.assemble("account", 1, &fragment),
            Err(HistoryProtocolError::ItemTooLarge)
        ));
        assert!(!assembler.discard("account", 1, &fragment));
        assert!(assembler.discard("account", 1, &pending("other")));
    }

    #[test]
    fn malformed_completed_json_utf8_and_nonobjects_are_discarded() {
        for encoded in ["/w==", "ew==", "bnVsbA==", "W10=", "MQ==", ""] {
            let mut chunk = chunk();
            chunk.data = encoded.into();
            let mut assembler = HistoryAssembler::default();
            assert!(matches!(
                assembler.assemble("account", 1, &chunk),
                Err(HistoryProtocolError::InvalidItem)
            ));
            assert!(!assembler.discard("account", 1, &chunk));
            chunk.data = "e30=".into();
            assert_eq!(
                assembler.assemble("account", 1, &chunk).unwrap(),
                Some(json!({}))
            );
        }
    }

    #[test]
    fn accepts_web_base64_with_nonzero_unused_bits() {
        let mut chunk = chunk();
        chunk.data = "e31=".into();
        assert!(parse_history_chunk(&serde_json::to_value(&chunk).unwrap()).is_some());
        assert_eq!(
            HistoryAssembler::default()
                .assemble("account", 1, &chunk)
                .unwrap(),
            Some(json!({}))
        );
    }

    #[test]
    fn strips_a_leading_utf8_bom_like_the_web_text_decoder() {
        let mut chunk = chunk();
        chunk.data = "77u/e30=".into();
        assert_eq!(
            HistoryAssembler::default()
                .assemble("account", 1, &chunk)
                .unwrap(),
            Some(json!({}))
        );
    }

    #[test]
    fn bounds_all_assemblies_including_completed_unacknowledged_items() {
        let mut assembler = HistoryAssembler::default();
        for index in 0..32 {
            let mut chunk = chunk();
            chunk.item_id = index.to_string();
            assembler.assemble("account", 1, &chunk).unwrap();
        }
        let next = pending("next");
        assert!(matches!(
            assembler.assemble("account", 1, &next),
            Err(HistoryProtocolError::TooManyIncompleteItems)
        ));
        let mut existing = chunk();
        existing.item_id = "0".into();
        assert_eq!(
            assembler.assemble("account", 1, &existing).unwrap(),
            Some(json!({}))
        );
        assembler.acknowledge("account", 1, &existing);
        assert_eq!(assembler.assemble("account", 1, &next).unwrap(), None);
    }

    #[test]
    fn expiry_is_strictly_after_ten_minutes_and_redelivery_refreshes_it() {
        let start = Instant::now();
        let mut assembler = HistoryAssembler::default();
        for index in 0..32 {
            assembler
                .assemble_at("account", 1, &pending(&index.to_string()), start)
                .unwrap();
        }
        assert!(matches!(
            assembler.assemble_at(
                "account",
                1,
                &pending("next"),
                start + Duration::from_secs(600)
            ),
            Err(HistoryProtocolError::TooManyIncompleteItems)
        ));
        assembler
            .assemble_at(
                "account",
                1,
                &pending("0"),
                start + Duration::from_secs(600),
            )
            .unwrap();
        assert_eq!(
            assembler
                .assemble_at(
                    "account",
                    1,
                    &pending("next"),
                    start + Duration::from_secs(601)
                )
                .unwrap(),
            None
        );
        assert!(assembler.discard("account", 1, &pending("0")));
        assert!(!assembler.discard("account", 1, &pending("1")));
    }

    #[test]
    fn account_device_and_item_metadata_partition_assemblies() {
        let first = pending("m");
        let mut last = first.clone();
        last.part_index = 1;
        last.data.clear();
        let mut assembler = HistoryAssembler::default();
        assembler.assemble("a", 1, &first).unwrap();
        assert_eq!(assembler.assemble("a", 2, &last).unwrap(), None);
        assert_eq!(assembler.assemble("b", 1, &last).unwrap(), None);
        for field in ["transfer", "conversation", "kind", "item"] {
            let mut other = last.clone();
            match field {
                "transfer" => other.transfer_id = CONVERSATION.into(),
                "conversation" => other.conversation_id = TRANSFER.into(),
                "kind" => other.item_kind = HistoryItemKind::Complete,
                _ => other.item_id = "different".into(),
            }
            assert_eq!(assembler.assemble("a", 1, &other).unwrap(), None);
        }
        assembler.clear_account("a");
        assert_eq!(assembler.assemble("a", 1, &last).unwrap(), None);
        assert_eq!(assembler.assemble("b", 1, &first).unwrap(), Some(json!({})));
    }

    #[test]
    fn assembler_revalidates_directly_constructed_chunks() {
        let mut invalid = chunk();
        invalid.part_count = 0;
        assert!(matches!(
            HistoryAssembler::default().assemble("account", 1, &invalid),
            Err(HistoryProtocolError::InvalidChunk)
        ));
    }
}
