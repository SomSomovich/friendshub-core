//! Transactional staging for encrypted-history replay.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use crate::util::time::now_unix;

const MAX_PENDING_STAGES: usize = 4;
pub const HISTORY_REPLAY_STAGE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityStateRow {
    pub id: i64,
    pub key_pair: Vec<u8>,
    pub registration_id: i64,
    pub next_prekey_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentityRow {
    pub account_id: String,
    pub device_number: i64,
    pub identity_key: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyRow {
    pub prekey_id: i64,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KyberPreKeyRow {
    pub prekey_id: i64,
    pub record: Vec<u8>,
    pub used: i64,
    pub key_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    pub account_id: String,
    pub device_number: i64,
    pub record: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyRow {
    pub sender_account_id: String,
    pub sender_device_number: i64,
    pub distribution_id: Vec<u8>,
    pub record: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityChangeRow {
    pub id: i64,
    pub account_id: String,
    pub device_number: i64,
    pub old_key: Vec<u8>,
    pub new_key: Vec<u8>,
    pub changed_at: i64,
    pub notified: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub account_id: Option<String>,
    pub device_number: Option<i64>,
}

/// Every durable table touched by the Signal and sender-key stores.
///
/// Rows are kept as typed values so the stage can be compared to the live
/// state and atomically copied back without serializing secret material into a
/// client-visible token or file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSnapshot {
    pub auth_context: Option<AuthContext>,
    pub identity_state: Vec<IdentityStateRow>,
    pub peer_identities: Vec<PeerIdentityRow>,
    pub pre_keys: Vec<PreKeyRow>,
    pub signed_pre_keys: Vec<PreKeyRow>,
    pub kyber_pre_keys: Vec<KyberPreKeyRow>,
    pub sessions: Vec<SessionRow>,
    pub sender_keys: Vec<SenderKeyRow>,
    pub identity_changes: Vec<IdentityChangeRow>,
    pub identity_change_sequence: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StageError {
    #[error("history replay token is invalid or expired")]
    UnknownOrExpired,
    #[error("too many pending history replay stages")]
    Capacity,
    #[error("database error: {0}")]
    Database(String),
}

#[derive(Debug, Clone)]
pub struct CryptoStage {
    pub base: CryptoSnapshot,
    pub staged: CryptoSnapshot,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitReceipt {
    Committed,
    Conflict,
}

#[derive(Debug)]
pub enum CommitLookup {
    Pending(CryptoStage),
    AlreadyCommitted,
    PreviouslyConflicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableCommitResult {
    Committed,
    Conflict,
    AlreadyCommitted,
    PreviouslyConflicted,
}

#[derive(Debug)]
struct ReceiptEntry {
    receipt: CommitReceipt,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct ReplayStages {
    pending: HashMap<String, CryptoStage>,
    receipts: HashMap<String, ReceiptEntry>,
}

impl ReplayStages {
    pub fn insert(
        &mut self,
        base: CryptoSnapshot,
        staged: CryptoSnapshot,
    ) -> Result<String, StageError> {
        self.insert_at(base, staged, Instant::now())
    }

    fn insert_at(
        &mut self,
        base: CryptoSnapshot,
        staged: CryptoSnapshot,
        now: Instant,
    ) -> Result<String, StageError> {
        self.purge_expired(now);
        if self.pending.len() >= MAX_PENDING_STAGES {
            return Err(StageError::Capacity);
        }
        let token = Uuid::new_v4().to_string();
        self.pending.insert(
            token.clone(),
            CryptoStage {
                base,
                staged,
                expires_at: now + HISTORY_REPLAY_STAGE_TTL,
            },
        );
        Ok(token)
    }

    pub fn take(&mut self, token: &str) -> Result<CryptoStage, StageError> {
        self.take_at(token, Instant::now())
    }

    fn take_at(&mut self, token: &str, now: Instant) -> Result<CryptoStage, StageError> {
        self.purge_expired(now);
        self.pending
            .remove(token)
            .ok_or(StageError::UnknownOrExpired)
    }

    pub fn discard(&mut self, token: &str) -> Result<(), StageError> {
        self.take(token).map(drop)
    }

    fn purge_expired(&mut self, now: Instant) {
        self.pending.retain(|_, stage| stage.expires_at > now);
        self.receipts.retain(|_, receipt| receipt.expires_at > now);
    }

    pub fn purge_expired_now(&mut self) {
        self.purge_expired(Instant::now());
    }

    pub fn lookup_for_commit(&mut self, token: &str) -> Result<CommitLookup, StageError> {
        self.lookup_for_commit_at(token, Instant::now())
    }

    fn lookup_for_commit_at(
        &mut self,
        token: &str,
        now: Instant,
    ) -> Result<CommitLookup, StageError> {
        self.purge_expired(now);
        if let Some(receipt) = self.receipts.get(token) {
            return Ok(match receipt.receipt {
                CommitReceipt::Committed => CommitLookup::AlreadyCommitted,
                CommitReceipt::Conflict => CommitLookup::PreviouslyConflicted,
            });
        }
        self.pending
            .get(token)
            .cloned()
            .map(CommitLookup::Pending)
            .ok_or(StageError::UnknownOrExpired)
    }

    pub fn finish_commit(&mut self, token: &str, receipt: CommitReceipt) {
        self.finish_commit_at(token, receipt, Instant::now());
    }

    fn finish_commit_at(&mut self, token: &str, receipt: CommitReceipt, now: Instant) {
        self.pending.remove(token);
        self.receipts.retain(|_, entry| entry.expires_at > now);
        if self.receipts.len() >= MAX_PENDING_STAGES {
            if let Some(oldest) = self
                .receipts
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(token, _)| token.clone())
            {
                self.receipts.remove(&oldest);
            }
        }
        self.receipts.insert(
            token.to_owned(),
            ReceiptEntry {
                receipt,
                expires_at: now + HISTORY_REPLAY_STAGE_TTL,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    fn insert_at_for_test(
        &mut self,
        base: CryptoSnapshot,
        staged: CryptoSnapshot,
        now: Instant,
    ) -> Result<String, StageError> {
        self.insert_at(base, staged, now)
    }

    #[cfg(test)]
    fn take_at_for_test(&mut self, token: &str, now: Instant) -> Result<CryptoStage, StageError> {
        self.take_at(token, now)
    }

    #[cfg(test)]
    fn lookup_for_commit_at_for_test(
        &mut self,
        token: &str,
        now: Instant,
    ) -> Result<CommitLookup, StageError> {
        self.lookup_for_commit_at(token, now)
    }

    #[cfg(test)]
    fn finish_commit_at_for_test(&mut self, token: &str, receipt: CommitReceipt, now: Instant) {
        self.finish_commit_at(token, receipt, now)
    }
}

pub async fn load_snapshot(db: &SqlitePool) -> Result<CryptoSnapshot, StageError> {
    let mut transaction = db.begin().await.map_err(db_error)?;
    let snapshot = load_snapshot_from(&mut *transaction).await?;
    transaction.commit().await.map_err(db_error)?;
    Ok(snapshot)
}

async fn load_snapshot_from(
    connection: &mut SqliteConnection,
) -> Result<CryptoSnapshot, StageError> {
    let auth_context = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
        "SELECT account_id, device_number FROM auth_state WHERE id = 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(db_error)?
    .map(|(account_id, device_number)| AuthContext {
        account_id,
        device_number,
    });

    let identity_state = sqlx::query_as::<_, (i64, Vec<u8>, i64, i64)>(
        "SELECT id, key_pair, registration_id, next_prekey_id FROM identity_state ORDER BY id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(
        |(id, key_pair, registration_id, next_prekey_id)| IdentityStateRow {
            id,
            key_pair,
            registration_id,
            next_prekey_id,
        },
    )
    .collect();

    let peer_identities = sqlx::query_as::<_, (String, i64, Vec<u8>, i64)>(
        "SELECT account_id, device_number, identity_key, updated_at FROM peer_identities ORDER BY account_id, device_number",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|(account_id, device_number, identity_key, updated_at)| PeerIdentityRow {
        account_id,
        device_number,
        identity_key,
        updated_at,
    })
    .collect();

    let pre_keys = load_prekeys(&mut *connection, "pre_keys").await?;
    let signed_pre_keys = load_prekeys(&mut *connection, "signed_pre_keys").await?;
    let kyber_pre_keys = sqlx::query_as::<_, (i64, Vec<u8>, i64, String)>(
        "SELECT prekey_id, record, used, key_kind FROM kyber_pre_keys ORDER BY prekey_id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|(prekey_id, record, used, key_kind)| KyberPreKeyRow {
        prekey_id,
        record,
        used,
        key_kind,
    })
    .collect();

    let sessions = sqlx::query_as::<_, (String, i64, Vec<u8>, i64)>(
        "SELECT account_id, device_number, record, updated_at FROM sessions ORDER BY account_id, device_number",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|(account_id, device_number, record, updated_at)| SessionRow {
        account_id,
        device_number,
        record,
        updated_at,
    })
    .collect();

    let sender_keys = sqlx::query_as::<_, (String, i64, Vec<u8>, Vec<u8>, i64)>(
        "SELECT sender_account_id, sender_device_number, distribution_id, record, updated_at FROM sender_keys ORDER BY sender_account_id, sender_device_number, distribution_id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|(sender_account_id, sender_device_number, distribution_id, record, updated_at)| {
        SenderKeyRow {
            sender_account_id,
            sender_device_number,
            distribution_id,
            record,
            updated_at,
        }
    })
    .collect();

    let identity_changes = sqlx::query_as::<_, (i64, String, i64, Vec<u8>, Vec<u8>, i64, i64)>(
        "SELECT id, account_id, device_number, old_key, new_key, changed_at, notified FROM identity_changes ORDER BY id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|(id, account_id, device_number, old_key, new_key, changed_at, notified)| {
        IdentityChangeRow {
            id,
            account_id,
            device_number,
            old_key,
            new_key,
            changed_at,
            notified,
        }
    })
    .collect();

    let identity_change_sequence = sqlx::query_scalar::<_, i64>(
        "SELECT seq FROM sqlite_sequence WHERE name = 'identity_changes'",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(db_error)?
    .unwrap_or_default();

    Ok(CryptoSnapshot {
        auth_context,
        identity_state,
        peer_identities,
        pre_keys,
        signed_pre_keys,
        kyber_pre_keys,
        sessions,
        sender_keys,
        identity_changes,
        identity_change_sequence,
    })
}

async fn load_prekeys(
    connection: &mut SqliteConnection,
    table: &'static str,
) -> Result<Vec<PreKeyRow>, StageError> {
    // The table name is private and only ever one of the two literal names
    // passed by load_snapshot_from.
    let query = match table {
        "pre_keys" => "SELECT prekey_id, record FROM pre_keys ORDER BY prekey_id",
        "signed_pre_keys" => "SELECT prekey_id, record FROM signed_pre_keys ORDER BY prekey_id",
        _ => unreachable!("internal fixed table name"),
    };
    Ok(sqlx::query_as::<_, (i64, Vec<u8>)>(query)
        .fetch_all(&mut *connection)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|(prekey_id, record)| PreKeyRow { prekey_id, record })
        .collect())
}

pub async fn replace_snapshot(
    db: &SqlitePool,
    snapshot: &CryptoSnapshot,
) -> Result<(), StageError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    replace_snapshot_in(&mut *tx, snapshot).await?;
    tx.commit().await.map_err(db_error)
}

/// Persist a staged crypto transition before its host-owned page can be saved.
/// The snapshots are stored in the SQLCipher database, so a native process
/// restart does not discard the token's ratchet transition.
pub async fn persist_pending_stage(
    db: &SqlitePool,
    token: &str,
    base: &CryptoSnapshot,
    staged: &CryptoSnapshot,
) -> Result<(), StageError> {
    let base = serde_json::to_string(base).map_err(db_error)?;
    let staged = serde_json::to_string(staged).map_err(db_error)?;
    let now = now_unix();
    let expires_at = now + HISTORY_REPLAY_STAGE_TTL.as_secs() as i64;
    let mut tx = db.begin().await.map_err(db_error)?;
    sqlx::query("DELETE FROM history_replay_stages WHERE expires_at <= ?")
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM history_replay_receipts WHERE expires_at <= ?")
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM history_replay_stages")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    if pending >= MAX_PENDING_STAGES as i64 {
        tx.rollback().await.map_err(db_error)?;
        return Err(StageError::Capacity);
    }
    sqlx::query(
        "INSERT INTO history_replay_stages (replay_token, base_snapshot, staged_snapshot, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token)
    .bind(base)
    .bind(staged)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)
}

/// Look up the durable result of a commit whose response may have been lost.
pub async fn lookup_durable_receipt(
    db: &SqlitePool,
    token: &str,
) -> Result<Option<CommitReceipt>, StageError> {
    let now = now_unix();
    sqlx::query("DELETE FROM history_replay_receipts WHERE expires_at <= ?")
        .bind(now)
        .execute(db)
        .await
        .map_err(db_error)?;
    let outcome = sqlx::query_scalar::<_, i64>(
        "SELECT outcome FROM history_replay_receipts WHERE replay_token = ? AND expires_at > ?",
    )
    .bind(token)
    .bind(now)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;
    outcome.map(receipt_from_db).transpose()
}

/// Atomically apply a persisted stage and write its receipt in the same SQLite
/// transaction. A retry after process restart therefore cannot mistake an
/// already-applied ratchet transition for an unknown token.
pub async fn commit_persisted_stage(
    db: &SqlitePool,
    token: &str,
) -> Result<DurableCommitResult, StageError> {
    let mut connection = db.acquire().await.map_err(db_error)?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;

    let result = async {
        let now = now_unix();
        sqlx::query("DELETE FROM history_replay_stages WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM history_replay_receipts WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;

        if let Some(outcome) = sqlx::query_scalar::<_, i64>(
            "SELECT outcome FROM history_replay_receipts WHERE replay_token = ? AND expires_at > ?",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(db_error)?
        {
            return match receipt_from_db(outcome)? {
                CommitReceipt::Committed => Ok(DurableCommitResult::AlreadyCommitted),
                CommitReceipt::Conflict => Ok(DurableCommitResult::PreviouslyConflicted),
            };
        }

        let Some((base_json, staged_json)) = sqlx::query_as::<_, (String, String)>(
            "SELECT base_snapshot, staged_snapshot FROM history_replay_stages WHERE replay_token = ? AND expires_at > ?",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(db_error)?
        else {
            return Err(StageError::UnknownOrExpired);
        };
        let base: CryptoSnapshot = serde_json::from_str(&base_json).map_err(db_error)?;
        let staged: CryptoSnapshot = serde_json::from_str(&staged_json).map_err(db_error)?;
        let current = load_snapshot_from(&mut connection).await?;
        let (receipt, result) = if current != base {
            (CommitReceipt::Conflict, DurableCommitResult::Conflict)
        } else {
            replace_snapshot_in(&mut connection, &staged).await?;
            (CommitReceipt::Committed, DurableCommitResult::Committed)
        };

        sqlx::query("DELETE FROM history_replay_stages WHERE replay_token = ?")
            .bind(token)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
        sqlx::query(
            "INSERT OR REPLACE INTO history_replay_receipts (replay_token, outcome, expires_at) VALUES (?, ?, ?)",
        )
        .bind(token)
        .bind(receipt_to_db(receipt))
        .bind(now + HISTORY_REPLAY_STAGE_TTL.as_secs() as i64)
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
        Ok(result)
    }
    .await;

    match result {
        Ok(result) => match sqlx::query("COMMIT").execute(&mut *connection).await {
            Ok(_) => Ok(result),
            Err(commit_error) => {
                let rollback_result = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                if let Err(rollback_error) = rollback_result {
                    Err(StageError::Database(format!(
                        "{commit_error}; transaction rollback also failed: {rollback_error}"
                    )))
                } else {
                    Err(db_error(commit_error))
                }
            }
        },
        Err(error) => {
            let rollback_result = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            if let Err(rollback_error) = rollback_result {
                return Err(StageError::Database(format!(
                    "{error}; transaction rollback also failed: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

pub async fn discard_persisted_stage(db: &SqlitePool, token: &str) -> Result<bool, StageError> {
    let result = sqlx::query("DELETE FROM history_replay_stages WHERE replay_token = ?")
        .bind(token)
        .execute(db)
        .await
        .map_err(db_error)?;
    Ok(result.rows_affected() > 0)
}

fn receipt_from_db(value: i64) -> Result<CommitReceipt, StageError> {
    match value {
        0 => Ok(CommitReceipt::Conflict),
        1 => Ok(CommitReceipt::Committed),
        other => Err(StageError::Database(format!(
            "invalid history replay receipt value {other}"
        ))),
    }
}

fn receipt_to_db(receipt: CommitReceipt) -> i64 {
    match receipt {
        CommitReceipt::Conflict => 0,
        CommitReceipt::Committed => 1,
    }
}

async fn replace_snapshot_in(
    connection: &mut SqliteConnection,
    snapshot: &CryptoSnapshot,
) -> Result<(), StageError> {
    sqlx::query("DELETE FROM identity_state")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM peer_identities")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM pre_keys")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM signed_pre_keys")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM kyber_pre_keys")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM sessions")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM sender_keys")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM identity_changes")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;

    for row in &snapshot.identity_state {
        sqlx::query("INSERT INTO identity_state (id, key_pair, registration_id, next_prekey_id) VALUES (?, ?, ?, ?)")
            .bind(row.id)
            .bind(&row.key_pair)
            .bind(row.registration_id)
            .bind(row.next_prekey_id)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    for row in &snapshot.peer_identities {
        sqlx::query("INSERT INTO peer_identities (account_id, device_number, identity_key, updated_at) VALUES (?, ?, ?, ?)")
            .bind(&row.account_id)
            .bind(row.device_number)
            .bind(&row.identity_key)
            .bind(row.updated_at)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    insert_prekeys(connection, "pre_keys", &snapshot.pre_keys).await?;
    insert_prekeys(connection, "signed_pre_keys", &snapshot.signed_pre_keys).await?;
    for row in &snapshot.kyber_pre_keys {
        sqlx::query(
            "INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (?, ?, ?, ?)",
        )
        .bind(row.prekey_id)
        .bind(&row.record)
        .bind(row.used)
        .bind(&row.key_kind)
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    }
    for row in &snapshot.sessions {
        sqlx::query("INSERT INTO sessions (account_id, device_number, record, updated_at) VALUES (?, ?, ?, ?)")
            .bind(&row.account_id)
            .bind(row.device_number)
            .bind(&row.record)
            .bind(row.updated_at)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    for row in &snapshot.sender_keys {
        sqlx::query("INSERT INTO sender_keys (sender_account_id, sender_device_number, distribution_id, record, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&row.sender_account_id)
            .bind(row.sender_device_number)
            .bind(&row.distribution_id)
            .bind(&row.record)
            .bind(row.updated_at)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    for row in &snapshot.identity_changes {
        sqlx::query("INSERT INTO identity_changes (id, account_id, device_number, old_key, new_key, changed_at, notified) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(row.id)
            .bind(&row.account_id)
            .bind(row.device_number)
            .bind(&row.old_key)
            .bind(&row.new_key)
            .bind(row.changed_at)
            .bind(row.notified)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    sqlx::query("DELETE FROM sqlite_sequence WHERE name = 'identity_changes'")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    if snapshot.identity_change_sequence > 0 {
        sqlx::query("INSERT INTO sqlite_sequence (name, seq) VALUES ('identity_changes', ?)")
            .bind(snapshot.identity_change_sequence)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

async fn insert_prekeys(
    connection: &mut SqliteConnection,
    table: &'static str,
    rows: &[PreKeyRow],
) -> Result<(), StageError> {
    let query = match table {
        "pre_keys" => "INSERT INTO pre_keys (prekey_id, record) VALUES (?, ?)",
        "signed_pre_keys" => "INSERT INTO signed_pre_keys (prekey_id, record) VALUES (?, ?)",
        _ => unreachable!("internal fixed table name"),
    };
    for row in rows {
        sqlx::query(query)
            .bind(row.prekey_id)
            .bind(&row.record)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

/// Compare-and-swap the crypto rows under an IMMEDIATE SQLite write lock.
/// Returns `false` without writing anything if another operation changed the
/// crypto state after replay began.
pub async fn commit_snapshot(
    db: &SqlitePool,
    base: &CryptoSnapshot,
    staged: &CryptoSnapshot,
) -> Result<bool, StageError> {
    let mut connection = db.acquire().await.map_err(db_error)?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;

    let result = async {
        let current = load_snapshot_from(&mut *connection).await?;
        if &current != base {
            return Ok(false);
        }
        replace_snapshot_in(&mut *connection, staged).await?;
        Ok(true)
    }
    .await;

    match result {
        Ok(true) => match sqlx::query("COMMIT").execute(&mut *connection).await {
            Ok(_) => Ok(true),
            Err(commit_error) => {
                let rollback_result = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                if let Err(rollback_error) = rollback_result {
                    Err(StageError::Database(format!(
                        "{commit_error}; transaction rollback also failed: {rollback_error}"
                    )))
                } else {
                    Err(db_error(commit_error))
                }
            }
        },
        Ok(false) => {
            sqlx::query("ROLLBACK")
                .execute(&mut *connection)
                .await
                .map_err(db_error)?;
            Ok(false)
        }
        Err(error) => {
            let rollback_result = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            if let Err(rollback_error) = rollback_result {
                return Err(StageError::Database(format!(
                    "{error}; transaction rollback also failed: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

pub async fn clone_crypto_database(
    config: &crate::config::Config,
    http: &crate::transport::HttpClient,
    auth: &crate::db::auth::AuthState,
    snapshot: &CryptoSnapshot,
) -> Result<(SqlitePool, crate::runtime::ActorState), StageError> {
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(db_error)?;
    if let Err(error) = crate::db::migrations::MIGRATOR.run(&db).await {
        db.close().await;
        return Err(db_error(error));
    }
    if let Err(error) = replace_snapshot(&db, snapshot).await {
        db.close().await;
        return Err(error);
    }
    if let Err(error) = sqlx::query(
        "INSERT INTO auth_state (id, account_id, session_id, session_token, device_number, fh_number, expires_at, updated_at) VALUES (1, ?, NULL, NULL, ?, NULL, NULL, 0)",
    )
    .bind(&auth.account_id)
    .bind(auth.device_number)
    .execute(&db)
    .await
    {
        db.close().await;
        return Err(db_error(error));
    }
    let state = crate::runtime::ActorState::new(config.clone(), db.clone(), http.clone());
    Ok((db, state))
}

fn db_error(error: impl std::fmt::Display) -> StageError {
    StageError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> SqlitePool {
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::db::migrations::MIGRATOR.run(&db).await.unwrap();
        db
    }

    async fn set_session(db: &SqlitePool, value: &[u8]) {
        sqlx::query("INSERT INTO sessions (account_id, device_number, record, updated_at) VALUES ('peer', 7, ?, 1)")
            .bind(value)
            .execute(db)
            .await
            .unwrap();
    }

    async fn session(db: &SqlitePool) -> Option<Vec<u8>> {
        sqlx::query_scalar(
            "SELECT record FROM sessions WHERE account_id='peer' AND device_number=7",
        )
        .fetch_optional(db)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn discard_keeps_live_crypto_rows_unchanged() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut staged = base.clone();
        staged.sessions[0].record = b"after".to_vec();
        let mut stages = ReplayStages::default();
        let token = stages.insert(base, staged).unwrap();

        stages.discard(&token).unwrap();

        assert_eq!(session(&db).await.as_deref(), Some(&b"before"[..]));
        assert_eq!(
            stages.take(&token).unwrap_err(),
            StageError::UnknownOrExpired
        );
        db.close().await;
    }

    #[tokio::test]
    async fn commit_applies_staged_crypto_rows_atomically() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut staged = base.clone();
        staged.sessions[0].record = b"after".to_vec();
        let mut stages = ReplayStages::default();
        let token = stages.insert(base, staged.clone()).unwrap();
        let stage = stages.take(&token).unwrap();

        assert!(
            commit_snapshot(&db, &stage.base, &stage.staged)
                .await
                .unwrap()
        );
        assert_eq!(load_snapshot(&db).await.unwrap(), staged);
        assert_eq!(
            stages.take(&token).unwrap_err(),
            StageError::UnknownOrExpired
        );
        db.close().await;
    }

    #[tokio::test]
    async fn concurrent_crypto_change_conflicts_without_overwrite() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut staged = base.clone();
        staged.sessions[0].record = b"replayed".to_vec();
        sqlx::query("UPDATE sessions SET record = X'706172616C6C656C' WHERE account_id='peer' AND device_number=7")
            .execute(&db)
            .await
            .unwrap();

        assert!(!commit_snapshot(&db, &base, &staged).await.unwrap());
        assert_eq!(session(&db).await.as_deref(), Some(&b"parallel"[..]));
        db.close().await;
    }

    #[tokio::test]
    async fn persisted_stage_and_receipt_survive_registry_recreation() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut staged = base.clone();
        staged.sessions[0].record = b"after".to_vec();
        let token = Uuid::new_v4().to_string();
        persist_pending_stage(&db, &token, &base, &staged)
            .await
            .unwrap();

        assert_eq!(
            commit_persisted_stage(&db, &token).await.unwrap(),
            DurableCommitResult::Committed
        );
        assert_eq!(session(&db).await.as_deref(), Some(&b"after"[..]));
        assert_eq!(
            lookup_durable_receipt(&db, &token).await.unwrap(),
            Some(CommitReceipt::Committed)
        );
        assert_eq!(
            commit_persisted_stage(&db, &token).await.unwrap(),
            DurableCommitResult::AlreadyCommitted
        );
        db.close().await;
    }

    #[tokio::test]
    async fn persisted_conflict_is_a_durable_non_applying_receipt() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut staged = base.clone();
        staged.sessions[0].record = b"staged".to_vec();
        let token = Uuid::new_v4().to_string();
        persist_pending_stage(&db, &token, &base, &staged)
            .await
            .unwrap();
        sqlx::query("UPDATE sessions SET record = X'706172616C6C656C' WHERE account_id='peer' AND device_number=7")
            .execute(&db)
            .await
            .unwrap();

        assert_eq!(
            commit_persisted_stage(&db, &token).await.unwrap(),
            DurableCommitResult::Conflict
        );
        assert_eq!(session(&db).await.as_deref(), Some(&b"parallel"[..]));
        assert_eq!(
            commit_persisted_stage(&db, &token).await.unwrap(),
            DurableCommitResult::PreviouslyConflicted
        );
        assert_eq!(
            lookup_durable_receipt(&db, &token).await.unwrap(),
            Some(CommitReceipt::Conflict)
        );
        db.close().await;
    }

    #[tokio::test]
    async fn account_switch_conflicts_with_a_pending_replay() {
        let db = test_db().await;
        sqlx::query("INSERT INTO auth_state (id, account_id, device_number, updated_at) VALUES (1, 'alice', 2, 1)")
            .execute(&db)
            .await
            .unwrap();
        let base = load_snapshot(&db).await.unwrap();
        let staged = base.clone();
        sqlx::query("UPDATE auth_state SET account_id='bob' WHERE id=1")
            .execute(&db)
            .await
            .unwrap();

        assert!(!commit_snapshot(&db, &base, &staged).await.unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT account_id FROM auth_state WHERE id=1")
                .fetch_one(&db)
                .await
                .unwrap(),
            "bob"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn failed_replay_on_isolated_database_does_not_touch_live_state() {
        let db = test_db().await;
        set_session(&db, b"live").await;
        let snapshot = load_snapshot(&db).await.unwrap();
        let config = crate::config::Config {
            db_path: std::path::PathBuf::from(":memory:"),
            api_base: "http://127.0.0.1".into(),
            ws_url: "ws://127.0.0.1".into(),
            discovery: crate::config::DiscoveryConfig {
                enabled: false,
                ..crate::config::DiscoveryConfig::default()
            },
            log_level: "off".into(),
            log_format: "text".into(),
        };
        let http = crate::transport::HttpClient::new(&config).unwrap();
        let auth = crate::db::auth::AuthState {
            account_id: Some("local".into()),
            device_number: Some(4),
            ..Default::default()
        };
        let (isolated_db, isolated_state) = clone_crypto_database(&config, &http, &auth, &snapshot)
            .await
            .unwrap();
        sqlx::query("UPDATE sessions SET record = ? WHERE account_id='peer' AND device_number=7")
            .bind(b"staged-only".as_slice())
            .execute(&isolated_db)
            .await
            .unwrap();

        // A decryption error discards this temporary pool without a live DB
        // write. The caller cannot apply its staged snapshot after returning
        // the page error.
        drop(isolated_state);
        isolated_db.close().await;

        assert_eq!(session(&db).await.as_deref(), Some(&b"live"[..]));
        db.close().await;
    }

    #[tokio::test]
    async fn failed_partial_replacement_rolls_back_every_crypto_table() {
        let db = test_db().await;
        set_session(&db, b"before").await;
        let base = load_snapshot(&db).await.unwrap();
        let mut invalid = base.clone();
        invalid.sessions[0].record = b"after".to_vec();
        invalid.identity_state = vec![
            IdentityStateRow {
                id: 1,
                key_pair: vec![1],
                registration_id: 1,
                next_prekey_id: 1,
            },
            IdentityStateRow {
                id: 1,
                key_pair: vec![2],
                registration_id: 2,
                next_prekey_id: 2,
            },
        ];

        assert!(commit_snapshot(&db, &base, &invalid).await.is_err());
        assert_eq!(load_snapshot(&db).await.unwrap(), base);
        db.close().await;
    }

    #[tokio::test]
    async fn staged_snapshot_preserves_kyber_prekey_kind() {
        let db = test_db().await;
        sqlx::query("INSERT INTO kyber_pre_keys (prekey_id, record, used, key_kind) VALUES (7, X'01', 1, 'last_resort')")
            .execute(&db)
            .await
            .unwrap();
        let base = load_snapshot(&db).await.unwrap();

        replace_snapshot(&db, &base).await.unwrap();

        let restored: (i64, String) =
            sqlx::query_as("SELECT used, key_kind FROM kyber_pre_keys WHERE prekey_id = 7")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(restored, (1, "last_resort".into()));
        db.close().await;
    }

    #[test]
    fn duplicate_tokens_are_one_shot_and_expiry_removes_pending_state() {
        let now = Instant::now();
        let mut stages = ReplayStages::default();
        let token = stages
            .insert_at_for_test(CryptoSnapshot::default(), CryptoSnapshot::default(), now)
            .unwrap();
        assert!(stages.take_at_for_test(&token, now).is_ok());
        assert_eq!(
            stages.take_at_for_test(&token, now).unwrap_err(),
            StageError::UnknownOrExpired
        );

        let expiring = stages
            .insert_at_for_test(CryptoSnapshot::default(), CryptoSnapshot::default(), now)
            .unwrap();
        let expired_at = now + HISTORY_REPLAY_STAGE_TTL + Duration::from_nanos(1);
        assert_eq!(
            stages.take_at_for_test(&expiring, expired_at).unwrap_err(),
            StageError::UnknownOrExpired
        );
        assert_eq!(stages.len(), 0);
    }

    #[test]
    fn successful_commit_receipt_makes_retry_idempotent_until_expiry() {
        let now = Instant::now();
        let mut stages = ReplayStages::default();
        let token = stages
            .insert_at_for_test(CryptoSnapshot::default(), CryptoSnapshot::default(), now)
            .unwrap();

        assert!(matches!(
            stages.lookup_for_commit_at_for_test(&token, now),
            Ok(CommitLookup::Pending(_))
        ));
        stages.finish_commit_at_for_test(&token, CommitReceipt::Committed, now);
        assert!(matches!(
            stages.lookup_for_commit_at_for_test(
                &token,
                now + HISTORY_REPLAY_STAGE_TTL - Duration::from_secs(1)
            ),
            Ok(CommitLookup::AlreadyCommitted)
        ));
        assert!(matches!(
            stages.lookup_for_commit_at_for_test(&token, now + HISTORY_REPLAY_STAGE_TTL * 2),
            Err(StageError::UnknownOrExpired)
        ));
    }

    #[test]
    fn pending_stage_count_is_bounded() {
        let mut stages = ReplayStages::default();
        for _ in 0..MAX_PENDING_STAGES {
            stages
                .insert(CryptoSnapshot::default(), CryptoSnapshot::default())
                .unwrap();
        }
        assert_eq!(
            stages
                .insert(CryptoSnapshot::default(), CryptoSnapshot::default())
                .unwrap_err(),
            StageError::Capacity
        );
        assert_eq!(stages.len(), MAX_PENDING_STAGES);
    }
}
