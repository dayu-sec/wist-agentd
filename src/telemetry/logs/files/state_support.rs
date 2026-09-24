use std::path::PathBuf;

use wist_contracts::telemetry_record::TelemetryRecord;

use crate::state_store::log_checkpoint_state::{LogCheckpointState, PendingMultilineState};
use crate::telemetry::logs::files::file_reader::ObservedFileIdentity;
use crate::telemetry::logs::files::file_watcher::ResumeDecision;
use crate::telemetry::logs::gate::Withheld;

#[derive(Debug, Clone, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(super) struct PendingCheckpoint {
    pub(super) source_path: PathBuf,
    pub(super) identity: ObservedFileIdentity,
    pub(super) checkpoint_offset: u64,
    pub(super) rotated_from_path: Option<String>,
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(super) struct RuntimeState {
    pub(super) checkpoint_path: PathBuf,
    pub(super) log_state: LogCheckpointState,
    pub(super) observed_at: String,
    pub(super) replayed_spool: usize,
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(super) struct CollectedReadBatch {
    pub(super) records: Vec<TelemetryRecord>,
    pub(super) pending_multiline: Option<PendingMultilineState>,
    pub(super) checkpoints: Vec<PendingCheckpoint>,
    pub(super) checkpoint_offset: u64,
    pub(super) truncated_lines: usize,
    /// 本次因**内容不全**被挡下（不转发）的记录。
    pub(super) withheld: Withheld,
    pub(super) resume: ResumeDecision,
}

impl CollectedReadBatch {
    pub(super) fn new(resume: ResumeDecision) -> Self {
        Self {
            records: Vec::new(),
            pending_multiline: None,
            checkpoints: Vec::new(),
            checkpoint_offset: 0,
            truncated_lines: 0,
            withheld: Withheld::default(),
            resume,
        }
    }
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(super) struct DeliveryOutcome {
    pub(super) records_processed: usize,
    pub(super) emitted_directly: usize,
    pub(super) spooled: usize,
}
