//! End-to-end standalone file-input processing.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::time::{now_rfc3339, now_ts_ms};

use crate::state_store::log_checkpoint_state::{
    LogCheckpointState, PendingMultilineState, TrackedFileCheckpoint,
};
use crate::state_store::log_checkpoints;
use crate::state_store::log_seq_state;
use crate::telemetry::logs::InputOrigin;
use crate::telemetry::logs::files::file_reader::{
    ObservedFileIdentity, ReadLimits, inspect_path_async, read_from_offset_async,
};
use crate::telemetry::logs::files::file_watcher::{StartupPosition, decide_resume_async};
use crate::telemetry::logs::gate::{UplinkGate, Withheld};
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::spool;
use crate::telemetry::warp_parse::RecordSink;

#[path = "checkpoint_support.rs"]
mod checkpoint_support;
#[path = "delivery_support.rs"]
mod delivery_support;
#[path = "multiline_support.rs"]
mod multiline_support;
#[path = "state_support.rs"]
mod state_support;

use checkpoint_support::{
    CheckpointUpdate, checkpoint_for_path, checkpoint_real_path, find_rotated_path_async,
    relocate_checkpoint_path, upsert_checkpoint_async,
};

#[cfg(test)]
use checkpoint_support::upsert_checkpoint;
use delivery_support::{deliver_records, replay_spool_if_present};
use multiline_support::{
    flush_pending_if_source_changes, pending_should_flush, rebind_pending_source_on_rotate,
    records_from_pending, records_from_read,
};
use state_support::{CollectedReadBatch, DeliveryOutcome, PendingCheckpoint, RuntimeState};

use super::glob_match::{FamilySelection, has_glob, resolve_family_paths};

const SPOOL_REPLAY_BATCH_SIZE: usize = 128;

/// 每个 input 最多跟踪多少个文件（超出后拒绝新文件，不淘汰已跟踪的）。
pub const DEFAULT_MAX_FILES_PER_INPUT: usize = 512;
/// 每 tick 最多接入多少个**新**文件（避免一个大目录把一轮 tick 拖死）。
pub const DEFAULT_MAX_NEW_FILES_PER_TICK: usize = 32;
/// 目录/glob 重扫间隔：3s tick 下不必每轮都扫（与 `daemon.rs::TICK_INTERVAL` 解耦）。
pub const DEFAULT_RESCAN_INTERVAL_MS: i64 = 15_000;

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct FileInputConfig {
    pub agent_id: String,
    pub input_id: String,
    /// 来源身份（面 + 目录单元）：随记录进帧。空 = 本机运维手工配置的输入。
    pub origin: InputOrigin,
    pub source_path: PathBuf,
    /// 文件族排除的路径（glob）；只对 glob/目录目标生效。
    pub exclude_globs: Vec<String>,
    /// 容器选源的结构化过滤器（默认空）；在**发现阶段**求值，只影响“哪些文件进工作集”。
    pub filters: wist_contracts::work::ContainerFilters,
    /// 每个 input 最多跟踪多少个文件。
    pub max_files: usize,
    /// 每 tick 最多接入多少个新文件。
    pub max_new_files: usize,
    /// 目录/glob 重扫间隔（毫秒）。
    pub rescan_interval_ms: i64,
    pub state_dir: PathBuf,
    pub spool_path: PathBuf,
    pub startup_position: StartupPosition,
    pub multiline_mode: MultilineMode,
    pub in_memory_budget_bytes: usize,
    /// 单次读取限制（长行截断 + 大文件分块回放）。
    pub read_limits: ReadLimits,
    /// spool 上限（字节），用于超限保护。
    pub spool_max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcomeKind {
    SourceBatch,
    SpoolReplayOnly,
    /// spool 已达上限且无法回放：暂停读源，保完整不丢数据。
    SpoolPaused,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct ProcessOutcome {
    pub kind: ProcessOutcomeKind,
    pub records_processed: usize,
    pub emitted_directly: usize,
    pub spooled: usize,
    /// **上送**这一步的失败原因（已含目标地址）；记录已安全进 spool。`None` = 没失败过。
    pub sink_error: Option<String>,
    pub checkpoint_offset: u64,
    pub replayed_spool: usize,
    pub truncated: bool,
    /// 本次因超长被截断提交的行数（每行已作为一条记录提交）。
    pub truncated_lines: usize,
    /// 本次因**内容不全**被挡下（不转发、不取号）的记录。
    /// 不是 0 就说明边界判据在这个文件上没起作用（例如某个块永不结束），必须说出来。
    pub withheld: Withheld,
    pub rotated: bool,
    /// 是否因 spool 超限而暂停采集。
    pub paused: bool,
    /// 暂停时的 spool 字节数。
    pub spool_bytes: u64,
    /// 文件族触顶（`max_files`）：本轮有匹配文件被拒绝跟踪。`None` = 没这回事。
    pub capacity: Option<FamilyCapacity>,
}

/// 文件族触顶的事实：匹配数超过跟踪上限，新文件不再纳入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyCapacity {
    /// 当前跟踪的文件数。
    pub tracked: usize,
    /// 上限。
    pub max_files: usize,
    /// 本轮因上限被拒绝的新文件数。
    pub refused: usize,
}

impl ProcessOutcome {
    fn from_delivery(
        delivery: DeliveryOutcome,
        checkpoint_offset: u64,
        replayed_spool: usize,
        truncated: bool,
        truncated_lines: usize,
        withheld: Withheld,
        rotated: bool,
    ) -> Self {
        Self {
            kind: ProcessOutcomeKind::SourceBatch,
            records_processed: delivery.records_processed,
            emitted_directly: delivery.emitted_directly,
            spooled: delivery.spooled,
            sink_error: delivery.sink_error,
            checkpoint_offset,
            replayed_spool,
            truncated,
            truncated_lines,
            withheld,
            rotated,
            paused: false,
            spool_bytes: 0,
            capacity: None,
        }
    }

    pub(crate) fn spool_replay_only(replayed_spool: usize) -> Self {
        Self {
            kind: ProcessOutcomeKind::SpoolReplayOnly,
            records_processed: 0,
            emitted_directly: 0,
            spooled: 0,
            sink_error: None,
            checkpoint_offset: 0,
            replayed_spool,
            truncated: false,
            truncated_lines: 0,
            withheld: Withheld::default(),
            rotated: false,
            paused: false,
            spool_bytes: 0,
            capacity: None,
        }
    }

    /// spool 超限暂停结果。
    ///
    /// `sink_error` 要跟着一起留下来：spool 涨满**不是**根因的消失 —— 根因通常是出口写不出去。
    /// 这里若把它丢掉，日志就从「目标连不上」退化成「spool 超限」，而目标地址恰恰是运维要的。
    pub(crate) fn paused(spool_bytes: u64, sink_error: Option<String>) -> Self {
        Self {
            kind: ProcessOutcomeKind::SpoolPaused,
            records_processed: 0,
            emitted_directly: 0,
            spooled: 0,
            sink_error,
            checkpoint_offset: 0,
            replayed_spool: 0,
            truncated: false,
            truncated_lines: 0,
            withheld: Withheld::default(),
            rotated: false,
            paused: true,
            spool_bytes,
            capacity: None,
        }
    }
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct FileInputProcessor<S> {
    config: FileInputConfig,
    sink: S,
}

impl<S> FileInputProcessor<S>
where
    S: RecordSink,
{
    pub fn new(config: FileInputConfig, sink: S) -> Self {
        Self { config, sink }
    }

    pub async fn process_once_async(&mut self, next_seq: &mut u64) -> io::Result<ProcessOutcome> {
        let mut runtime = self.load_runtime_state_async().await?;
        match replay_spool_if_present(
            &mut self.sink,
            &self.config.spool_path,
            SPOOL_REPLAY_BATCH_SIZE,
        )
        .await
        {
            Ok(replayed) => runtime.replayed_spool = replayed,
            Err(err) => {
                // 回放失败：若 spool 已达上限则进入暂停（保完整、不丢数据），
                // 否则维持原有错误语义。
                return match self.paused_outcome_async(Some(&err)).await? {
                    Some(paused) => Ok(paused),
                    None => Err(err),
                };
            }
        }
        let batch = self.collect_read_batch(&mut runtime, next_seq).await?;
        let CollectedReadBatch {
            records,
            pending_multiline,
            checkpoints,
            checkpoint_offset,
            truncated_lines,
            withheld,
            resume,
        } = batch;
        let delivery = self.deliver_records_async(records).await?;
        if delivery.records_processed > 0 {
            // 全局 `seq` 前移：写入独立文件（先于 checkpoint 提交、原子写）。
            // 前移一位保证崩溃只会造成「重复」（重读拿到新号），绝不回退撞号丢数据。
            let global_seq_path = log_seq_state::path_for(&self.config.state_dir);
            log_seq_state::store_async(&global_seq_path, *next_seq).await?;
        }
        self.commit_log_state(&mut runtime, checkpoints, pending_multiline)
            .await?;

        Ok(ProcessOutcome::from_delivery(
            delivery,
            checkpoint_offset,
            runtime.replayed_spool,
            resume.truncated,
            truncated_lines,
            withheld,
            resume.rotated,
        ))
    }

    #[cfg(test)]
    pub fn process_once(&mut self) -> io::Result<ProcessOutcome> {
        // 单 input 单测：从全局 `seq` 文件读取高水位作为起点（独立于 checkpoint）。
        let global_seq_path = log_seq_state::path_for(&self.config.state_dir);
        let mut next_seq =
            block_on_io(async { log_seq_state::load_or_default_async(&global_seq_path).await })?;
        block_on_io(self.process_once_async(&mut next_seq))
    }

    async fn load_runtime_state_async(&mut self) -> io::Result<RuntimeState> {
        load_runtime_state_async(&self.config).await
    }

    /// spool 达到上限时返回暂停结果（不读源、不推进 checkpoint）。
    ///
    /// `spool_over_limit` 校验收敛为仅 `pause`（保完整、不丢数据）；`drop_oldest`
    /// 留待后续按 input 优先级丢弃落地。
    async fn paused_outcome_async(
        &self,
        replay_error: Option<&io::Error>,
    ) -> io::Result<Option<ProcessOutcome>> {
        paused_outcome_async(
            &self.config.spool_path,
            self.config.spool_max_bytes,
            replay_error,
        )
        .await
    }

    async fn collect_read_batch(
        &self,
        runtime: &mut RuntimeState,
        next_seq: &mut u64,
    ) -> io::Result<CollectedReadBatch> {
        let current = inspect_path_async(&self.config.source_path).await?;
        let tracked = checkpoint_for_path(&runtime.log_state, &self.config.source_path);
        let resume = decide_resume_async(
            &self.config.source_path,
            &current,
            tracked.as_ref(),
            self.config.startup_position,
        )
        .await;
        let mut batch = CollectedReadBatch::new(resume);
        batch.pending_multiline = runtime.log_state.pending_multiline.take();
        // 记录出口的闸门：本次采集的所有记录都过它（内容不全的在它那里被挡下）。
        // 时间戳取一份：闸门会一直持有它，而 `runtime` 后面还要可变借用。
        let observed_at = runtime.observed_at.clone();
        let mut gate = UplinkGate::new(
            &self.config.agent_id,
            &observed_at,
            &self.config.input_id,
            self.config.origin.clone(),
        );
        let mut saw_new_lines = self
            .collect_rotated_tail(runtime, tracked.as_ref(), &mut batch, &mut gate, next_seq)
            .await?;

        if batch.resume.rotated || batch.resume.truncated {
            batch.records.extend(records_from_pending(
                &mut gate,
                batch.pending_multiline.take(),
                next_seq,
            ));
        } else {
            batch.records.extend(flush_pending_if_source_changes(
                &mut gate,
                &mut batch.pending_multiline,
                &self.config.source_path,
                next_seq,
            ));
        }

        let active_read = read_from_offset_async(
            &self.config.source_path,
            batch.resume.start_offset,
            self.config.read_limits,
        )
        .await?;
        saw_new_lines |= !active_read.lines.is_empty();
        batch.truncated_lines += active_read.truncated_lines;
        let folded = records_from_read(
            &mut gate,
            self.config.multiline_mode,
            &observed_at,
            &self.config.source_path,
            active_read.lines,
            batch.pending_multiline,
            next_seq,
        );
        batch.records.extend(folded.records);
        batch.pending_multiline = folded.pending;
        batch.checkpoint_offset = active_read.committed_end_offset;
        batch.checkpoints.push(PendingCheckpoint {
            source_path: self.config.source_path.clone(),
            identity: active_read.identity,
            checkpoint_offset: batch.checkpoint_offset,
            rotated_from_path: batch.resume.rotated_from_path.clone(),
        });

        if !saw_new_lines && pending_should_flush(batch.pending_multiline.as_ref(), &observed_at) {
            batch.records.extend(records_from_pending(
                &mut gate,
                batch.pending_multiline.take(),
                next_seq,
            ));
        }

        batch.withheld = gate.withheld();
        Ok(batch)
    }

    async fn collect_rotated_tail(
        &self,
        runtime: &mut RuntimeState,
        tracked: Option<&TrackedFileCheckpoint>,
        batch: &mut CollectedReadBatch,
        gate: &mut UplinkGate<'_>,
        next_seq: &mut u64,
    ) -> io::Result<bool> {
        if !batch.resume.rotated {
            return Ok(false);
        }
        let Some(previous) = tracked else {
            return Ok(false);
        };
        let Some(rotated_path) =
            find_rotated_path_async(&self.config.source_path, previous).await?
        else {
            return Ok(false);
        };

        relocate_checkpoint_path(&mut runtime.log_state, previous, &rotated_path);
        rebind_pending_source_on_rotate(
            &mut batch.pending_multiline,
            &self.config.source_path,
            &rotated_path,
        );
        let rotated_read = read_from_offset_async(
            &rotated_path,
            previous.checkpoint_offset,
            self.config.read_limits,
        )
        .await?;
        let saw_new_lines = !rotated_read.lines.is_empty();
        batch.truncated_lines += rotated_read.truncated_lines;
        let folded = records_from_read(
            gate,
            self.config.multiline_mode,
            &runtime.observed_at,
            &rotated_path,
            rotated_read.lines,
            batch.pending_multiline.take(),
            next_seq,
        );
        batch.records.extend(folded.records);
        batch.pending_multiline = folded.pending;
        batch.checkpoints.push(PendingCheckpoint {
            source_path: rotated_path,
            identity: rotated_read.identity,
            checkpoint_offset: rotated_read.committed_end_offset,
            rotated_from_path: None,
        });
        Ok(saw_new_lines)
    }

    async fn deliver_records_async(
        &mut self,
        records: Vec<TelemetryRecord>,
    ) -> io::Result<DeliveryOutcome> {
        deliver_records(
            &mut self.sink,
            &self.config.spool_path,
            self.config.in_memory_budget_bytes,
            records,
        )
        .await
    }

    async fn commit_log_state(
        &self,
        runtime: &mut RuntimeState,
        checkpoints: Vec<PendingCheckpoint>,
        pending_multiline: Option<PendingMultilineState>,
    ) -> io::Result<()> {
        for checkpoint in checkpoints {
            upsert_checkpoint_async(
                &mut runtime.log_state,
                &checkpoint.source_path,
                &checkpoint.identity,
                CheckpointUpdate {
                    checkpoint_offset: checkpoint.checkpoint_offset,
                    observed_at: &runtime.observed_at,
                    real_path: "",
                    pending_multiline: None,
                    rotated_from_path: checkpoint.rotated_from_path,
                },
            )
            .await;
        }
        runtime.log_state.pending_multiline = pending_multiline;
        runtime.log_state.updated_at = runtime.observed_at.clone();
        log_checkpoints::store_async(&runtime.checkpoint_path, &runtime.log_state).await
    }
}

/// 读取/加载一个 input 的本地状态（单文件与文件族共用）。
async fn load_runtime_state_async(config: &FileInputConfig) -> io::Result<RuntimeState> {
    let checkpoint_path = log_checkpoints::path_for(&config.state_dir, &config.input_id);
    // 读不动就**当没有**：一份 checkpoint 不该有让采集停下的权力。
    //
    // 不这么做的话，读不动的 checkpoint 会让这个输入**每 tick 都失败**（而且 daemon
    // 的失败去重让它只打印一次），变成"这个文件永远不进数据"的一个静默停摆；
    // 换 schema 时尤其容易踩到。
    //
    // 代价要说清：当没有 = 按 `startup_position` 重新定位 —— `tail` 跳过历史（安全），
    // `head` 会重放一遍（可能重复）。重复看得见且一次性，停摆看不见且持续。
    let log_state = match log_checkpoints::load_or_default_from_path_async(
        &checkpoint_path,
        &config.input_id,
    )
    .await
    {
        Ok(state) => state,
        Err(err) => {
            log::warn!(
                "event=LogCheckpointUnreadable input_id={} path={} err={err} action=\"按没有 checkpoint 处理，按 startup_position={} 重新定位\"",
                config.input_id,
                checkpoint_path.display(),
                match config.startup_position {
                    StartupPosition::Head => "head",
                    StartupPosition::Tail => "tail",
                },
            );
            log_checkpoints::load_or_default(&config.input_id)
        }
    };
    Ok(RuntimeState {
        log_state,
        checkpoint_path,
        observed_at: now_rfc3339(),
        replayed_spool: 0,
    })
}

/// spool 达到上限时返回暂停结果（单文件与文件族共用）。
async fn paused_outcome_async(
    spool_path: &Path,
    spool_max_bytes: u64,
    replay_error: Option<&io::Error>,
) -> io::Result<Option<ProcessOutcome>> {
    let spool_bytes = spool::size_async(spool_path).await?;
    if spool_bytes >= spool_max_bytes {
        // 只把**出口写失败**带进暂停结果（读/解析错误不算出口失败，别张冠李戴）。
        let sink_error = replay_error
            .and_then(crate::telemetry::warp_parse::uplink_write_detail)
            .map(str::to_string);
        Ok(Some(ProcessOutcome::paused(spool_bytes, sink_error)))
    } else {
        Ok(None)
    }
}

/// 文件族（glob / 目录）输入处理器：**一个 input，多个文件**。
///
/// 与 [`FileInputProcessor`] 的分工：显式单路径走后者（行为与既有测试逐字不变）；
/// 通配 / 目录走这里。两者共用读取、折叠、spool、checkpoint 的底层函数。
///
/// 关键语义（见 W1 方案 D4 / D5 / D10）：
/// - 首次见到这个 pattern：`startup_position`（默认 tail）；
/// - 运行中 / 重启后新出现的文件：**head**（checkpoint 里没有它 = 没见过）；
/// - symlink 走 `real_path` 读与找轮转（容器日志的 `/var/log/pods/...` 才是真实目录）；
/// - 每文件自己的 `pending_multiline`，不共用一个块。
pub struct FileFamilyProcessor<S> {
    config: FileInputConfig,
    sink: S,
}

impl<S> FileFamilyProcessor<S>
where
    S: RecordSink,
{
    pub fn new(config: FileInputConfig, sink: S) -> Self {
        Self { config, sink }
    }

    #[cfg(test)]
    pub fn process_once(&mut self) -> io::Result<ProcessOutcome> {
        let global_seq_path = log_seq_state::path_for(&self.config.state_dir);
        let mut next_seq =
            block_on_io(async { log_seq_state::load_or_default_async(&global_seq_path).await })?;
        block_on_io(self.process_once_async(&mut next_seq))
    }

    pub async fn process_once_async(&mut self, next_seq: &mut u64) -> io::Result<ProcessOutcome> {
        let mut runtime = load_runtime_state_async(&self.config).await?;
        // 提交时用来判断「状态真的变了吗」：没变就不重写状态盘。
        // 必须在 `migrate` **之前**拍快照 —— 迁移本身也是状态变更（否则孤儿块会被反复迁、反复发）。
        let before = runtime.log_state.clone();
        // 旧状态（单文件 input）的 input 级未封口块：能对上文件的迁过去，对不上的交给本轮封口 ——
        // 不交出去就会被下面的 `commit_family_state` 清空，那块内容就无声消失了。
        let orphan_pending = migrate_input_pending_to_files(&mut runtime.log_state);
        match replay_spool_if_present(
            &mut self.sink,
            &self.config.spool_path,
            SPOOL_REPLAY_BATCH_SIZE,
        )
        .await
        {
            Ok(replayed) => runtime.replayed_spool = replayed,
            Err(err) => {
                return match paused_outcome_async(
                    &self.config.spool_path,
                    self.config.spool_max_bytes,
                    Some(&err),
                )
                .await?
                {
                    Some(paused) => Ok(paused),
                    None => Err(err),
                };
            }
        }
        let batch = self
            .collect_family_batch(&mut runtime, next_seq, orphan_pending)
            .await?;
        let FamilyBatch {
            records,
            checkpoints,
            checkpoint_offset,
            truncated_lines,
            rotated,
            truncated,
            withheld,
            failure,
            capacity,
        } = batch;
        let delivery = deliver_records(
            &mut self.sink,
            &self.config.spool_path,
            self.config.in_memory_budget_bytes,
            records,
        )
        .await?;
        if delivery.records_processed > 0 {
            let global_seq_path = log_seq_state::path_for(&self.config.state_dir);
            log_seq_state::store_async(&global_seq_path, *next_seq).await?;
        }
        self.commit_family_state(&mut runtime, checkpoints, &before)
            .await?;
        // 先交付/提交能读到的，再把单文件读失败报给上层：不交出去的话，
        // 同目录其它文件每轮都白读一遍（记录已上送，checkpoint 却没前进）。
        if let Some(err) = failure {
            return Err(err);
        }
        let mut outcome = ProcessOutcome::from_delivery(
            delivery,
            checkpoint_offset,
            runtime.replayed_spool,
            truncated,
            truncated_lines,
            withheld,
            rotated,
        );
        outcome.capacity = capacity;
        Ok(outcome)
    }

    async fn collect_family_batch(
        &self,
        runtime: &mut RuntimeState,
        next_seq: &mut u64,
        orphan_pending: Option<PendingMultilineState>,
    ) -> io::Result<FamilyBatch> {
        let observed_at = runtime.observed_at.clone();
        let mut gate = UplinkGate::new(
            &self.config.agent_id,
            &observed_at,
            &self.config.input_id,
            self.config.origin.clone(),
        );
        let mut batch = FamilyBatch::new();
        // 迁移不上任何文件的旧块：没有文件可等，按到期封口直接交出去。
        batch
            .records
            .extend(records_from_pending(&mut gate, orphan_pending, next_seq));
        // 「首次扫描」= 这个 input **从未扫描过**（既没有跟踪任何文件，也没落过扫描时间）。
        //
        // 不能只看 `files.is_empty()`：跟踪过的文件全被删/轮转走之后也会是空，而那台机器上
        // 新出现的文件属于 D10 的「运行中/重启后新文件」—— 要从 head 读，不能当首装 tail。
        let first_scan =
            runtime.log_state.files.is_empty() && runtime.log_state.last_scan_ms.is_none();
        let target_text = self.config.source_path.display().to_string();
        let is_family = has_glob(&target_text) || self.config.source_path.is_dir();
        let now_ms = now_ts_ms();
        let should_scan = !is_family
            || runtime
                .log_state
                .last_scan_ms
                .is_none_or(|last| now_ms.saturating_sub(last) >= self.config.rescan_interval_ms);
        let selection = if should_scan {
            let selection = resolve_family_paths(
                &self.config.source_path,
                &self.config.exclude_globs,
                &self.config.filters,
                // 扫描上限 ≠ 跟踪上限：匹配集要足够全，否则「超过 max_files 的已跟踪文件」
                // 会被当作“不再匹配”错误清理。
                self.config.max_files.saturating_mul(4).max(1024),
            )
            .await?;
            // 只在**扫描成功**后推进时钟：扫描失败（目录不可读）时每轮都重试，
            // 否则错误只每 15s 报一次，中间那些 tick 看着「一切正常」。
            runtime.log_state.last_scan_ms = Some(now_ms);
            selection
        } else {
            FamilySelection::none()
        };
        let matched = &selection.selected;
        let deselected = &selection.deselected;
        let matched_keys: BTreeSet<String> = matched
            .iter()
            .map(|path| path.display().to_string())
            .collect();

        // 工作集 = 已跟踪（含轮转后待排空的文件）+ 本次新匹配（受 max_files / max_new_files 约束）。
        let mut working: BTreeMap<String, PathBuf> = runtime
            .log_state
            .files
            .iter()
            // 策展人本轮刚取消选择的：**这一轮就停**，不再多读一 tick。
            .filter(|entry| !deselected.contains(&entry.path))
            .map(|entry| (entry.path.clone(), PathBuf::from(&entry.path)))
            .collect();
        // 同一个真实文件只能读一次：目录里可能同时有 `link.log` 和它的真实文件
        // （或两条指向同一 inode 的 symlink），它们是同一批字节 ——
        // 各读一遍就是重复上送（不变量 2）。按真实路径去重，已跟踪的那条优先保留。
        let mut taken_real: BTreeSet<String> = runtime
            .log_state
            .files
            .iter()
            .map(|entry| checkpoint_real_path(entry).to_string())
            .collect();
        let mut new_count = 0usize;
        let mut refused = 0usize;
        for (index, path) in matched.iter().enumerate() {
            let key = path.display().to_string();
            if working.contains_key(&key) {
                continue;
            }
            // 触顶：`max_files` 是**保护**不是节奏，必须如实报出来（有多少没被采）。
            // `max_new_files` 只是每轮节奏，被它挡住的下一轮自然会进来，不算触顶。
            if working.len() >= self.config.max_files {
                refused = matched[index..]
                    .iter()
                    .filter(|candidate| !working.contains_key(&candidate.display().to_string()))
                    .count();
                break;
            }
            if new_count >= self.config.max_new_files {
                break;
            }
            let real = tokio::fs::canonicalize(path)
                .await
                .map(|resolved| resolved.display().to_string())
                .unwrap_or_else(|_| key.clone());
            if !taken_real.insert(real) {
                // 已经有一条在盯这个真实文件（symlink 别名 / 真实文件本身）。
                continue;
            }
            working.insert(key, path.clone());
            new_count += 1;
        }

        if refused > 0 {
            batch.capacity = Some(FamilyCapacity {
                tracked: working.len(),
                max_files: self.config.max_files,
                refused,
            });
        }

        let mut budget = self.config.read_limits;
        for display in working.values() {
            if budget.max_lines == 0 || budget.max_bytes == 0 {
                break;
            }
            if let Err(err) = self
                .read_one_file(
                    runtime,
                    display,
                    first_scan,
                    &mut gate,
                    &mut budget,
                    next_seq,
                    &mut batch,
                )
                .await
            {
                // 一个文件读不了不该拖垮整个文件族：跳过后面的文件继续读，
                // 本轮先把读得到的那些交付 / 提交，再把错误报给上层（下一轮重试这个文件）。
                // 否则一个 000 权限的旧文件会让同目录其它文件永远读不动。
                batch.failure.get_or_insert(err);
            }
        }
        if should_scan {
            prune_family_state(
                &mut runtime.log_state,
                &matched_keys,
                deselected,
                &observed_at,
            );
        }
        batch.withheld = gate.withheld();
        Ok(batch)
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_one_file(
        &self,
        runtime: &mut RuntimeState,
        display: &Path,
        first_scan: bool,
        gate: &mut UplinkGate<'_>,
        budget: &mut ReadLimits,
        next_seq: &mut u64,
        batch: &mut FamilyBatch,
    ) -> io::Result<()> {
        let tracked = checkpoint_for_path(&runtime.log_state, display);
        let current = match inspect_path_async(display).await {
            Ok(current) => current,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if let Some(previous) = tracked.as_ref() {
                    let drained = self
                        .drain_rotated(runtime, previous, gate, budget, next_seq, batch)
                        .await?;
                    // 找不到轮转目标（被删 / 被压缩搬走）：手里那条未封口块按到期封口交出去，
                    // 并把 pending 从 checkpoint 里清掉。不清就成了一个既不会封口、也不会被
                    // `prune_family_state` 清理的死块（«有 pending 就保留»）。
                    if !drained {
                        let display_path = display.display().to_string();
                        if let Some(entry) = runtime
                            .log_state
                            .files
                            .iter_mut()
                            .find(|entry| entry.path == display_path)
                        {
                            let pending = entry.pending_multiline.take();
                            batch
                                .records
                                .extend(records_from_pending(gate, pending, next_seq));
                        }
                    }
                }
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let real_path = tokio::fs::canonicalize(display)
            .await
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| display.display().to_string());
        let startup = if tracked.is_none() && !first_scan {
            // 运行中 / 重启后新出现的文件：从 head 读（停机期间的日志不能整段丢）。
            StartupPosition::Head
        } else {
            self.config.startup_position
        };
        // `decide_resume_async` 用 `path` 字符串判定“同一个文件”。symlink 输入下显示路径
        // （`/var/log/containers/...`）与真实路径（`/var/log/pods/...`）不同，必须把比较基准
        // 换成真实路径，否则每一轮都会被误判成“轮转了”。
        let resume_base = tracked
            .as_ref()
            .map(|previous| PathBuf::from(checkpoint_real_path(previous)))
            .unwrap_or_else(|| PathBuf::from(&real_path));
        let previous_for_resume = tracked.as_ref().map(|previous| {
            let mut clone = previous.clone();
            clone.path = checkpoint_real_path(previous).to_string();
            clone
        });
        let resume = decide_resume_async(
            &resume_base,
            &current,
            previous_for_resume.as_ref(),
            startup,
        )
        .await;
        let mut pending = tracked
            .as_ref()
            .and_then(|entry| entry.pending_multiline.clone());
        if resume.truncated {
            // 截断：旧内容先封口，再从 0 读新内容。
            batch
                .records
                .extend(records_from_pending(gate, pending.take(), next_seq));
            batch.truncated = true;
        }
        if resume.rotated {
            let drained = if let Some(previous) = tracked.as_ref() {
                self.drain_rotated(runtime, previous, gate, budget, next_seq, batch)
                    .await?
            } else {
                false
            };
            // 旧文件找不到（已删 / 已被搬走）：手里那条未封口块按到期封口交出去，
            // 不能因为“轮转了”就跟着丢。同时把旧条目的 checkpoint 摘掉 —— 它的 identity
            // 已经不成立，留着会让新文件以同一个 `path` 再插一条，同一个文件两份
            // checkpoint 会互相打架（`checkpoint_for_path` 只取第一条）。
            if !drained {
                let display_path = display.display().to_string();
                runtime
                    .log_state
                    .files
                    .retain(|entry| entry.path != display_path);
                batch
                    .records
                    .extend(records_from_pending(gate, pending.take(), next_seq));
            }
            // 旧块已随轮转文件 rebind / 封口；当前文件重新开始。
            pending = None;
            batch.rotated = true;
        }
        // 排空旧文件可能已经吃满本轮预算：把当前文件留到下一轮。
        // 但轮转 / 截断时当前文件的起点已经确定是 0，必须把它记下来 —— 否则下一轮它
        // 没有 checkpoint，会被当成「新出现的文件」从 head 读，这中间写入的内容就整段丢了。
        if budget.max_lines == 0 || budget.max_bytes == 0 {
            if resume.rotated || resume.truncated {
                batch.checkpoints.push(FamilyCheckpoint {
                    display_path: display.to_path_buf(),
                    real_path,
                    identity: current,
                    checkpoint_offset: 0,
                    pending_multiline: None,
                });
            }
            return Ok(());
        }

        let limits = ReadLimits {
            max_line_bytes: budget.max_line_bytes,
            max_bytes: budget.max_bytes,
            max_lines: budget.max_lines,
        };
        let read =
            read_from_offset_async(Path::new(&real_path), resume.start_offset, limits).await?;
        let consumed_lines = read.lines.len();
        let consumed_bytes = read
            .committed_end_offset
            .saturating_sub(resume.start_offset);
        batch.truncated_lines += read.truncated_lines;
        let folded = records_from_read(
            gate,
            self.config.multiline_mode,
            &runtime.observed_at,
            display,
            read.lines,
            pending,
            next_seq,
        );
        batch.records.extend(folded.records);
        let mut pending = folded.pending;
        if consumed_lines == 0 && pending_should_flush(pending.as_ref(), &runtime.observed_at) {
            batch
                .records
                .extend(records_from_pending(gate, pending.take(), next_seq));
        }
        batch.checkpoint_offset = batch.checkpoint_offset.max(read.committed_end_offset);
        // 只有**真变了**才写 checkpoint：未变化的位置每 15s 已经有一次全量状态写，
        // 每个 tick 再重写一次 512 条（~200KB / 3s）是纯写放大。
        // `real_path` 变了（symlink 重指）也要写，否则排空会用旧真实路径。
        let unchanged = tracked.as_ref().is_some_and(|previous| {
            previous.checkpoint_offset == read.committed_end_offset
                && previous.pending_multiline == pending
                && checkpoint_real_path(previous) == real_path
        });
        if !unchanged {
            batch.checkpoints.push(FamilyCheckpoint {
                display_path: display.to_path_buf(),
                real_path,
                identity: read.identity,
                checkpoint_offset: read.committed_end_offset,
                pending_multiline: pending,
            });
        }
        budget.max_lines = budget.max_lines.saturating_sub(consumed_lines);
        budget.max_bytes = budget.max_bytes.saturating_sub(consumed_bytes as usize);
        Ok(())
    }

    /// 当前路径被换掉（轮转）或已消失：按旧 checkpoint 的 `real_path` 在**真实目录**里
    /// 找到被改名的旧文件，把它剩下的尾巴读完，并把旧块跟着改名。
    ///
    /// 返回「是否真的找到了旧文件」：找不到时调用方要处理手里的未封口块。
    async fn drain_rotated(
        &self,
        runtime: &mut RuntimeState,
        previous: &TrackedFileCheckpoint,
        gate: &mut UplinkGate<'_>,
        budget: &mut ReadLimits,
        next_seq: &mut u64,
        batch: &mut FamilyBatch,
    ) -> io::Result<bool> {
        let base = PathBuf::from(checkpoint_real_path(previous));
        let Some(rotated_path) = find_rotated_path_async(&base, previous).await? else {
            return Ok(false);
        };
        let mut pending = previous.pending_multiline.clone();
        rebind_pending_source_on_rotate(&mut pending, Path::new(&previous.path), &rotated_path);
        relocate_checkpoint_path(&mut runtime.log_state, previous, &rotated_path);
        let limits = ReadLimits {
            max_line_bytes: budget.max_line_bytes,
            max_bytes: budget.max_bytes,
            max_lines: budget.max_lines,
        };
        let read =
            read_from_offset_async(&rotated_path, previous.checkpoint_offset, limits).await?;
        let consumed_lines = read.lines.len();
        let consumed_bytes = read
            .committed_end_offset
            .saturating_sub(previous.checkpoint_offset);
        batch.truncated_lines += read.truncated_lines;
        let folded = records_from_read(
            gate,
            self.config.multiline_mode,
            &runtime.observed_at,
            &rotated_path,
            read.lines,
            pending,
            next_seq,
        );
        batch.records.extend(folded.records);
        let mut pending = folded.pending;
        if consumed_lines == 0 && pending_should_flush(pending.as_ref(), &runtime.observed_at) {
            batch
                .records
                .extend(records_from_pending(gate, pending.take(), next_seq));
        }
        let rotated_real = tokio::fs::canonicalize(&rotated_path)
            .await
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| rotated_path.display().to_string());
        batch.checkpoint_offset = batch.checkpoint_offset.max(read.committed_end_offset);
        batch.checkpoints.push(FamilyCheckpoint {
            display_path: rotated_path,
            real_path: rotated_real,
            identity: read.identity,
            checkpoint_offset: read.committed_end_offset,
            pending_multiline: pending,
        });
        budget.max_lines = budget.max_lines.saturating_sub(consumed_lines);
        budget.max_bytes = budget.max_bytes.saturating_sub(consumed_bytes as usize);
        Ok(true)
    }

    async fn commit_family_state(
        &self,
        runtime: &mut RuntimeState,
        checkpoints: Vec<FamilyCheckpoint>,
        before: &LogCheckpointState,
    ) -> io::Result<()> {
        for checkpoint in checkpoints {
            upsert_checkpoint_async(
                &mut runtime.log_state,
                &checkpoint.display_path,
                &checkpoint.identity,
                CheckpointUpdate {
                    checkpoint_offset: checkpoint.checkpoint_offset,
                    observed_at: &runtime.observed_at,
                    real_path: &checkpoint.real_path,
                    pending_multiline: checkpoint.pending_multiline.as_ref(),
                    rotated_from_path: None,
                },
            )
            .await;
        }
        // 文件族不使用 input 级 pending（每文件一份）。
        runtime.log_state.pending_multiline = None;
        if &runtime.log_state == before {
            // 位置没动、集合也没变：不重写状态盘。
            // （不这么做时，512 个文件的全量状态每 3s 重写一次 = 数 GB/天的写放大。）
            return Ok(());
        }
        runtime.log_state.updated_at = runtime.observed_at.clone();
        log_checkpoints::store_async(&runtime.checkpoint_path, &runtime.log_state).await
    }
}

struct FamilyCheckpoint {
    display_path: PathBuf,
    real_path: String,
    identity: ObservedFileIdentity,
    checkpoint_offset: u64,
    pending_multiline: Option<PendingMultilineState>,
}

struct FamilyBatch {
    records: Vec<TelemetryRecord>,
    checkpoints: Vec<FamilyCheckpoint>,
    checkpoint_offset: u64,
    truncated_lines: usize,
    rotated: bool,
    truncated: bool,
    withheld: Withheld,
    /// 本轮某个文件读失败（其余文件照常交付 / 提交），由调用方在提交之后抛出。
    failure: Option<io::Error>,
    /// 本轮因 `max_files` 拒绝的新文件（触顶事实）。
    capacity: Option<FamilyCapacity>,
}

impl FamilyBatch {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            checkpoints: Vec::new(),
            checkpoint_offset: 0,
            truncated_lines: 0,
            rotated: false,
            truncated: false,
            withheld: Withheld::default(),
            failure: None,
            capacity: None,
        }
    }
}

/// 旧状态（单文件 input）的 input 级 pending → 迁移到对应文件的 checkpoint。
///
/// 返回**迁移不了**的那一块（对应的文件条目已不存在）：调用方要把它交出去封口，
/// 而不是让它随着本轮 `commit_family_state` 的 `pending_multiline = None` 无声消失。
fn migrate_input_pending_to_files(state: &mut LogCheckpointState) -> Option<PendingMultilineState> {
    let pending = state.pending_multiline.take()?;
    let target = state
        .files
        .iter_mut()
        .find(|entry| entry.path == pending.source_path);
    match target {
        Some(entry) if entry.pending_multiline.is_none() => {
            entry.pending_multiline = Some(pending);
            None
        }
        Some(_) => Some(pending),
        None => Some(pending),
    }
}

/// 清理不再匹配、且已经读完的 checkpoint；未读完的保留 7 天（可能还在等轮转排空）。
fn prune_family_state(
    state: &mut LogCheckpointState,
    matched: &BTreeSet<String>,
    deselected: &BTreeSet<String>,
    observed_at: &str,
) {
    state.files.retain(|entry| {
        if matched.contains(&entry.path) {
            return true;
        }
        // **策展人取消选择**（filters / exclude_globs / target 改了）：立刻停，不排空。
        //
        // 容器日志是持续增长的：靠“排空到 EOF”永远排不完，现场表现就是
        // 「把 namespace 从 filters 里去掉后，那条流还在往里进」。
        // 轮转 / 删除后的旧名字根本不在枚举结果里（不在 deselected 中），
        // 所以它们仍走下面的排空逻辑，W1 的行为不变。
        if deselected.contains(&entry.path) {
            return false;
        }
        // 还有未封口块：它在等空闲封口，不能现在丢。
        if entry.pending_multiline.is_some() {
            return true;
        }
        let fully_read = entry
            .last_size
            .is_some_and(|size| entry.checkpoint_offset >= size);
        if fully_read {
            // rename 轮转后写入者已跟到新文件；旧文件读完即可释放。
            return false;
        }
        !checkpoint_is_stale(entry, observed_at)
    });
}

fn checkpoint_is_stale(entry: &TrackedFileCheckpoint, observed_at: &str) -> bool {
    let Some(last) = entry.last_commit_point_at.as_deref() else {
        return true;
    };
    let Ok(last) =
        time::OffsetDateTime::parse(last, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    let Ok(now) =
        time::OffsetDateTime::parse(observed_at, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    now - last >= time::Duration::days(7)
}

#[cfg(test)]
fn block_on_io<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
