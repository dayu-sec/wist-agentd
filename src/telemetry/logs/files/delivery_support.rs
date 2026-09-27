use std::io;
use std::path::Path;

use wist_contracts::telemetry_record::TelemetryRecord;

use crate::telemetry::buffer::TelemetryBuffer;
use crate::telemetry::spool;
use crate::telemetry::warp_parse::RecordSink;

use super::state_support::DeliveryOutcome;

pub(super) async fn deliver_records<S: RecordSink>(
    sink: &mut S,
    spool_path: &Path,
    in_memory_budget_bytes: usize,
    records: Vec<TelemetryRecord>,
) -> io::Result<DeliveryOutcome> {
    let records_processed = records.len();
    let mut buffer = TelemetryBuffer::new(in_memory_budget_bytes);
    let staged = buffer.stage_all(records);

    let (emitted_directly, spooled, sink_error) = if spool::has_records_async(spool_path).await? {
        // 防御性分支：在当前调用链下**不可达**（`process_once_async` 先回放，成功即清空 spool；
        // 失败则直接返回、根本走不到这里）。保留它是为了「有积压就按序追加」这个不变量 ——
        // 一旦将来有人改了调用顺序（例如先在别处丢掉积压），这里不能默默把顺序搞乱。
        let spooled = spool_pending(spool_path, staged.staged, staged.overflowed).await?;
        (0, spooled, None)
    } else {
        deliver_fresh(sink, spool_path, staged.staged, staged.overflowed).await?
    };

    Ok(DeliveryOutcome {
        records_processed,
        emitted_directly,
        spooled,
        sink_error,
    })
}

/// 已有积压 spool 时：为保序，本批 staged 与 overflowed 全部追加到 spool，不直发。
async fn spool_pending(
    spool_path: &Path,
    staged: Vec<TelemetryRecord>,
    overflowed: Vec<TelemetryRecord>,
) -> io::Result<usize> {
    let mut to_spool = staged;
    to_spool.extend(overflowed);
    let spooled = to_spool.len();
    spool::append_records_async(spool_path, &to_spool).await?;
    Ok(spooled)
}

/// 无积压时：overflowed 先落 spool，staged 尝试直发，直发失败再落 spool。
///
/// 直发失败的原因要**带出去**（第三个返回值）：这一层过去把 sink 错误吞在 `Err(_) => spool` 里，
/// 于是第一次出口失败是完全静默的（只有下一轮的回放失败才会报）。
async fn deliver_fresh<S: RecordSink>(
    sink: &mut S,
    spool_path: &Path,
    staged: Vec<TelemetryRecord>,
    overflowed: Vec<TelemetryRecord>,
) -> io::Result<(usize, usize, Option<String>)> {
    let mut emitted_directly = 0usize;
    let mut spooled = 0usize;
    let mut sink_error = None;

    if !overflowed.is_empty() {
        spooled += overflowed.len();
        spool::append_records_async(spool_path, &overflowed).await?;
    }
    if !staged.is_empty() {
        match sink.write_records(&staged).await {
            Ok(()) => emitted_directly = staged.len(),
            Err(err) => {
                spooled += staged.len();
                let detail = err.to_string();
                // 落盘也失败时，别让**次生错误**盖住根因（出口写失败才是要查的那个）。
                if let Err(spool_err) = spool::append_records_async(spool_path, &staged).await {
                    return Err(io::Error::new(
                        spool_err.kind(),
                        format!(
                            "{spool_err}; while buffering records that failed to send: {detail}"
                        ),
                    ));
                }
                sink_error = Some(detail);
            }
        }
    }

    Ok((emitted_directly, spooled, sink_error))
}

pub(super) async fn replay_spool_if_present<S: RecordSink>(
    sink: &mut S,
    spool_path: &Path,
    batch_size: usize,
) -> io::Result<usize> {
    if !spool::has_records_async(spool_path).await? {
        return Ok(0);
    }

    spool::replay_records_async(spool_path, sink, batch_size).await
}

#[cfg(test)]
mod tests {
    use super::{deliver_records, replay_spool_if_present};
    use crate::telemetry::spool;
    use crate::telemetry::warp_parse::RecordSink;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wist_contracts::telemetry_record::TelemetryRecord;

    #[derive(Default)]
    struct TestSink {
        records: Vec<TelemetryRecord>,
        fail_writes: bool,
    }

    impl RecordSink for TestSink {
        async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
            if self.fail_writes {
                return Err(io::Error::other("sink unavailable"));
            }
            self.records.extend_from_slice(records);
            Ok(())
        }
    }

    fn record(body: &str) -> TelemetryRecord {
        TelemetryRecord::new_log(
            "agent-a".to_string(),
            "2026-04-13T00:00:00Z".to_string(),
            "input-a".to_string(),
            "/tmp/app.log".to_string(),
            body.to_string(),
            0,
            body.len() as u64,
            0,
        )
    }

    fn temp_spool_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-delivery-{name}-{suffix}.ndjson"))
    }

    #[tokio::test]
    async fn deliver_records_emits_directly_when_no_backlog() {
        let spool_path = temp_spool_path("direct");
        let mut sink = TestSink::default();
        let records = vec![record("a"), record("b")];

        let outcome = deliver_records(&mut sink, &spool_path, 4096, records.clone())
            .await
            .expect("deliver");

        assert_eq!(outcome.records_processed, 2);
        assert_eq!(outcome.emitted_directly, 2);
        assert_eq!(outcome.spooled, 0);
        assert_eq!(outcome.sink_error, None, "直发成功就不该有出口失败");
        assert_eq!(sink.records, records);
        assert!(
            !spool::has_records_async(&spool_path)
                .await
                .expect("has records")
        );

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn deliver_records_does_not_report_an_uplink_failure_when_everything_just_overflowed() {
        // 「内存预算溢出 → 转 spool」**不是**出口失败：这一轮根本没试直发。
        // 若实现错写成「overflowed 非空就置 sink_error」，运维会把「单行太大」误读成「目标连不上」。
        let spool_path = temp_spool_path("overflow-only");
        let mut sink = TestSink {
            fail_writes: true,
            ..TestSink::default()
        };

        // 预算比任何一条记录都小 ⇒ 全部 overflowed、staged 为空。
        let outcome = deliver_records(
            &mut sink,
            &spool_path,
            8,
            vec![record("line-1"), record("line-2")],
        )
        .await
        .expect("deliver");

        assert_eq!(outcome.emitted_directly, 0);
        assert_eq!(outcome.spooled, 2);
        assert_eq!(
            outcome.sink_error, None,
            "没试直发就不该报出口失败（溢出 ≠ 目标不可达）"
        );
        assert!(sink.records.is_empty());
        assert_eq!(spool::load_records(&spool_path).expect("load").len(), 2);

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn deliver_records_spools_overflow_when_budget_exceeded() {
        let spool_path = temp_spool_path("overflow");
        let mut sink = TestSink::default();
        let records = vec![record("line-1"), record("line-2"), record("line-3")];

        // 预算 120 → 1 条 staged、2 条 overflowed（与 buffer.rs 的用例一致）。
        let outcome = deliver_records(&mut sink, &spool_path, 120, records)
            .await
            .expect("deliver");

        assert_eq!(outcome.records_processed, 3);
        assert_eq!(outcome.emitted_directly, 1);
        assert_eq!(outcome.spooled, 2);
        assert_eq!(sink.records.len(), 1);
        assert_eq!(spool::load_records(&spool_path).expect("load").len(), 2);

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn deliver_records_spools_everything_when_backlog_exists() {
        let spool_path = temp_spool_path("backlog");
        spool::append_records_async(&spool_path, &[record("backlog")])
            .await
            .expect("seed backlog");

        let mut sink = TestSink::default();
        let outcome = deliver_records(&mut sink, &spool_path, 4096, vec![record("a"), record("b")])
            .await
            .expect("deliver");

        assert_eq!(outcome.emitted_directly, 0);
        assert_eq!(outcome.spooled, 2);
        assert_eq!(
            outcome.sink_error, None,
            "积压路径不直发，所以没有出口失败可言"
        );
        assert!(sink.records.is_empty());
        assert_eq!(spool::load_records(&spool_path).expect("load").len(), 3);

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn deliver_records_spools_staged_when_sink_fails() {
        let spool_path = temp_spool_path("sink-fail");
        let mut sink = TestSink {
            fail_writes: true,
            ..TestSink::default()
        };

        let outcome = deliver_records(&mut sink, &spool_path, 4096, vec![record("a"), record("b")])
            .await
            .expect("deliver");

        assert_eq!(outcome.emitted_directly, 0);
        assert_eq!(outcome.spooled, 2);
        assert_eq!(
            outcome.sink_error.as_deref(),
            Some("sink unavailable"),
            "直发失败的原因必须带出来（否则第一次出口失败完全静默）"
        );
        assert!(sink.records.is_empty());
        assert_eq!(spool::load_records(&spool_path).expect("load").len(), 2);

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn deliver_records_handles_empty_batch() {
        let spool_path = temp_spool_path("empty");
        let mut sink = TestSink::default();

        let outcome = deliver_records(&mut sink, &spool_path, 4096, Vec::new())
            .await
            .expect("deliver");

        assert_eq!(outcome.records_processed, 0);
        assert_eq!(outcome.emitted_directly, 0);
        assert_eq!(outcome.spooled, 0);
        assert!(
            !spool::has_records_async(&spool_path)
                .await
                .expect("has records")
        );

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn replay_spool_returns_zero_when_no_spool() {
        let spool_path = temp_spool_path("replay-none");
        let mut sink = TestSink::default();

        let replayed = replay_spool_if_present(&mut sink, &spool_path, 128)
            .await
            .expect("replay");

        assert_eq!(replayed, 0);
        assert!(sink.records.is_empty());

        let _ = fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn replay_spool_replays_existing_records() {
        let spool_path = temp_spool_path("replay");
        spool::append_records_async(&spool_path, &[record("a"), record("b")])
            .await
            .expect("seed spool");

        let mut sink = TestSink::default();
        let replayed = replay_spool_if_present(&mut sink, &spool_path, 128)
            .await
            .expect("replay");

        assert_eq!(replayed, 2);
        assert_eq!(sink.records.len(), 2);

        let _ = fs::remove_file(&spool_path);
    }
}
