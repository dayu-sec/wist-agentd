//! Durable local spool for structured telemetry records.

#[cfg(test)]
use std::fs;
use std::io;
use std::path::Path;

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::fs::ensure_parent;

use crate::telemetry::warp_parse::RecordSink;

/// 以「只追加」方式打开路径，父目录按需创建；append 与隔离区共用同一份写入约定。
async fn open_append(path: &Path) -> io::Result<File> {
    ensure_parent(path)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

pub async fn append_records_async(path: &Path, records: &[TelemetryRecord]) -> io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }

    let mut file = open_append(path).await?;
    let mut buffer = Vec::new();
    for record in records {
        buffer.clear();
        serde_json::to_writer(&mut buffer, record).map_err(io::Error::other)?;
        buffer.push(b'\n');
        file.write_all(&buffer).await?;
    }
    file.sync_all().await
}

#[cfg(test)]
pub fn append_records(path: &Path, records: &[TelemetryRecord]) -> io::Result<()> {
    block_on_io(append_records_async(path, records))
}

#[cfg(test)]
pub fn load_records(path: &Path) -> io::Result<Vec<TelemetryRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_record_line)
        .collect()
}

/// 文件字节数；文件不存在按 `None` 处理（spool 还没产生数据 = 不存在，不是错误）。
async fn metadata_len(path: &Path) -> io::Result<Option<u64>> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn has_records_async(path: &Path) -> io::Result<bool> {
    Ok(metadata_len(path).await?.is_some_and(|len| len > 0))
}

#[cfg(test)]
pub fn has_records(path: &Path) -> io::Result<bool> {
    block_on_io(has_records_async(path))
}

/// spool 当前字节数；文件不存在视为 0，用于上限（背压）判断。
pub async fn size_async(path: &Path) -> io::Result<u64> {
    Ok(metadata_len(path).await?.unwrap_or_default())
}

#[cfg(test)]
pub fn size(path: &Path) -> io::Result<u64> {
    block_on_io(size_async(path))
}

pub async fn replay_records_async<S: RecordSink>(
    path: &Path,
    sink: &mut S,
    batch_size: usize,
) -> io::Result<usize> {
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };

    let replayed = replay_batches(path, BufReader::new(file), sink, batch_size).await?;
    clear_async(path).await?;
    Ok(replayed)
}

/// 顺序读 spool 并按批交给 sink，返回成功发出的记录数。
///
/// 只有整轮读完后调用方才清空 spool：sink 中途失败时 spool 必须留着，下次重放才有数据。
async fn replay_batches<S: RecordSink>(
    path: &Path,
    mut reader: BufReader<File>,
    sink: &mut S,
    batch_size: usize,
) -> io::Result<usize> {
    let mut batch = Vec::with_capacity(batch_size.max(1));
    let mut line = String::new();
    let mut replayed = 0usize;

    while let Some(record) = next_record(path, &mut reader, &mut line).await? {
        batch.push(record);
        if batch.len() >= batch.capacity() {
            replayed += flush_batch(sink, &mut batch).await?;
        }
    }
    replayed += flush_batch(sink, &mut batch).await?;
    Ok(replayed)
}

/// 取下一条可回放的记录：空行跳过，读不动的行隔离后跳过，`None` 表示读到文件尾。
async fn next_record(
    path: &Path,
    reader: &mut BufReader<File>,
    line: &mut String,
) -> io::Result<Option<TelemetryRecord>> {
    loop {
        line.clear();
        if reader.read_line(line).await? == 0 {
            return Ok(None);
        }
        if line.trim().is_empty() {
            continue;
        }
        // 一行读不动的 JSON 不能让整个输入**永久卡死**：过去它会让回放永远失败、spool 永不清空，
        // 该输入从此既不产出、也报不出新东西（唯一一种“行永不消失”的故障）。
        // 把坏行**隔离**到 `{spool}.ndjson.bad`（留证，不静默丢）后跳过，队列才能继续往前排。
        match parse_record_line(line) {
            Ok(record) => return Ok(Some(record)),
            Err(err) => {
                quarantine_line(path, line).await?;
                log::warn!(
                    "telemetry spool: quarantined an unreadable record from {}: {err}",
                    path.display()
                );
            }
        }
    }
}

/// 把攒好的一批记录交给 sink，成功后清空批次；空批直接跳过（收尾那一批可能是空的）。
async fn flush_batch<S: RecordSink>(
    sink: &mut S,
    batch: &mut Vec<TelemetryRecord>,
) -> io::Result<usize> {
    if batch.is_empty() {
        return Ok(0);
    }
    sink.write_records(batch).await?;
    let flushed = batch.len();
    batch.clear();
    Ok(flushed)
}

/// 把一行读不动的 spool 记录挪到 `{spool}.ndjson.bad`：留证，但不再挡着后面的记录。
///
/// 为什么不是丢掉：这一行可能就是唯一的证据（写入端 bug / 磁盘损坏）。
/// 为什么不直接失败：失败会把整个输入钉死（回放永远不过 → spool 永不清空 → 不再产出）。
async fn quarantine_line(path: &Path, line: &str) -> io::Result<()> {
    let mut file = open_append(&path.with_extension("ndjson.bad")).await?;
    file.write_all(line.as_bytes()).await?;
    if line.ends_with('\n') {
        return Ok(());
    }
    file.write_all(b"\n").await
}

#[cfg(test)]
pub fn replay_records<S: RecordSink>(
    path: &Path,
    sink: &mut S,
    batch_size: usize,
) -> io::Result<usize> {
    block_on_io(replay_records_async(path, sink, batch_size))
}

pub async fn clear_async(path: &Path) -> io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub fn clear(path: &Path) -> io::Result<()> {
    block_on_io(clear_async(path))
}

fn parse_record_line(line: &str) -> io::Result<TelemetryRecord> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    serde_json::from_str::<TelemetryRecord>(trimmed).map_err(io::Error::other)
}

#[cfg(test)]
fn block_on_io<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        append_records, append_records_async, clear, has_records, has_records_async, load_records,
        replay_records, replay_records_async, size,
    };
    use crate::telemetry::warp_parse::RecordSink;
    use wist_contracts::telemetry_record::TelemetryRecord;

    fn temp_file(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-spool-{name}-{suffix}.ndjson"))
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

    fn encoded(record: &TelemetryRecord) -> String {
        serde_json::to_string(record).expect("encode")
    }

    fn bad_path(spool: &Path) -> PathBuf {
        spool.with_extension("ndjson.bad")
    }

    #[test]
    fn append_and_load_round_trip_records() {
        let path = temp_file("round-trip");
        append_records(&path, &[record("a"), record("b")]).expect("append");

        let loaded = load_records(&path).expect("load");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].body, "a");
        assert_eq!(loaded[1].body, "b");
        fs::remove_file(path).ok();
    }

    #[test]
    fn clear_removes_spool_file() {
        let path = temp_file("clear");
        append_records(&path, &[record("a")]).expect("append");

        clear(&path).expect("clear");

        assert!(!path.exists());
    }

    #[test]
    fn size_is_zero_when_missing_and_bytes_when_present() {
        let path = temp_file("size");

        assert_eq!(size(&path).expect("size missing"), 0);

        append_records(&path, &[record("a")]).expect("append");

        assert!(size(&path).expect("size present") > 0);
        fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn append_without_records_is_a_noop_and_creates_no_file() {
        let path = temp_file("append-empty");

        append_records_async(&path, &[])
            .await
            .expect("append empty");

        assert!(!path.exists(), "空批次不该凭空造出 spool 文件");
        assert!(!has_records_async(&path).await.expect("has records"));
        assert_eq!(super::size_async(&path).await.expect("size"), 0);
    }

    #[test]
    fn has_records_is_false_when_spool_is_missing() {
        let path = temp_file("has-records-missing");

        assert!(!has_records(&path).expect("has records missing"));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn replay_missing_spool_reports_nothing_to_do() {
        let path = temp_file("replay-missing");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 8)
            .await
            .expect("replay missing spool");

        assert_eq!(replayed, 0);
        assert!(sink.records.is_empty());
        assert!(!path.exists(), "不存在的 spool 不能被凭空创建");
    }

    #[tokio::test]
    async fn replay_empty_spool_clears_it() {
        let path = temp_file("replay-empty");
        fs::write(&path, "").expect("seed empty");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 4)
            .await
            .expect("replay empty spool");

        assert_eq!(replayed, 0);
        assert!(!path.exists(), "空 spool 也要清掉，否则会一直占着队列");
    }

    #[tokio::test]
    async fn replay_skips_blank_lines() {
        let path = temp_file("replay-blank");
        fs::write(
            &path,
            format!(
                "\n{}\n   \n{}\n\n",
                encoded(&record("a")),
                encoded(&record("b"))
            ),
        )
        .expect("seed");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 8)
            .await
            .expect("replay");

        assert_eq!(replayed, 2, "空行既不算记录，也不该被当成坏行");
        assert_eq!(sink.records.len(), 2);
        assert!(!path.exists());
        assert!(!bad_path(&path).exists(), "空行不该进隔离区");
    }

    #[tokio::test]
    async fn replay_sends_everything_when_batch_size_is_zero() {
        // batch_size 0 会被夹到 1：契约是「至少一批一条」，不是「一条都不发」。
        let path = temp_file("replay-zero-batch");
        fs::write(
            &path,
            format!(
                "{}\n{}\n{}\n",
                encoded(&record("a")),
                encoded(&record("b")),
                encoded(&record("c"))
            ),
        )
        .expect("seed");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 0)
            .await
            .expect("replay");

        assert_eq!(replayed, 3);
        assert_eq!(sink.records.len(), 3);
        assert_eq!(sink.batches, 3, "batch_size 0 等价于逐条发送");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_corrupt_spool_line_is_quarantined_instead_of_wedging_the_input() {
        // 过去：一行坏 JSON 让回放永远失败 ⇒ spool 永不清空 ⇒ 该输入从此既不产出、
        // 也报不出新东西（唯一一种「行永不消失」的故障）。
        // 现在：坏行挪到 `{spool}.ndjson.bad`（留证）后跳过，后面的记录照常发出。
        let path = temp_file("corrupt");
        let good_before = encoded(&record("before"));
        let good_after = encoded(&record("after"));
        fs::write(&path, format!("{good_before}\n{{ not json\n{good_after}\n")).expect("seed");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 128)
            .await
            .expect("replay must not fail on a corrupt line");

        assert_eq!(replayed, 2, "坏行之外的两条要照常发出");
        assert!(sink.records.len() == 2);
        assert!(
            !has_records_async(&path).await.expect("has records"),
            "队列要能排空，否则这个输入被一行坏数据钉死"
        );

        let quarantined = fs::read_to_string(bad_path(&path)).expect("quarantine file");
        assert!(
            quarantined.contains("not json"),
            "坏行要留证：{quarantined:?}"
        );

        fs::remove_file(&path).ok();
        fs::remove_file(bad_path(&path)).ok();
    }

    #[tokio::test]
    async fn quarantine_keeps_earlier_evidence_and_terminates_the_new_line() {
        // 坏行可能没有结尾换行（例如被截断的尾行）：隔离区必须自己补上，
        // 否则下一条证据会和它粘成一行、从此再也分不开。
        let path = temp_file("quarantine-append");
        fs::write(&path, "{ broken tail").expect("seed spool");
        fs::write(bad_path(&path), "{\"earlier\":true}\n").expect("seed evidence");

        let mut sink = TestSink::default();
        let replayed = replay_records_async(&path, &mut sink, 8)
            .await
            .expect("replay");

        assert_eq!(replayed, 0);
        let evidence = fs::read_to_string(bad_path(&path)).expect("quarantine file");
        assert_eq!(
            evidence, "{\"earlier\":true}\n{ broken tail\n",
            "旧证据要留着，新证据要单独成行"
        );

        fs::remove_file(&path).ok();
        fs::remove_file(bad_path(&path)).ok();
    }

    #[test]
    fn replay_records_streams_batches_and_clears_spool_on_success() {
        let path = temp_file("replay");
        append_records(&path, &[record("a"), record("b"), record("c")]).expect("append");
        let mut sink = TestSink::default();

        let replayed = replay_records(&path, &mut sink, 2).expect("replay");

        assert_eq!(replayed, 3);
        assert_eq!(sink.records.len(), 3);
        assert_eq!(sink.batches, 2, "3 条 / 每批 2 条 = 2 批");
        assert!(!has_records(&path).expect("spool presence"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_records_leaves_spool_when_sink_fails() {
        let path = temp_file("replay-fail");
        append_records_async(&path, &[record("a"), record("b"), record("c")])
            .await
            .expect("append");
        let mut sink = TestSink {
            fail_after_batches: Some(1),
            ..Default::default()
        };

        let err = replay_records_async(&path, &mut sink, 2)
            .await
            .expect_err("replay should fail");

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(has_records_async(&path).await.expect("spool presence"));
        fs::remove_file(path).ok();
    }

    #[derive(Default)]
    struct TestSink {
        records: Vec<TelemetryRecord>,
        fail_after_batches: Option<usize>,
        batches: usize,
    }

    impl RecordSink for TestSink {
        async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
            self.batches += 1;
            if self
                .fail_after_batches
                .is_some_and(|limit| self.batches > limit)
            {
                return Err(io::Error::other("sink unavailable"));
            }
            self.records.extend_from_slice(records);
            Ok(())
        }
    }
}
