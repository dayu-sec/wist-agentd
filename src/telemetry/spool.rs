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

pub async fn append_records_async(path: &Path, records: &[TelemetryRecord]) -> io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }

    ensure_parent(path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    for record in records {
        let encoded = serde_json::to_vec(record).map_err(io::Error::other)?;
        file.write_all(&encoded).await?;
        file.write_all(b"\n").await?;
    }
    file.sync_all().await?;
    Ok(())
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

pub async fn has_records_async(path: &Path) -> io::Result<bool> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.len() > 0),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub fn has_records(path: &Path) -> io::Result<bool> {
    block_on_io(has_records_async(path))
}

/// spool 当前字节数；文件不存在视为 0，用于上限（背压）判断。
pub async fn size_async(path: &Path) -> io::Result<u64> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err),
    }
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

    let mut reader = BufReader::new(file);
    let mut replayed = 0usize;
    let mut batch = Vec::with_capacity(batch_size.max(1));
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        // 一行读不动的 JSON 不能让整个输入**永久卡死**：过去它会让回放永远失败、spool 永不清空，
        // 该输入从此既不产出、也报不出新东西（唯一一种“行永不消失”的故障）。
        // 把坏行**隔离**到 `{spool}.ndjson.bad`（留证，不静默丢）后跳过，队列才能继续往前排。
        match parse_record_line(&line) {
            Ok(record) => batch.push(record),
            Err(err) => {
                quarantine_line(path, &line).await?;
                eprintln!(
                    "telemetry spool: quarantined an unreadable record from {}: {err}",
                    path.display()
                );
            }
        }
        if batch.len() >= batch.capacity() {
            sink.write_records(&batch).await?;
            replayed += batch.len();
            batch.clear();
        }
    }

    if !batch.is_empty() {
        sink.write_records(&batch).await?;
        replayed += batch.len();
    }
    clear_async(path).await?;
    Ok(replayed)
}

/// 把一行读不动的 spool 记录挪到 `{spool}.ndjson.bad`：留证，但不再挡着后面的记录。
///
/// 为什么不是丢掉：这一行可能就是唯一的证据（写入端 bug / 磁盘损坏）。
/// 为什么不直接失败：失败会把整个输入钉死（回放永远不过 → spool 永不清空 → 不再产出）。
async fn quarantine_line(path: &Path, line: &str) -> io::Result<()> {
    let bad_path = path.with_extension("ndjson.bad");
    ensure_parent(&bad_path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&bad_path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    if !line.ends_with('\n') {
        file.write_all(b"\n").await?;
    }
    Ok(())
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
    use std::path::PathBuf;
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
    async fn a_corrupt_spool_line_is_quarantined_instead_of_wedging_the_input() {
        // 过去：一行坏 JSON 让回放永远失败 ⇒ spool 永不清空 ⇒ 该输入从此既不产出、
        // 也报不出新东西（唯一一种「行永不消失」的故障）。
        // 现在：坏行挪到 `{spool}.ndjson.bad`（留证）后跳过，后面的记录照常发出。
        let path = temp_file("corrupt");
        let good_before = serde_json::to_string(&record("before")).expect("encode");
        let good_after = serde_json::to_string(&record("after")).expect("encode");
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

        let bad_path = path.with_extension("ndjson.bad");
        let quarantined = fs::read_to_string(&bad_path).expect("quarantine file");
        assert!(
            quarantined.contains("not json"),
            "坏行要留证：{quarantined:?}"
        );

        fs::remove_file(&path).ok();
        fs::remove_file(&bad_path).ok();
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

    #[test]
    fn replay_records_streams_batches_and_clears_spool_on_success() {
        let path = temp_file("replay");
        append_records(&path, &[record("a"), record("b"), record("c")]).expect("append");
        let mut sink = TestSink::default();

        let replayed = replay_records(&path, &mut sink, 2).expect("replay");

        assert_eq!(replayed, 3);
        assert_eq!(sink.records.len(), 3);
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
}
