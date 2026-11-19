//! Linux 内核环形缓冲（`/dev/kmsg`）兜底通道。
//!
//! 为什么需要：常驻托管下 stdout/stderr 进 journald，而 journald 自己要落盘。磁盘写满时连
//! journald 都报 `Failed to open system journal: No space left on device`，于是「启动即退出」
//! 那次事故的唯一现场（错误因果链）**一行都没留下**——只能靠时间线反推（issue #47 的 01:41）。
//! 内核环形缓冲不占盘、不依赖任何用户态服务，是那个时刻唯一还写得进去的地方。
//!
//! 取舍：
//! - **只镜像最致命的一类**（`run()` 返回 `Err` 的那条路径），不接日志框架：正常运维日志走
//!   journald（有级别、有轮转、可 grep），kmsg 只负责「事故时留下遗言」。
//! - **panic 不镜像**：panic 的现场仍靠 journald / 落盘日志；这里只补“启动即退出”那一类
//!   （它恰恰是磁盘满时最容易完全无痕的）。
//! - 写失败一律忽略：`/dev/kmsg` 可能不可写（非 root、内核裁剪、容器里没有该设备），而这条
//!   路径本来就是「别的都失败了」的时候，不能因为它再失败一次。
//! - 非 Linux 是空实现：macOS 侧日志落 `/var/log/wist-agentd/`，不依赖系统日志守护进程。

#[cfg(any(target_os = "linux", test))]
use std::io::{self, Write};
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

/// 内核日志级别：3 = `KERN_ERR`。
#[cfg(any(target_os = "linux", test))]
const LOG_LEVEL_ERR: u8 = 3;
/// 单条记录上限。内核 `LOG_LINE_MAX` 是 1024，留出 `<3>program[pid]: ` 前缀的余量。
#[cfg(any(target_os = "linux", test))]
const MAX_RECORD_BYTES: usize = 900;
/// 内核日志字符设备。
#[cfg(target_os = "linux")]
const KMSG_PATH: &str = "/dev/kmsg";

/// 把一段（可能多行的）致命错误镜像到内核环形缓冲。
///
/// 调用点是进程退出前的最后一步；本函数**不会**返回错误，也不会 panic。
pub fn mirror_fatal(program: &str, text: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = write_records(Path::new(KMSG_PATH), program, std::process::id(), text);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // 非 Linux 没有等价物：日志本来就不经过系统日志守护进程。
        let _ = (program, text);
    }
}

/// 逐行写入：一条 `write` = 一条内核记录，前缀带级别与进程身份。
///
/// 多行不合并：内核按 write 划分记录，合在一行里会丢掉可读的换行；而一条长错误拆成多条，
/// 也保证单条超长不会把整段遗言挤掉。
#[cfg(any(target_os = "linux", test))]
fn write_records(path: &Path, program: &str, pid: u32, text: &str) -> io::Result<()> {
    let mut device = std::fs::OpenOptions::new().write(true).open(path)?;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let record = format!(
            "<{LOG_LEVEL_ERR}>{program}[{pid}]: {}\n",
            truncate_on_char_boundary(line, MAX_RECORD_BYTES)
        );
        device.write_all(record.as_bytes())?;
    }
    Ok(())
}

/// 按**字节**截断但不切断 UTF-8 字符（错误链里可能有中文路径）。
#[cfg(any(target_os = "linux", test))]
fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 测试用「设备」：真设备由内核提供，这里用普通文件顶替；离开作用域就删（断言失败也不留垃圾）。
    struct Sink {
        path: PathBuf,
    }

    impl Sink {
        fn new(name: &str) -> Self {
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("duration")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("wist-agentd-kmsg-{name}-{suffix}"));
            std::fs::File::create(&path).expect("create sink");
            Self { path }
        }

        fn write(&self, program: &str, pid: u32, text: &str) -> io::Result<()> {
            write_records(&self.path, program, pid, text)
        }

        fn text(&self) -> String {
            std::fs::read_to_string(&self.path).expect("read records")
        }
    }

    impl Drop for Sink {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// 取记录正文（去掉级别/身份前缀与行尾）。
    fn body(record: &str) -> &str {
        record
            .strip_prefix("<3>wist-agentd[1]: ")
            .expect("prefix")
            .trim_end()
    }

    #[test]
    fn each_line_becomes_one_record_with_level_and_identity() {
        let sink = Sink::new("lines");
        sink.write("wist-agentd", 4242, "boom\ncaused by: disk full\n")
            .expect("write records");

        assert_eq!(
            sink.text(),
            "<3>wist-agentd[4242]: boom\n<3>wist-agentd[4242]: caused by: disk full\n"
        );
    }

    #[test]
    fn blank_and_whitespace_only_lines_are_skipped() {
        let sink = Sink::new("blank");
        sink.write("wist-agentd", 1, "a\n\n\n   \n\t\nb\n")
            .expect("write records");

        assert_eq!(sink.text(), "<3>wist-agentd[1]: a\n<3>wist-agentd[1]: b\n");
    }

    #[test]
    fn an_empty_chain_writes_nothing() {
        // 不该因为在“没有遗言”时也吐一个空记录（dmesg 会多出一行噪声）。
        let sink = Sink::new("empty");
        sink.write("wist-agentd", 1, "").expect("write records");

        assert_eq!(sink.text(), "");
    }

    #[test]
    fn carriage_returns_are_trimmed_and_leading_indent_is_kept() {
        // `display_chain()` 是缩进的多行文本；Windows 风格的 `\r\n` 不该把 `\r` 带进内核记录。
        let sink = Sink::new("crlf");
        sink.write("wist-agentd", 1, "  -> Caused by:\r\ncaused by:\r\n")
            .expect("write records");

        assert_eq!(
            sink.text(),
            "<3>wist-agentd[1]:   -> Caused by:\n<3>wist-agentd[1]: caused by:\n"
        );
    }

    #[test]
    fn a_line_exactly_at_the_limit_is_kept_intact() {
        let sink = Sink::new("exact");
        let line = "a".repeat(MAX_RECORD_BYTES);
        sink.write("wist-agentd", 1, &line).expect("write records");

        assert_eq!(body(&sink.text()), line);
    }

    #[test]
    fn overlong_lines_are_truncated_without_breaking_utf8() {
        let sink = Sink::new("truncate");
        // 每字符 3 字节：截断点会落在字符内部，必须回退到边界。
        let line = "错".repeat(MAX_RECORD_BYTES);
        sink.write("wist-agentd", 1, &line).expect("write records");

        let body = body(&sink.text()).to_string();
        assert!(body.len() <= MAX_RECORD_BYTES, "{}", body.len());
        assert!(body.chars().all(|ch| ch == '错'), "截断必须落在字符边界上");
        assert!(!body.is_empty());
    }

    #[test]
    fn truncate_never_splits_a_character() {
        assert_eq!(truncate_on_char_boundary("short", 900), "short");
        assert_eq!(truncate_on_char_boundary("abcdef", 3), "abc");
        // “错”占 3 字节：4 字节处不是字符边界，回退到 3。
        assert_eq!(truncate_on_char_boundary("错错", 4), "错");
        assert_eq!(truncate_on_char_boundary("错错", 6), "错错");
        assert_eq!(truncate_on_char_boundary("错", 0), "");
    }

    #[test]
    fn a_missing_device_is_an_error_and_mirror_fatal_swallows_it() {
        let missing = std::env::temp_dir().join("wist-agentd-kmsg-missing-dir/record");
        assert!(
            write_records(&missing, "wist-agentd", 1, "boom").is_err(),
            "写不进去要如实报错，由调用方决定忽略"
        );
        // `mirror_fatal` 是退出前的最后一步：设备缺失也不能 panic。
        mirror_fatal("wist-agentd", "boom");
    }
}
