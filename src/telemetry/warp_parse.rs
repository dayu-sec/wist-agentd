//! Structured record sinks for local `warp-parse` style output.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::agent_config::LogsOutputSection;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use wist_contracts::telemetry_record::{DataFrame, TelemetryRecord};
use wist_shared::fs::ensure_parent;

use crate::telemetry::metrics::samples::VmMetricLine;

pub(crate) trait RecordSink {
    async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()>;
}

impl<T> RecordSink for &mut T
where
    T: RecordSink + ?Sized,
{
    async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
        (**self).write_records(records).await
    }
}

/// 出口写失败的**标记**：把「写出口失败」与「读 / 解析失败」分开。
///
/// 为什么要一个专用类型：上层（daemon）要把两者归到不同失败类（出口失败 vs 处理失败），
/// 而靠错误**文本**嗅探是不行的 —— 文本是给人看的，会被改动。
#[derive(Debug)]
pub(crate) struct UplinkWriteError {
    detail: String,
}

impl std::fmt::Display for UplinkWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for UplinkWriteError {}

/// 把出口错误包成带标记的 `io::Error`。
///
/// **保留 `kind()`**：退避窗口的 `WouldBlock` 等语义不能丢（测试也钉着它）。
fn uplink_write_error(err: io::Error) -> io::Error {
    let detail = err.to_string();
    io::Error::new(err.kind(), UplinkWriteError { detail })
}

/// 若这个错误来自出口写入，取出它的可读原因（含目标地址）。
///
/// 供 daemon 把回放阶段的出口失败也归到出口失败类（而不是含混的「处理失败」）。
pub(crate) fn uplink_write_detail(err: &io::Error) -> Option<&str> {
    err.get_ref()?
        .downcast_ref::<UplinkWriteError>()
        .map(|marker| marker.detail.as_str())
}

#[derive(Debug)]
pub(crate) enum TelemetryRecordSink {
    File(FileRecordSink),
    Tcp(TcpRecordSink),
}

impl RecordSink for TelemetryRecordSink {
    async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
        match self {
            Self::File(sink) => sink.write_records(records).await,
            Self::Tcp(sink) => sink.write_records(records).await,
        }
    }
}

impl TelemetryRecordSink {
    /// `framing` 给了就**覆盖**配置里的值：调用方已经算出「实际必须用哪种分帧」。
    ///
    /// 为什么要能覆盖：分帧合不合法取决于**记录是否可能含多行**（协议 §3：`line` 只适用于
    /// 单行记录），而那取决于本轮采什么（授权工作），不是静态配置能表达全的。
    pub(crate) fn from_logs_output(
        output: &LogsOutputSection,
        framing: Option<TcpFraming>,
    ) -> io::Result<Self> {
        match output.kind.as_str() {
            "file" => Ok(Self::File(FileRecordSink::new(PathBuf::from(
                &output.file.path,
            )))),
            "tcp" => Ok(Self::Tcp(TcpRecordSink::new(
                output.tcp.addr.clone(),
                output.tcp.port,
                match framing {
                    Some(framing) => framing,
                    None => TcpFraming::parse(&output.tcp.framing)?,
                },
            ))),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported telemetry output kind: {other}"),
            )),
        }
    }

    /// 上送一帧指标帧。指标走 TCP uplink，与日志复用同一连接、靠 ` METRICS:` 帧标记区分；
    /// 文件输出仅承载日志（本地调试），不承载指标，返回 Ok 跳过。
    pub(crate) async fn write_metrics(
        &mut self,
        envelope: &DataFrame,
        metrics: &VmMetricLine,
    ) -> io::Result<()> {
        match self {
            Self::File(_) => Ok(()),
            Self::Tcp(sink) => sink.write_metrics(envelope, metrics).await,
        }
    }

    /// 上送一帧事实帧（` OBSFACT:` 标记 + 契约对象 JSON）。
    ///
    /// 与指标**故意不同的一点**：文件输出下指标是静默跳过（本地调试不需要指标），事实则返回
    /// `Err` —— 「事实发不出去」是一个必须被看见的配置错误：数据面上行没开，网关就永远拿不到
    /// 事实（用途推断与资产清单全空），而这种故障在两侧都不显形。
    pub(crate) async fn write_fact(&mut self, envelope: &DataFrame, body: &[u8]) -> io::Result<()> {
        match self {
            Self::File(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fact frames need the data-plane TCP uplink; set [telemetry.logs.output] kind = \"tcp\"",
            )),
            Self::Tcp(sink) => sink.write_fact(envelope, body).await,
        }
    }

    /// 这条 sink 到底**能不能**承载事实帧。
    ///
    /// 事实帧只有数据面 TCP 一条通道；file sink 只承载日志（本地调试）。与 [`Self::write_fact`]
    /// 的 `Err` 不同，这个是给调用方在**发送前**判断用的：生效输出是 file（本机调试）时，
    /// 事实本就不该上送，也就不该走 `write_fact` 的 `Err` 分支 —— 否则正常状态会被报成故障。
    /// （`write_fact` 的 `Err` 保留，作为真正误配时的兜底。）
    pub(crate) fn carries_fact_frames(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// 上送一帧原文发现快照（` DSNAP:` 标记 + `ReportDiscoverySnapshot` JSON）。
    ///
    /// 与事实帧分开标记：原文快照体积大、消费者是 atlas 而非网关，不能让网关的
    /// `agent-facts` 通道误收。file sink 只承载日志，这里静默跳过（由调用方的
    /// `carries_discovery_frames()` 在发送前判断）。
    pub(crate) async fn write_discovery(
        &mut self,
        envelope: &DataFrame,
        body: &[u8],
    ) -> io::Result<()> {
        match self {
            Self::File(_) => Ok(()),
            Self::Tcp(sink) => sink.write_discovery(envelope, body).await,
        }
    }

    pub(crate) fn carries_discovery_frames(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// 上送一帧**调查报告**（` IVSREP: ` 标记 + `Report` JSON）。
    ///
    /// 为什么与事实/快照同一条闸：它是**控制类帧**（小、结构化、消费者是网关自己），
    /// 不是主机日志内容。file sink 只承载日志（本机调试），这里静默跳过 —— 由调用方的
    /// [`Self::carries_investigation_frames`] 在发送前判断（与事实帧同一套写法，
    /// 不让正常状态走 `Err` 被报成故障）。
    pub(crate) async fn write_investigation(
        &mut self,
        envelope: &DataFrame,
        body: &[u8],
    ) -> io::Result<()> {
        match self {
            Self::File(_) => Ok(()),
            Self::Tcp(sink) => sink.write_investigation(envelope, body).await,
        }
    }

    /// 这条 sink 能不能承载调查帧（只有数据面 TCP 能）。
    pub(crate) fn carries_investigation_frames(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

#[derive(Debug, Clone, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(crate) struct FileRecordSink {
    path: PathBuf,
}

impl FileRecordSink {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl RecordSink for FileRecordSink {
    async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        self.write_records_inner(records)
            .await
            .map_err(uplink_write_error)
    }
}

impl FileRecordSink {
    async fn write_records_inner(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
        ensure_parent(&self.path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        for record in records {
            let encoded = serde_json::to_vec(record).map_err(io::Error::other)?;
            file.write_all(&encoded).await?;
            file.write_all(b"\n").await?;
        }
        file.sync_all().await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpFraming {
    Line,
    Len,
}

impl TcpFraming {
    pub(crate) fn parse(raw: &str) -> io::Result<Self> {
        match raw {
            "line" => Ok(Self::Line),
            "len" => Ok(Self::Len),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported tcp framing: {raw}"),
            )),
        }
    }
}

/// TCP 连接超时：避免死网卡/黑洞地址让 tick 永久挂起。
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP 写超时窗口：判的是**没有进展**，不是整次写的时长。
///
/// 为什么必须是「无进展」而不是 `timeout(_, write_all)`：后者会把一个**慢但一直在推进**的
/// 连接当场取消，取消点落在任意字节上，于是线上留下半帧。接收端（wparse 的 `line`/`auto`）
/// 在 EOF 上会把最后一条**没有换行**的残行当成一条完整记录交付 —— 数据面因此看到一条被截断
/// 的 JSON 帧（解析失败 + miss 脏数据）。见 [`finish_in_background`]。
const TCP_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(5);
/// 单次 payload 写（一条连接上的一次写单元）的**总时长**上限。
///
/// 只判「无进展」还不够：对端每 4.9 秒滴 1 字节也能让无进展窗口永不触发，而主循环是
/// **串行**的 —— 卡住等于不采集、不上报、不看控制面。3 秒一拍，一次写超过这个上限本身
/// 就是故障现场：交给后台收尾，本轮按失败落 spool（数据不会丢，重放会补上）。
const TCP_WRITE_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// 写停住后，「把剩下的半帧写完」的上限。
///
/// 只保「不留半帧」，不保「很快」：这一轮已经失败、调用方会把整批落 spool 重放，
/// 收尾慢一点没有代价；把连接直接关掉才是有代价的（接收端会把半帧当记录）。
const TCP_WRITE_FINISH_TIMEOUT: Duration = Duration::from_secs(60);
/// 退避初始时长与上限（失败翻倍、成功重置）。
const TCP_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const TCP_BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub(crate) struct TcpRecordSink {
    target_addr: String,
    framing: TcpFraming,
    stream: Option<TcpStream>,
    /// 退避窗口内不允许再尝试连接的时间点（指数退避）。
    next_attempt_at: Option<Instant>,
    /// 当前退避时长：失败翻倍、成功重置为初始值。
    backoff: Duration,
}

impl TcpRecordSink {
    pub(crate) fn new(addr: String, port: u16, framing: TcpFraming) -> Self {
        Self {
            target_addr: format!("{addr}:{port}"),
            framing,
            stream: None,
            next_attempt_at: None,
            backoff: TCP_BACKOFF_INITIAL,
        }
    }

    fn in_backoff(&self) -> bool {
        self.next_attempt_at.is_some_and(|at| Instant::now() < at)
    }

    fn schedule_backoff(&mut self) {
        self.backoff = self.backoff.saturating_mul(2).min(TCP_BACKOFF_MAX);
        self.next_attempt_at = Some(Instant::now() + self.backoff);
    }

    /// 给出口错误挂上**目标地址**。
    ///
    /// 为什么必须挂：目标现在由控制面下发（见 `agent-uplink-authorization.md`），填错是常见故障；
    /// 而 OS 的 "Connection refused (os error 61)" 只说“连不上”，不说“连谁”——
    /// 运维看到第一行必须能知道是哪个 `host:port`。
    fn tag_target(&self, err: io::Error) -> io::Error {
        io::Error::new(err.kind(), format!("{}: {err}", self.target_addr))
    }

    fn backoff_error(&self) -> io::Error {
        self.tag_target(io::Error::new(
            io::ErrorKind::WouldBlock,
            "tcp uplink in backoff",
        ))
    }

    /// 确保连接可用：无连接则先 connect（带超时）；退避窗口内直接失败交给 spool。
    async fn ensure_connected(&mut self) -> io::Result<()> {
        if self.stream.is_some() {
            return Ok(());
        }
        if self.in_backoff() {
            return Err(self.backoff_error());
        }
        match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&self.target_addr)).await {
            Ok(Ok(stream)) => {
                self.stream = Some(stream);
                self.backoff = TCP_BACKOFF_INITIAL;
                self.next_attempt_at = None;
                Ok(())
            }
            Ok(Err(err)) => {
                self.schedule_backoff();
                Err(self.tag_target(err))
            }
            Err(_) => {
                self.schedule_backoff();
                Err(self.tag_target(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp connect timed out",
                )))
            }
        }
    }

    /// 写一段已分帧的字节到连接；失败时重置连接并进入指数退避，以便下次重连。
    ///
    /// 关键不变量：**这条连接上最后一条数据必须是完整帧**。写停住时不能直接关连接，
    /// 否则线上剩下的半帧会在接收端 EOF 时被当成一条记录（见 [`finish_in_background`]）。
    ///
    /// 例外只有一种：链路真的断了（`PayloadWrite::Failed`）或进程被直接杀掉 —— 那时本端
    /// 已经无法再写，残尾只能由接收端看到；数据本身由 spool 兜住。
    async fn write_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        self.ensure_connected().await?;
        let mut stream = self.stream.take().expect("connected");
        match write_payload_bytes(
            &mut stream,
            payload,
            TCP_WRITE_STALL_TIMEOUT,
            TCP_WRITE_TOTAL_TIMEOUT,
        )
        .await
        {
            PayloadWrite::Complete => {
                self.stream = Some(stream);
                Ok(())
            }
            PayloadWrite::Failed(err) => {
                self.schedule_backoff();
                Err(self.tag_target(err))
            }
            PayloadWrite::Stalled { written } => {
                self.schedule_backoff();
                if written < payload.len() {
                    // 线上已经有半帧：交给后台把剩余字节写完再关。绝不在这里直接关。
                    finish_in_background(stream, payload[written..].to_vec());
                }
                // `written == 0`：一个字节都没出去，直接关是干净的（走 drop）。
                Err(self.tag_target(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp write stalled (no progress)",
                )))
            }
        }
    }

    /// 写入一帧指标帧（` METRICS: ` 标记 + 结构化 JSON 正文）。
    pub(crate) async fn write_metrics(
        &mut self,
        envelope: &DataFrame,
        metrics: &VmMetricLine,
    ) -> io::Result<()> {
        let frame = build_metrics_frame(envelope, metrics)?;
        self.write_payload(&build_payload_bytes(&frame, self.framing))
            .await
    }

    /// 写入一帧事实帧（` OBSFACT: ` 标记 + 契约对象 JSON 正文）。
    pub(crate) async fn write_fact(&mut self, envelope: &DataFrame, body: &[u8]) -> io::Result<()> {
        let frame = build_fact_frame(envelope, body)?;
        self.write_payload(&build_payload_bytes(&frame, self.framing))
            .await
    }

    /// 写入一帧原文发现快照（` DSNAP: ` 标记 + 契约对象 JSON 正文）。
    pub(crate) async fn write_discovery(
        &mut self,
        envelope: &DataFrame,
        body: &[u8],
    ) -> io::Result<()> {
        let frame = build_discovery_frame(envelope, body)?;
        self.write_payload(&build_payload_bytes(&frame, self.framing))
            .await
    }

    /// 写入一帧调查报告（` IVSREP: ` 标记 + `Report` JSON 正文）。
    pub(crate) async fn write_investigation(
        &mut self,
        envelope: &DataFrame,
        body: &[u8],
    ) -> io::Result<()> {
        let frame = build_investigation_frame(envelope, body)?;
        self.write_payload(&build_payload_bytes(&frame, self.framing))
            .await
    }

    /// 测试用：缩短退避窗口，避免真实等待默认的 1s。
    #[cfg(test)]
    fn with_backoff(mut self, initial: Duration) -> Self {
        self.backoff = initial;
        self
    }
}

impl RecordSink for TcpRecordSink {
    async fn write_records(&mut self, records: &[TelemetryRecord]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let mut payload = Vec::new();
        for record in records {
            let frame = build_record_frame(record)?;
            payload.extend_from_slice(&build_payload_bytes(&frame, self.framing));
        }

        self.write_payload(&payload)
            .await
            .map_err(uplink_write_error)
    }
}

/// 一次 payload 写的结局。
#[derive(Debug)]
enum PayloadWrite {
    /// 全部写入（含下层的 flush）。
    Complete,
    /// 我们不再等了（`stall` 窗口内无进展，或总时长用尽）；`written` 字节已经在线上。
    Stalled { written: usize },
    /// 连接出错；出错前可能已有部分字节在线上，而错误后的连接已不可再写。
    ///
    /// 这种残尾**没法在本端收尾**（socket 已经坏了），接收端仍可能在 EOF 上把它当一条记录。
    /// 数据本身由 spool 兜住，这里只是如实区分「我们主动不等了」与「链路断了」。
    Failed(io::Error),
}

/// 把 `payload` 写进 `stream`：`stall` 管「多久没进展就算停住」，`total` 管「这次写最多占多久」。
///
/// 两个上限都要：只有 `stall` 时，对端慢慢滴数据可以无限拖住串行的主循环；
/// 只有 `total` 时，慢但对端一直在推进的连接会被误杀（就是本 issue 的半帧来源）。
///
/// 逐次 `write`（而不是 `write_all`）是为了在停住时**知道已经出去了多少字节** ——
/// 收尾只需要写剩下的部分，不必重发、也不会把重复的字节拼进帧里。
async fn write_payload_bytes<S>(
    stream: &mut S,
    payload: &[u8],
    stall: Duration,
    total: Duration,
) -> PayloadWrite
where
    S: AsyncWrite + Unpin,
{
    let deadline = Instant::now() + total;
    let mut written = 0usize;
    while written < payload.len() {
        let now = Instant::now();
        if now >= deadline {
            return PayloadWrite::Stalled { written };
        }
        let window = stall.min(deadline - now);
        match timeout(window, stream.write(&payload[written..])).await {
            Ok(Ok(0)) => {
                return PayloadWrite::Failed(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tcp write accepted zero bytes",
                ));
            }
            Ok(Ok(written_now)) => written += written_now,
            Ok(Err(err)) => return PayloadWrite::Failed(err),
            Err(_) => return PayloadWrite::Stalled { written },
        }
    }
    match stream.flush().await {
        Ok(()) => PayloadWrite::Complete,
        Err(err) => PayloadWrite::Failed(err),
    }
}

/// 把「已经写了半截」的剩余字节写完再关连接。
///
/// 为什么必须有：接收端在 EOF 上会把最后一条**没有换行**的残行交付成一条记录
/// （wparse `line` / `auto` 的 tail-line 语义）。所以这条连接的最后一条数据必须是完整帧；
/// 写停住时若直接关闭，数据面就会收到一条**截断的 JSON 帧**，现象就是 miss 里出现半条报文
/// （`{"schema":"v1","agent":"..."` 这类截在信封中间的脏数据）。
///
/// 为什么放后台而不是这里 await：这一轮已经失败（调用方会把整批落 spool，下一轮重放），
/// 但半帧不能就这么留在线上；进度等不起，收尾可以慢慢来。
///
/// 剩余字节写不完（对端真的死了）时只能如实告警：那种情况下没有数据面侧能做的事，
/// 数据本身也已经由 spool 兜住。
fn finish_in_background<S>(mut stream: S, rest: Vec<u8>)
where
    S: AsyncWrite + Send + Unpin + 'static,
{
    // 拿不到 runtime（进程正在退出）时不 spawn：`tokio::spawn` 在无上下文时会 panic，
    // 而这条路径本身就是「尽力而为」，宁可留下半帧也不能让收尾把进程带崩。
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::warn!("uplink: no runtime available to finish a stalled frame");
        return;
    };
    handle.spawn(async move {
        match timeout(TCP_WRITE_FINISH_TIMEOUT, stream.write_all(&rest)).await {
            Ok(Ok(())) => {
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            }
            Ok(Err(err)) => log::warn!(
                "uplink: failed to finish a stalled frame; the peer may see a truncated tail: {err}"
            ),
            Err(_) => log::warn!(
                "uplink: gave up finishing a stalled frame after {}s; the peer may see a truncated tail",
                TCP_WRITE_FINISH_TIMEOUT.as_secs()
            ),
        }
    });
}

/// TCP 上送帧：结构化信封（不含原文）与 `LOGRAW:` 原始行分离，避免把 raw 塞进 JSON。
///
/// `{envelope} LOGRAW: <body>`，其中 envelope 只承载通用字段（`schema`/`agent`/`ts`/`seq`，短名），
/// body 保持原文、不转义，供数据面审计核对与回放。来源细节（`input`/路径/偏移）不进帧。
fn build_record_frame(record: &TelemetryRecord) -> io::Result<Vec<u8>> {
    let envelope = DataFrame::from(record);
    let mut frame = serde_json::to_vec(&envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    // LOGRAW: 后跟一个空格分隔帧标记与原文，保证原文从正文首字符开始、不带标记前缀。
    frame.extend_from_slice(b" LOGRAW: ");
    frame.extend_from_slice(record.body.as_bytes());
    Ok(frame)
}

/// TCP 指标帧：与日志帧共用 `DataFrame` 信封，但帧标记为 ` METRICS: `，正文是 VM JSON line。
///
/// `{envelope} METRICS: {"metric":{...},"value":<number>}`；信封 `seq` 参与 `(agent, seq)` 去重/查缺。
fn build_metrics_frame(envelope: &DataFrame, metrics: &VmMetricLine) -> io::Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    frame.extend_from_slice(b" METRICS: ");
    let body = serde_json::to_vec(metrics)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// TCP 事实帧：与日志/指标共用 `DataFrame` 信封，帧标记为 ` OBSFACT: `，正文是**契约对象原样**
/// （`ReportAgentFactSummary` 的 JSON 字节）。
///
/// 为什么正文由调用方给字节、不在这里重建：它必须与 `wist-contracts` 的类型表达同一件事，
/// 而「谁负责构造契约对象」只应有一处（daemon 侧）。这里只做分帧 —— 与指标帧同一个道理，
/// 只是指标那侧顺手把序列化也放进来了。
fn build_fact_frame(envelope: &DataFrame, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    frame.extend_from_slice(b" OBSFACT: ");
    frame.extend_from_slice(body);
    Ok(frame)
}

/// TCP 原文发现快照帧：与事实帧同构，但帧标记为 ` DSNAP: `，正文是
/// `ReportDiscoverySnapshot`（`kind = report_discovery_snapshot`）的 JSON。
fn build_discovery_frame(envelope: &DataFrame, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    frame.extend_from_slice(b" DSNAP: ");
    frame.extend_from_slice(body);
    Ok(frame)
}

/// TCP 调查报告帧：与事实/快照帧同构，但帧标记为 ` IVSREP: `（investigation report），
/// 正文是 `wist-agentd investigate` 的 `Report` JSON（含 `command_id`，与控制面 ack 关联）。
///
/// 为什么单开一个标记而不是复用 `OBSFACT`：两者的**消费者与保留策略不同** —— 事实是资产
/// 清单的原料（可长期留），调查是某次提问的证据（含路径/文件名，通常短期保留）。
/// 混在一个标记里，数据面只能用同一条 sink 规则，等于把两者的保留期与可见性绑死。
fn build_investigation_frame(envelope: &DataFrame, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    frame.extend_from_slice(b" IVSREP: ");
    frame.extend_from_slice(body);
    Ok(frame)
}

fn build_payload_bytes(data: &[u8], framing: TcpFraming) -> Vec<u8> {
    match framing {
        TcpFraming::Line => {
            if data.last() == Some(&b'\n') {
                data.to_vec()
            } else {
                let mut buf = Vec::with_capacity(data.len() + 1);
                buf.extend_from_slice(data);
                buf.push(b'\n');
                buf
            }
        }
        TcpFraming::Len => {
            let mut buf = Vec::with_capacity(16 + data.len());
            buf.extend_from_slice(data.len().to_string().as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(data);
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    use super::{
        FileRecordSink, RecordSink, TCP_BACKOFF_INITIAL, TCP_BACKOFF_MAX, TcpFraming,
        TcpRecordSink, build_payload_bytes,
    };

    use crate::telemetry::metrics::samples::{VmMetricLabels, VmMetricLine};
    use wist_contracts::telemetry_record::{DataFrame, TelemetryRecord};

    fn record(body: &str) -> TelemetryRecord {
        TelemetryRecord::new_log(
            "agent-a".to_string(),
            "2026-04-14T00:00:00Z".to_string(),
            "input-a".to_string(),
            "/tmp/app.log".to_string(),
            body.to_string(),
            0,
            body.len() as u64,
            0,
        )
    }

    fn temp_file(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-warp-parse-{name}-{suffix}.ndjson"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_record_sink_writes_ndjson() {
        let path = temp_file("file-sink");
        let mut sink = FileRecordSink::new(path.clone());

        sink.write_records(&[record("a"), record("b")])
            .await
            .expect("write records");

        let written = fs::read_to_string(&path).expect("read output");
        assert!(written.contains("\"body\":\"a\""));
        assert!(written.contains("\"body\":\"b\""));
        fs::remove_file(path).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_record_sink_sends_envelope_and_raw_frame() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.expect("read");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Line);

        sink.write_records(&[record("line-a"), record("line-b")])
            .await
            .expect("write records");

        let body = server.await.expect("join");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let (envelope, raw) = line.split_once(" LOGRAW: ").expect("LOGRAW marker");
            assert!(envelope.starts_with('{'), "envelope json: {envelope}");
            assert!(envelope.contains("\"agent\":\"agent-a\""));
            assert!(
                !envelope.contains("\"body\""),
                "raw must not be in envelope"
            );
            assert!(raw.starts_with("line-"), "raw body: {raw}");
        }
    }

    /// 拿一个“确定会拒连”的端口。
    ///
    /// 不能直接用 `bind(127.0.0.1:0)` 再 drop：拿到的 ephemeral 端口会在 drop 之后
    /// **被内核再次分配**给别人（同一轮测试里另一个 bind、或机器上任何新连接），
    /// 于是 connect 有时会成功 —— 这就是这个用例偶发失败的原因。
    ///
    /// 这里改用 **ephemeral 段之外**的固定端口（Linux 典型 32768-60999，macOS 49152-65535）：
    /// 内核不会自动分配它们，drop 之后只有显式 bind 才能占到，概率可以忽略。
    async fn closed_port() -> u16 {
        // 取几不在两个平台的 ephemeral 区间里的值；绑不上（被真实服务占用）就换下一个。
        for candidate in [29_417u16, 29_531, 29_611] {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", candidate)).await {
                let port = listener.local_addr().expect("addr").port();
                drop(listener);
                return port;
            }
        }
        // 极端环境下全部被占：退回 ephemeral（接受极小概率的竞态，不让用例直接失败）。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_sink_backs_off_after_connect_failure() {
        let port = closed_port().await;
        // 测试用缩短退避窗口，避免真实等待 1s。
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Line)
            .with_backoff(Duration::from_millis(10));

        // 第一次 connect 失败，进入退避（10ms → 20ms）。
        let err = sink
            .write_records(&[record("a")])
            .await
            .expect_err("connect refused");
        // 错误必须挂上**目标地址**：OS 只说“连不上”，不说“连谁”；
        // 而目标现在由控制面下发，运维看到第一行就得知道是哪个 `host:port`。
        assert!(
            err.to_string().contains(&format!("127.0.0.1:{port}:")),
            "出口错误必须带目标地址：{err}"
        );

        // 退避窗口内：快速返回 WouldBlock，不再尝试 connect；同样带目标。
        let err = sink
            .write_records(&[record("b")])
            .await
            .expect_err("backoff");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(
            err.to_string().contains(&format!("127.0.0.1:{port}:")),
            "退避错误也要能看出目标：{err}"
        );

        // 越过退避窗口：重新尝试 connect（仍失败，退避翻倍到 40ms）。
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(sink.write_records(&[record("c")]).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_sink_backoff_doubles_and_caps() {
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), 1, TcpFraming::Line);

        // 1s → 2s → 4s → 8s → 16s → 30s（封顶）。
        let mut expected = TCP_BACKOFF_INITIAL;
        for _ in 0..5 {
            sink.schedule_backoff();
            expected = expected.saturating_mul(2).min(TCP_BACKOFF_MAX);
            assert_eq!(sink.backoff, expected);
        }

        // 已封顶：继续失败不再增长。
        let capped = sink.backoff;
        assert_eq!(capped, TCP_BACKOFF_MAX);
        sink.schedule_backoff();
        assert_eq!(sink.backoff, capped);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_sink_resets_backoff_on_successful_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept");
            // 保持连接一小段时间，确保客户端 connect + write 完成。
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Line);
        // 直接置为非初始退避态（窗口已过期），模拟之前失败过。
        sink.backoff = TCP_BACKOFF_MAX;
        sink.next_attempt_at = Some(Instant::now() - Duration::from_secs(1));

        sink.write_records(&[record("a")]).await.expect("write");

        // 成功连接后：退避重置为初始值、退避窗口清除。
        assert_eq!(sink.backoff, TCP_BACKOFF_INITIAL);
        assert!(sink.next_attempt_at.is_none());
        server.await.expect("server");
    }

    /// 写停住时，报告的是**真正到过对端的字节数**（不是「全写了」也不是「一点没写」）。
    ///
    /// 这个数字是收尾的唯一依据：多算会把重复字节拼进帧，少算会丢字节。
    #[tokio::test(flavor = "current_thread")]
    async fn stalled_write_reports_the_bytes_that_reached_the_peer() {
        // `duplex(64)`：写满 64 字节后不再有进展，可确定性地触发「停住」。
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let payload = vec![b'a'; 1024];

        let outcome = super::write_payload_bytes(
            &mut writer,
            &payload,
            Duration::from_millis(20),
            Duration::from_secs(5),
        )
        .await;

        let written = match outcome {
            super::PayloadWrite::Stalled { written } => written,
            other => panic!("expected a stall, got {other:?}"),
        };
        assert!(
            written > 0 && written < payload.len(),
            "must report a partial write, got {written}"
        );

        let mut got = vec![0u8; written];
        reader.read_exact(&mut got).await.expect("read prefix");
        assert_eq!(
            got,
            payload[..written],
            "reported bytes must match what the peer got"
        );
    }

    /// 停住之后必须把剩余字节写完再关：对端最终拿到的是**完整帧**，而不是半条。
    ///
    /// 这就是 issue #34 的要害：wparse 在 EOF 上会把最后一条无换行的残行当记录交付，
    /// 半帧会变成 miss 里的一条截断 JSON。
    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_frame_is_finished_before_the_stream_closes() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let payload = vec![b'f'; 4096];

        let stalled = super::write_payload_bytes(
            &mut writer,
            &payload,
            Duration::from_millis(20),
            Duration::from_secs(5),
        )
        .await;
        let written = match stalled {
            super::PayloadWrite::Stalled { written } => written,
            other => panic!("expected a stall, got {other:?}"),
        };

        super::finish_in_background(writer, payload[written..].to_vec());

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut got))
            .await
            .expect("background finish must not hang")
            .expect("read to end");
        assert_eq!(
            got, payload,
            "the peer must end up with the whole frame, not a truncated tail"
        );
    }

    /// 总时长上限必须能单独生效：否则「对端每 4.9 秒收 1 字节」能把串行的主循环无限拖住
    /// （无进展窗口永远不触发）。
    #[tokio::test(flavor = "current_thread")]
    async fn the_total_budget_caps_a_write_before_the_stall_window_would() {
        // `duplex(1)`：只能收下 1 字节，之后无进展；无进展窗口故意设成 30s，只有总预算能做主。
        let (mut writer, _reader) = tokio::io::duplex(1);
        let payload = vec![b'z'; 1024];

        let outcome = super::write_payload_bytes(
            &mut writer,
            &payload,
            Duration::from_secs(30),
            Duration::from_millis(50),
        )
        .await;

        match outcome {
            super::PayloadWrite::Stalled { written } => assert_eq!(
                written, 1,
                "the total budget must cut the write and keep the progress count"
            ),
            other => panic!("expected the total budget to cut the write, got {other:?}"),
        }
    }

    #[test]
    fn record_frame_keeps_raw_outside_json_envelope() {
        let frame = super::build_record_frame(&record("raw 行内容")).expect("build frame");
        let text = String::from_utf8_lossy(&frame);
        let (envelope, raw) = text.split_once(" LOGRAW: ").expect("LOGRAW marker");
        let parsed: serde_json::Value = serde_json::from_str(envelope).expect("valid envelope");
        assert_eq!(parsed["schema"], "v1");
        assert_eq!(parsed["agent"], "agent-a");
        assert_eq!(parsed["ts"], "2026-04-14T00:00:00Z");
        assert_eq!(parsed["seq"], 0);
        assert!(parsed.get("body").is_none(), "raw must not be in envelope");
        assert!(
            parsed.get("input_id").is_none(),
            "input_id must not be in envelope"
        );
        assert!(
            parsed.get("signal_kind").is_none(),
            "signal_kind must not be in envelope"
        );
        assert_eq!(raw, "raw 行内容");
    }

    #[test]
    fn payload_builder_matches_line_and_len_contract() {
        assert_eq!(build_payload_bytes(b"abc", TcpFraming::Line), b"abc\n");
        assert_eq!(build_payload_bytes(b"hello", TcpFraming::Len), b"5 hello");
    }

    #[test]
    fn metrics_frame_uses_metrics_marker_with_json_body() {
        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 42);
        let metrics = VmMetricLine {
            metric: VmMetricLabels {
                name: "system.load_average.1m".to_string(),
                agent: "agent-001".to_string(),
                kind: "host_metrics".to_string(),
                target_ref: "host-1:host".to_string(),
                resource_ref: Some("host-1".to_string()),
                unit: "1".to_string(),
                mount: None,
                fstype: None,
            },
            values: vec![0.25],
            timestamps: vec![1_234_567_890_000],
        };

        let frame = super::build_metrics_frame(&envelope, &metrics).expect("build frame");
        let text = String::from_utf8_lossy(&frame);
        let (env, body) = text.split_once(" METRICS: ").expect("METRICS marker");

        let parsed_env: serde_json::Value = serde_json::from_str(env).expect("valid envelope");
        assert_eq!(parsed_env["agent"], "agent-001");
        assert_eq!(parsed_env["seq"], 42);
        assert!(
            parsed_env.get("kind").is_none(),
            "envelope stays signal-agnostic"
        );

        let parsed_body: serde_json::Value = serde_json::from_str(body).expect("valid metrics");
        assert_eq!(parsed_body["metric"]["__name__"], "system.load_average.1m");
        assert_eq!(parsed_body["metric"]["agent"], "agent-001");
        assert_eq!(parsed_body["metric"]["kind"], "host_metrics");
        assert_eq!(parsed_body["values"][0], 0.25);
        assert_eq!(parsed_body["timestamps"][0], 1_234_567_890_000_i64);
    }

    #[test]
    fn discovery_frame_uses_dsnap_marker_and_keeps_body() {
        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 43);
        let body = br#"{"api_version":"v1","kind":"report_discovery_snapshot"}"#;

        let frame = super::build_discovery_frame(&envelope, body).expect("build frame");
        let text = String::from_utf8_lossy(&frame);
        let (env, parsed_body) = text.split_once(" DSNAP: ").expect("DSNAP marker");

        let parsed_env: serde_json::Value = serde_json::from_str(env).expect("valid envelope");
        assert_eq!(parsed_env["agent"], "agent-001");
        assert_eq!(parsed_env["seq"], 43);
        assert_eq!(parsed_body, String::from_utf8_lossy(body));
    }

    #[test]
    fn investigation_frame_uses_ivsrep_marker_and_keeps_body() {
        let envelope = DataFrame::new("agent-001", "2026-10-30T00:00:00Z", 44);
        let body = br#"{"command":"investigate","topic":"disk","command_id":"cmd_1"}"#;

        let frame = super::build_investigation_frame(&envelope, body).expect("build frame");
        let text = String::from_utf8_lossy(&frame);
        let (env, parsed_body) = text.split_once(" IVSREP: ").expect("IVSREP marker");

        let parsed_env: serde_json::Value = serde_json::from_str(env).expect("valid envelope");
        assert_eq!(parsed_env["agent"], "agent-001");
        assert_eq!(parsed_env["seq"], 44);
        assert_eq!(parsed_body, String::from_utf8_lossy(body));
        // 不许蹭别的帧标记：数据面按标记分 sink，串台会把报告写进日志/事实的保留策略里。
        for other in [" LOGRAW: ", " METRICS: ", " OBSFACT: ", " DSNAP: "] {
            assert!(!text.contains(other), "must not carry {other}: {text}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn only_the_tcp_sink_carries_investigation_frames() {
        let file = super::TelemetryRecordSink::File(super::FileRecordSink::new(
            std::path::PathBuf::from("/tmp/wist-agentd-investigation-sink.ndjson"),
        ));
        assert!(!file.carries_investigation_frames());
        // 与事实帧同一道闸：两者都是控制类帧，只走 TCP。
        assert_eq!(
            file.carries_fact_frames(),
            file.carries_investigation_frames()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_record_sink_writes_discovery_frame() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        // 收满一帧即返回：sink 会把连接留着复用，读 EOF 会挂到测试结束。
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut body = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = socket.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
                if body.contains(&b'\n') {
                    break;
                }
            }
            body
        });
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Line);

        // 正文故意超过单次读缓冲：分帧只能依赖标记与结尾换行，不能假设「一次 write 一个包」。
        let payload = format!(
            r#"{{"kind":"report_discovery_snapshot","pad":"{}"}}"#,
            "x".repeat(20_000)
        );
        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 11);
        sink.write_discovery(&envelope, payload.as_bytes())
            .await
            .expect("write discovery");

        let body = server.await.expect("join");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.ends_with('\n'),
            "line framing must terminate the frame"
        );
        assert!(
            !text.ends_with("\n\n"),
            "only one trailing newline (a second one would be an empty record)"
        );
        assert_eq!(text.matches(" DSNAP: ").count(), 1, "exactly one marker");

        let (env, parsed) = text
            .trim_end_matches('\n')
            .split_once(" DSNAP: ")
            .expect("DSNAP marker");
        let parsed_env: serde_json::Value = serde_json::from_str(env).expect("valid envelope");
        assert_eq!(parsed_env["agent"], "agent-001");
        assert_eq!(parsed_env["seq"], 11);
        // 正文必须字节级不变：适配器按契约解，中间任何重编码都是隐患。
        assert_eq!(parsed, payload);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_record_sink_len_framing_prefixes_the_discovery_frame_length() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut body = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = socket.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
                // 头是「<len> <frame>」；这里只等到拿全头 + 长度足够。
                let text = String::from_utf8_lossy(&body);
                if let Some((len, rest)) = text.split_once(' ')
                    && let Ok(len) = len.parse::<usize>()
                    && rest.len() >= len
                {
                    break;
                }
            }
            body
        });
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Len);
        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 12);

        sink.write_discovery(&envelope, br#"{"kind":"report_discovery_snapshot"}"#)
            .await
            .expect("write discovery");

        let body = server.await.expect("join");
        let text = String::from_utf8_lossy(&body);
        let (len, frame) = text.split_once(' ').expect("length prefix");
        let len: usize = len.parse().expect("numeric length");
        assert_eq!(len, frame.len(), "length must describe the frame bytes");
        assert!(frame.contains(" DSNAP: "), "frame: {frame}");
        assert!(
            !frame.ends_with('\n'),
            "len framing carries the frame verbatim, no trailing newline"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_sink_swallows_discovery_frames() {
        // file sink 只承载日志记录。发现快照必须显式不可用，否则它会被静默写进
        // 日志文件（到那时没人会去那里找资产，体积还白担）。
        let path = temp_file("discovery-file-sink");
        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 3);
        let body = br#"{"kind":"report_discovery_snapshot"}"#;

        let mut sink = super::TelemetryRecordSink::File(FileRecordSink::new(path.clone()));
        assert!(
            !sink.carries_discovery_frames(),
            "file sink only carries logs"
        );
        sink.write_discovery(&envelope, body)
            .await
            .expect("file sink must swallow the frame");
        assert!(
            !path.exists(),
            "file sink must not create a file for a discovery frame"
        );

        let tcp_sink = TcpRecordSink::new("127.0.0.1".to_string(), 9, TcpFraming::Line);
        let tcp = super::TelemetryRecordSink::Tcp(tcp_sink);
        assert!(tcp.carries_discovery_frames());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_record_sink_writes_metrics_frame() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.expect("read");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut sink = TcpRecordSink::new("127.0.0.1".to_string(), port, TcpFraming::Line);

        let envelope = DataFrame::new("agent-001", "2026-04-14T00:00:00Z", 7);
        let metrics = VmMetricLine {
            metric: VmMetricLabels {
                name: "system.load_average.1m".to_string(),
                agent: "agent-001".to_string(),
                kind: "host_metrics".to_string(),
                target_ref: "host-1:host".to_string(),
                resource_ref: Some("host-1".to_string()),
                unit: "1".to_string(),
                mount: None,
                fstype: None,
            },
            values: vec![0.25],
            timestamps: vec![1_234_567_890_000],
        };

        sink.write_metrics(&envelope, &metrics)
            .await
            .expect("write metrics");

        let body = server.await.expect("join");
        assert!(body.contains(" METRICS: "), "frame: {body}");
        assert!(body.contains("\"agent\":\"agent-001\""), "frame: {body}");
        assert!(
            body.contains("\"__name__\":\"system.load_average.1m\""),
            "frame: {body}"
        );
    }
}
