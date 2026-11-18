//! 云实例身份：从云厂商的**元数据服务**读 `instance-id`。
//!
//! ## 为什么需要它
//!
//! 同一台云主机会被两个来源报到 atlas：agentd（本机发现）和云 API（wist-harvest）。
//! 两者给的外部 ID 完全不同（agentd 是本机 `machine_id`/hostname，云侧是 `InstanceId`），
//! 不建立关联就会在拓扑里变成**两个节点**。
//!
//! 元数据服务的 `instance-id` 是**机器自己声明"我是哪个云实例"**，是所有关联证据里
//! 唯一确定性的一类。没有它，只能退化到「私网 IP + 子网」这种会被 IP 回收误导的弱证据。
//!
//! ## 为什么不用 HTTP 客户端
//!
//! - 这些端点全是**固定私有地址**（不需要 DNS，也不需要 TLS），元数据服务一定在链路上；
//! - `discovery` 的探针是**同步** `refresh()`，而工程里的 `reqwest` 是异步的；
//!   `reqwest::blocking` 在 tokio runtime 里会 panic（"cannot block within runtime"），
//!   为一个 60 行的只读 GET 引入这种约束不值得。
//!
//! ## 超时预算
//!
//! **端点 200ms（连接 + 写 + 读合计一个 deadline）、一轮总共 400ms**。
//! 这个数不是随便定的：探针是**同步**的，而 `main.rs` 起的是 `current_thread` 运行时，
//! `refresh_discovery_snapshot` 就在 3s tick 里 inline 调 `refresh()` —— 这里多阻塞
//! 一秒，心跳 / 状态上报 / 命令轮询 / 采集就一起停一秒。host 探针 15 分钟才跑一次，
//! 400ms 足够试完前几家；真被防火墙 DROP 的那家留到下一轮。
//!
//! ## 属性名与 atlas 的对应关系
//!
//! 这里写的是 `cloud.instance_id`（与 `host.*` / `os.*` 的点分约定一致）。
//! `cloud.provider` 的取值是 `tencent` / `aliyun` / `aws` / **`imds`**——
//! `imds` = “在云上，但这家云不认”（`169.254.169.254` 被多家共用，不被确认就不猜厂商）。
//! atlas 的 IN-01 输入里叫 `cloud_instance_id`，**由 edge adapter 负责映射**；
//! 映射漏了的表现是「身份归并静默失效」，不会报错 —— 改动这一层时请一起改 adapter。

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// 单个端点的**总**预算：连接 + 写 + 读合计共用这一个 deadline（不是每一步各给一份）。
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
/// 一轮探测（所有端点合计）的硬预算，见模块头「超时预算」。
const PROBE_BUDGET: Duration = Duration::from_millis(400);
/// 响应体上限：instance-id 是几十字节，给 512 足够，且防止对端狂写。
const MAX_RESPONSE: u64 = 512;
/// instance-id 的合理长度上限（超过就不采信，避免把 HTML 错误页当成 ID）。
const MAX_ID_LEN: usize = 128;
/// instance-id 的最短长度。
///
/// 它拦的是另一种失败：被链路上的门户 / 代理接住时返回的 `OK` / `200` / `healthy`
/// —— 这些都是纯字母数字，字符集检查拦不住，但它们不像实例 ID（真实 ID 都在 12 字符以上）。
const MIN_ID_LEN: usize = 8;
/// `169.254.169.254` 的**默认** provider。
///
/// 这个地址不是 AWS 专属：OpenStack / 华为云 / 火山引擎 / Oracle / DO 都指向同一个元数据
/// 服务地址。确认之前不写厂商名 —— 错标会让资产挂到错误的云账号下（见 `refine_provider`）。
const GENERIC_IMDS: &str = "imds";

const META_PATH: &str = "/latest/meta-data/instance-id";
/// 只有 AWS 会有这个路径（返回 `amazonaws.com` / `amazonaws.com.cn`），
/// 用来把“通用 IMDS 地址”上的 AWS 与其它云分开。
const SERVICES_DOMAIN_PATH: &str = "/latest/meta-data/services/domain";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudIdentity {
    /// `tencent` / `aliyun` / `aws`
    pub provider: &'static str,
    pub instance_id: String,
}

struct Endpoint {
    provider: &'static str,
    ip: IpAddr,
    /// HTTP `Host` 头：元数据服务按它区分租户（不能省略，部分实现会 400）。
    host_header: &'static str,
    port: u16,
}

/// 顺序 = 探测顺序。全用**固定 IP**，不做 DNS：
/// 不在云上的机器调 `to_socket_addrs` 可能被解析器拖住好几秒。
const ENDPOINTS: &[Endpoint] = &[
    // 腾讯云：metadata.tencentyun.com 解析到 169.254.0.23
    Endpoint {
        provider: "tencent",
        ip: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 23)),
        host_header: "metadata.tencentyun.com",
        port: 80,
    },
    // 阿里云
    Endpoint {
        provider: "aliyun",
        ip: IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
        host_header: "100.100.100.200",
        port: 80,
    },
    // AWS（以及兼容 IMDS 的私有云：OpenStack / 华为云 / 火山 / Oracle / DO 也用它）
    Endpoint {
        provider: GENERIC_IMDS,
        ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        host_header: "169.254.169.254",
        port: 80,
    },
];

/// 探测云实例身份。不在云上时返回 `None`（**不写空属性**：缺键比空串好）。
pub fn probe() -> Option<CloudIdentity> {
    probe_endpoints(ENDPOINTS)
}

/// 一步到位的截止时刻：连接 / 写 / 读每一步都拿它的 `remaining()` 当超时，
/// 这样“端点总预算”才是真的总预算，而不是每步各给一份。
#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn new(budget: Duration) -> Self {
        Self(Instant::now() + budget)
    }

    fn remaining(self) -> Option<Duration> {
        let left = self.0.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left)
    }

    fn expired(self) -> bool {
        self.remaining().is_none()
    }
}

fn probe_endpoints(endpoints: &[Endpoint]) -> Option<CloudIdentity> {
    let budget = Deadline::new(PROBE_BUDGET);
    for endpoint in endpoints {
        if budget.expired() {
            break;
        }
        if let Some(identity) = probe_endpoint(endpoint, Deadline::new(PROBE_TIMEOUT)) {
            return Some(identity);
        }
    }
    None
}

fn probe_endpoint(endpoint: &Endpoint, deadline: Deadline) -> Option<CloudIdentity> {
    let (status, body) = http_get(endpoint, META_PATH, &[], deadline)?;
    let instance_id = if status == 200 {
        sanitize_id(&body, endpoint.provider)?
    } else if status == 401 {
        // AWS 默认强制 IMDSv2：GET 返回 401，需要先拿一次性 token。
        imdsv2_instance_id(endpoint, deadline)?
    } else {
        return None;
    };
    Some(CloudIdentity {
        provider: refine_provider(endpoint, deadline),
        instance_id,
    })
}

/// `169.254.169.254` 的厂商判定：只有元数据服务自己说是 `amazonaws.com` 才标 `aws`。
///
/// 为什么不能直接写 `aws`：那个地址被多家云共用（OpenStack / 华为云 / 火山 / Oracle / DO），
/// 一台华为云主机会被标成 `aws`，而 `cloud.provider` 是会进资产属性的 —— 错标比不标更坏。
/// 确认不了就保持中性 `imds`：**实例 ID 照旧上报**（它才是归并键），只是不猜厂商。
fn refine_provider(endpoint: &Endpoint, deadline: Deadline) -> &'static str {
    if endpoint.provider != GENERIC_IMDS {
        return endpoint.provider;
    }
    // 预算用完就不猜：宁可少一个厂商名，也不要多一次阻塞。
    let Some((status, domain)) = http_get(endpoint, SERVICES_DOMAIN_PATH, &[], deadline) else {
        return endpoint.provider;
    };
    if status == 200 && domain.to_ascii_lowercase().contains("amazonaws.com") {
        "aws"
    } else {
        endpoint.provider
    }
}

/// IMDSv2：`PUT /latest/api/token` 拿 token，再带 `X-aws-ec2-metadata-token` 重试。
fn imdsv2_instance_id(endpoint: &Endpoint, deadline: Deadline) -> Option<String> {
    let (status, token) = http_request(
        endpoint,
        "PUT",
        "/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
        deadline,
    )?;
    if status != 200 {
        return None;
    }
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_ID_LEN {
        return None;
    }
    let (status, body) = http_get(
        endpoint,
        META_PATH,
        &[("X-aws-ec2-metadata-token", token)],
        deadline,
    )?;
    if status != 200 {
        return None;
    }
    sanitize_id(&body, endpoint.provider)
}

fn http_get(
    endpoint: &Endpoint,
    path: &str,
    headers: &[(&str, &str)],
    deadline: Deadline,
) -> Option<(u16, String)> {
    http_request(endpoint, "GET", path, headers, deadline)
}

fn http_request(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    deadline: Deadline,
) -> Option<(u16, String)> {
    let addr = SocketAddr::new(endpoint.ip, endpoint.port);
    let mut stream = TcpStream::connect_timeout(&addr, deadline.remaining()?).ok()?;
    stream.set_write_timeout(deadline.remaining()).ok()?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        endpoint.host_header
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).ok()?;

    // 逐次读并在每次之前**重新核对 deadline**：`set_read_timeout` 只管单次 `read`，
    // 对端一字节一字节吐的话，多次 read 累计能远超预算 —— 而这里是主循环线程。
    let mut raw = Vec::new();
    let mut buf = [0u8; 128];
    while raw.len() < MAX_RESPONSE as usize {
        let Some(left) = deadline.remaining() else {
            break;
        };
        if stream.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(&buf[..read]);
            }
            // 超时 / 对端重置：用已经读到的内容试一下解析（头部完整就能用）。
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status_line = head.lines().next()?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    Some((status, body.trim().to_string()))
}

/// 只接受“看起来确实是一个实例 ID”的值。
///
/// 两种真实失败模式，靠两层检查分开挡：
///   1. 元数据服务不可达时，**被链路上的门户 / 代理接住**返回一段 HTML —— 字符集检查挡下；
///   2. 同一类门户返回 `OK` / `200` / `healthy` 这种纯字母数字单词 —— 长度与**厂商前缀**挡下。
fn sanitize_id(body: &str, provider: &str) -> Option<String> {
    let id = body.trim();
    if id.len() < MIN_ID_LEN || id.len() > MAX_ID_LEN {
        return None;
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return None;
    }
    // 已知厂商的实例 ID 有固定前缀：`ins-`（腾讯）/ `i-`（阿里云、AWS）。
    // 不认识的端点（通用 IMDS）不猜前缀，只靠上面的长度 / 字符集。
    let expected_prefix = match provider {
        "tencent" => Some("ins-"),
        "aliyun" | "aws" => Some("i-"),
        _ => None,
    };
    if let Some(prefix) = expected_prefix
        && !id.starts_with(prefix)
    {
        return None;
    }
    Some(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// 起一个假元数据服务：第 i 个连接用 `responses[i]` 回应。
    ///
    /// 为什么要多条：IMDSv2 是 `PUT` + `GET` 两次请求，通用端点的厂商判定还要再来一次 ——
    /// 一次只回一条的假服务根本测不到那些分支。
    fn serve_many(responses: Vec<&'static str>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(response.as_bytes());
            }
        });
        port
    }

    /// 只回一条的便捷包装。
    fn serve(response: &'static str) -> u16 {
        serve_many(vec![response])
    }

    fn endpoint(provider: &'static str, port: u16) -> Vec<Endpoint> {
        vec![Endpoint {
            provider,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_header: "metadata.example",
            port,
        }]
    }

    fn local(port: u16) -> Vec<Endpoint> {
        endpoint("tencent", port)
    }

    /// 一个肯定没人监听的本地端口。
    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn reads_instance_id_from_a_200_response() {
        let port = serve("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nins-12345");
        let got = probe_endpoints(&local(port)).expect("应读到一个实例 ID");
        assert_eq!(got.provider, "tencent");
        assert_eq!(got.instance_id, "ins-12345");
    }

    #[test]
    fn html_error_page_is_not_an_instance_id() {
        let port = serve("HTTP/1.1 200 OK\r\n\r\n<html>login</html>");
        assert!(
            probe_endpoints(&local(port)).is_none(),
            "代理返回的 HTML 不能被当成实例 ID"
        );
    }

    /// 同一个门户失败模式的另一半：`OK` / `200` / `healthy` 这些纯字母数字的词，
    /// 字符集检查拦不住 —— 靠长度与厂商前缀。
    #[test]
    fn a_portal_saying_ok_is_not_an_instance_id() {
        for response in [
            "HTTP/1.1 200 OK\r\n\r\nOK",
            "HTTP/1.1 200 OK\r\n\r\n200",
            "HTTP/1.1 200 OK\r\n\r\nhealthy",
        ] {
            let port = serve(response);
            assert!(
                probe_endpoints(&local(port)).is_none(),
                "被门户接住时的普通词不是实例 ID：{response}"
            );
        }
    }

    /// 腾讯云端点返回一个 `i-` 开头的串：不像腾讯的 ID，不采信。
    #[test]
    fn an_id_without_the_vendor_prefix_is_rejected() {
        let port = serve("HTTP/1.1 200 OK\r\n\r\ni-0123456789abcdef0");
        assert!(probe_endpoints(&local(port)).is_none());
    }

    #[test]
    fn unreachable_endpoint_yields_none() {
        assert!(probe_endpoints(&local(closed_port())).is_none());
    }

    #[test]
    fn non_200_without_token_support_yields_none() {
        let port = serve("HTTP/1.1 404 Not Found\r\n\r\n");
        assert!(probe_endpoints(&local(port)).is_none());
    }

    /// 第一家不可达不能挡住后面的端点（探测顺序是设计的一部分）。
    #[test]
    fn an_unreachable_endpoint_falls_through_to_the_next() {
        let live = serve("HTTP/1.1 200 OK\r\n\r\ni-bp1abcdefgh");
        let endpoints = vec![
            Endpoint {
                provider: "tencent",
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                host_header: "metadata.example",
                port: closed_port(),
            },
            Endpoint {
                provider: "aliyun",
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                host_header: "metadata.example",
                port: live,
            },
        ];

        let got = probe_endpoints(&endpoints).expect("第二家应该被探到");
        assert_eq!(got.provider, "aliyun");
        assert_eq!(got.instance_id, "i-bp1abcdefgh");
    }

    /// AWS 强制 IMDSv2（`HttpTokens=required`）时的完整流程：401 → PUT 拿 token → 带 token 的 GET。
    /// 这是 AWS 新实例的**默认**路径，以前完全没有测试。
    #[test]
    fn imdsv2_token_is_fetched_and_used_for_the_retry() {
        let port = serve_many(vec![
            "HTTP/1.1 401 Unauthorized\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\ntoken-abc123",
            "HTTP/1.1 200 OK\r\n\r\ni-0123456789abcdef0",
        ]);

        let got = probe_endpoints(&endpoint("aws", port)).expect("IMDSv2 应能读到 ID");
        assert_eq!(got.provider, "aws");
        assert_eq!(got.instance_id, "i-0123456789abcdef0");
    }

    /// `169.254.169.254` 不是 AWS 专属：只有元数据服务自己说 `amazonaws.com` 才算 AWS。
    #[test]
    fn a_generic_metadata_endpoint_is_labeled_aws_only_when_it_says_so() {
        let aws = serve_many(vec![
            "HTTP/1.1 200 OK\r\n\r\ni-0123456789abcdef0",
            "HTTP/1.1 200 OK\r\n\r\namazonaws.com",
        ]);
        let got = probe_endpoints(&endpoint(GENERIC_IMDS, aws)).expect("有 ID");
        assert_eq!(got.provider, "aws", "services/domain 说是 amazonaws.com");

        // 同一地址上的华为云 / OpenStack：ID 照旧上报，但不能被标成 aws。
        let other = serve_many(vec![
            "HTTP/1.1 200 OK\r\n\r\ni-0123456789abcdef0",
            "HTTP/1.1 200 OK\r\n\r\nhwclouds.com",
        ]);
        let got = probe_endpoints(&endpoint(GENERIC_IMDS, other)).expect("有 ID");
        assert_eq!(got.provider, GENERIC_IMDS, "不认识就不猜厂商");
        assert_eq!(got.instance_id, "i-0123456789abcdef0");
    }

    #[test]
    fn the_deadline_expires_and_reports_remaining() {
        let fresh = Deadline::new(Duration::from_millis(50));
        assert!(fresh.remaining().is_some());
        assert!(!fresh.expired());

        let expired = Deadline::new(Duration::ZERO);
        assert!(expired.remaining().is_none());
        assert!(expired.expired());
    }

    #[test]
    fn defaults_are_fixed_private_addresses() {
        // 回归护栏：这些端点必须全是固定 IP（不走 DNS），否则非云环境会被解析器拖住。
        for endpoint in ENDPOINTS {
            assert!(matches!(endpoint.ip, IpAddr::V4(_)));
            assert!(!endpoint.host_header.is_empty());
        }
        assert_eq!(ENDPOINTS.len(), 3);
        assert_eq!(ENDPOINTS[0].provider, "tencent");
        assert_eq!(ENDPOINTS[1].provider, "aliyun");
        // 169.254.169.254 被多家云共用：默认必须是中性名，厂商名由 services/domain 确认。
        assert_eq!(ENDPOINTS[2].provider, GENERIC_IMDS);
    }

    /// 预算就是“一次 host 刷新最多把主循环堵多久”：改大它等于把心跳 / 采集一起拖慢。
    #[test]
    fn the_probe_budget_stays_sub_second() {
        assert_eq!(PROBE_TIMEOUT, Duration::from_millis(200));
        assert_eq!(PROBE_BUDGET, Duration::from_millis(400));
        assert!(PROBE_BUDGET >= PROBE_TIMEOUT, "总预算不该比单端点预算还小");
        assert!(
            PROBE_BUDGET < Duration::from_secs(1),
            "探针跑在 current_thread 运行时的 tick 上：必须亚秒"
        );
    }
}
