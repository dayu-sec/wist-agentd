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
//! 每个厂商 200ms，最多 600ms；不在云上的机器（IDC、开发机）就是连续三次快速失败。
//! host 探针 15 分钟才跑一次，这点开销可以接受 —— **但不要**把它加到更频繁的探针里。
//!
//! ## 属性名与 atlas 的对应关系
//!
//! 这里写的是 `cloud.instance_id`（与 `host.*` / `os.*` 的点分约定一致）。
//! atlas 的 IN-01 输入里叫 `cloud_instance_id`，**由 edge adapter 负责映射**；
//! 映射漏了的表现是「身份归并静默失效」，不会报错 —— 改动这一层时请一起改 adapter。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// 单个端点的总预算（连接 + 写 + 读）。
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
/// 响应体上限：instance-id 是几十字节，给 512 足够，且防止对端狂写。
const MAX_RESPONSE: u64 = 512;
/// instance-id 的合理长度上限（超过就不采信，避免把 HTML 错误页当成 ID）。
const MAX_ID_LEN: usize = 128;

const META_PATH: &str = "/latest/meta-data/instance-id";

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
    // AWS（含大部分兼容 IMDS 的私有云）
    Endpoint {
        provider: "aws",
        ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        host_header: "169.254.169.254",
        port: 80,
    },
];

/// 探测云实例身份。不在云上时返回 `None`（**不写空属性**：缺键比空串好）。
pub fn probe() -> Option<CloudIdentity> {
    probe_endpoints(ENDPOINTS)
}

fn probe_endpoints(endpoints: &[Endpoint]) -> Option<CloudIdentity> {
    for endpoint in endpoints {
        let Some((status, body)) = http_get(endpoint, META_PATH, &[]) else {
            continue;
        };
        if status == 200 {
            if let Some(id) = sanitize_id(&body) {
                return Some(CloudIdentity {
                    provider: endpoint.provider,
                    instance_id: id,
                });
            }
            continue;
        }
        // AWS 默认强制 IMDSv2：GET 返回 401，需要先拿一次性 token。
        if status == 401
            && let Some(id) = imdsv2_instance_id(endpoint)
        {
            return Some(CloudIdentity {
                provider: endpoint.provider,
                instance_id: id,
            });
        }
    }
    None
}

/// IMDSv2：`PUT /latest/api/token` 拿 token，再带 `X-aws-ec2-metadata-token` 重试。
fn imdsv2_instance_id(endpoint: &Endpoint) -> Option<String> {
    let (status, token) = http_request(
        endpoint,
        "PUT",
        "/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
    )?;
    if status != 200 {
        return None;
    }
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_ID_LEN {
        return None;
    }
    let (status, body) = http_get(endpoint, META_PATH, &[("X-aws-ec2-metadata-token", token)])?;
    if status != 200 {
        return None;
    }
    sanitize_id(&body)
}

fn http_get(endpoint: &Endpoint, path: &str, headers: &[(&str, &str)]) -> Option<(u16, String)> {
    http_request(endpoint, "GET", path, headers)
}

fn http_request(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Option<(u16, String)> {
    let addr = SocketAddr::new(endpoint.ip, endpoint.port);
    let mut stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;

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

    let mut raw = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE)
        .read_to_end(&mut raw)
        .ok()?;
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

/// 只接受"看起来确实是一个实例 ID"的值。
///
/// 元数据服务不可达时常见的失败不是连接错误，而是**被链路上的门户/代理接住**并返回一段 HTML。
/// 不做这个检查就会把 `<html>...` 当成 instance-id 写进资产属性，而且下游看不出异常。
fn sanitize_id(body: &str) -> Option<String> {
    let id = body.trim();
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return None;
    }
    if id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        Some(id.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// 起一个只回应一次的假元数据服务，返回它的端口。
    fn serve(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(response.as_bytes());
            }
        });
        port
    }

    fn local(port: u16) -> Vec<Endpoint> {
        vec![Endpoint {
            provider: "tencent",
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_header: "metadata.example",
            port,
        }]
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

    #[test]
    fn unreachable_endpoint_yields_none() {
        // 绑定后立刻释放，保证端口没人监听。
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        assert!(probe_endpoints(&local(port)).is_none());
    }

    #[test]
    fn non_200_without_token_support_yields_none() {
        let port = serve("HTTP/1.1 404 Not Found\r\n\r\n");
        assert!(probe_endpoints(&local(port)).is_none());
    }

    #[test]
    fn defaults_are_fixed_private_addresses() {
        // 回归护栏：这些端点必须全是固定 IP（不走 DNS），否则非云环境会被解析器拖住。
        for endpoint in ENDPOINTS {
            assert!(matches!(endpoint.ip, IpAddr::V4(_)));
            assert!(!endpoint.host_header.is_empty());
        }
        assert_eq!(ENDPOINTS.len(), 3);
    }
}
