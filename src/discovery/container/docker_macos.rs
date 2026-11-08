//! macOS 的容器发现：走 Docker Engine API（Unix socket）。
//!
//! 为什么 macOS 需要另一条路：Linux 能扫运行时根目录（`/run/containerd/...`、
//! `/var/lib/docker/...`）并从 `/proc` 读到容器进程；macOS 上容器跑在**独立的 Linux
//! 虚拟机**里，宿主这两样都没有，只剩 Docker 自己暴露的 Unix socket。
//!
//! 只用 HTTP/1.1 的一个 GET，不引 HTTP 客户端依赖，也不依赖 `docker` 命令：
//! 长驻探针每多一个外部二进制就多一个「生产机上没装 / PATH 不对」的故障点
//! （与 `endpoint_macos.rs` 选 libproc 是同一个理由）。
//!
//! 只取两样东西：**容器身份**（id / 名字 / 镜像）与**发布到宿主的端口**。前者让
//! 知识库能按「这台机器上跑着 postgres 容器」门控单元；后者让数据库自探能连过去。

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// 单次读写的上限时间。
const IO_TIMEOUT: Duration = Duration::from_millis(2_000);
/// 响应上限：几百个容器也就几百 KB，4 MiB 足够且不会把内存吃穿。
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// 一个正在跑的容器。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerContainer {
    pub id: String,
    /// 去掉 Docker 前缀斜杠的名字（`/pg-probe-test` → `pg-probe-test`）。
    pub name: String,
    pub image: String,
    /// 发布到宿主的 TCP 端口。
    pub ports: Vec<DockerPort>,
}

/// `-p host:container` 这条映射的宿主侧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerPort {
    /// 宿主侧绑定地址（`0.0.0.0` / `::` / 具体 IP）。
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
}

/// 列一遍正在跑的容器。
///
/// 返回 `None` = 这台机器没有可用的 Docker socket（没装 / 没起）。
/// 调用方把它当「没有容器」，不是错误 —— 探针不该因为机器上没 Docker 就报失败。
pub(crate) fn list_containers() -> Option<Vec<DockerContainer>> {
    for socket in socket_paths() {
        if !socket.exists() {
            continue;
        }
        let Some(raw) = request(&socket, "/containers/json") else {
            continue;
        };
        let Some((headers, body)) = split_response(&raw) else {
            continue;
        };
        let body = if header_has(&headers, "transfer-encoding", "chunked") {
            dechunk(body)
        } else {
            body.to_vec()
        };
        if let Ok(containers) = parse_containers(&body) {
            return Some(containers);
        }
    }
    None
}

/// 候选 socket：先看 `DOCKER_HOST`，再看各运行时的约定位置。
///
/// agentd 以 root 跑时 `HOME` 是 `/var/root`，所以用户态的
/// `~/.docker/run/docker.sock` 通常**不**在这里列；Docker Desktop / OrbStack 都会把
/// `/var/run/docker.sock` 指过去，那一条才是主路径。
fn socket_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(host) = std::env::var("DOCKER_HOST")
        && let Some(path) = host.strip_prefix("unix://")
        && !path.is_empty()
    {
        out.push(PathBuf::from(path));
    }
    out.push(PathBuf::from("/var/run/docker.sock"));
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        out.push(home.join(".docker/run/docker.sock"));
        out.push(home.join(".orbstack/run/docker.sock"));
    }
    out
}

fn request(socket: &PathBuf, path: &str) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).ok()?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES as u64)
        .read_to_end(&mut raw)
        .ok()?;
    Some(raw)
}

/// 拆 `头 / 体`。头统一小写，便于按键取值。
fn split_response(raw: &[u8]) -> Option<(String, &[u8])> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&raw[..split])
        .ok()?
        .to_ascii_lowercase();
    Some((headers, &raw[split + 4..]))
}

fn header_has(headers: &str, name: &str, needle: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(key, value)| key.trim() == name && value.contains(needle))
    })
}

/// 解 `Transfer-Encoding: chunked`。
///
/// Docker 的 JSON 响应是分块的（Go 的 net/http 即使收到 HTTP/1.0 也这么回），
/// 而这里没有 HTTP 客户端库来解它。
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while let Some(nl) = rest.windows(2).position(|window| window == b"\r\n") {
        let size_line = String::from_utf8_lossy(&rest[..nl]);
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = nl + 2;
        let Some(end) = start.checked_add(size) else {
            break;
        };
        if end > rest.len() {
            out.extend_from_slice(&rest[start..]);
            break;
        }
        out.extend_from_slice(&rest[start..end]);
        rest = &rest[end..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct ContainerJson {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "Ports", default)]
    ports: Vec<PortJson>,
}

#[derive(serde::Deserialize)]
struct PortJson {
    #[serde(rename = "IP", default)]
    ip: String,
    #[serde(rename = "PrivatePort", default)]
    private_port: u16,
    #[serde(rename = "PublicPort")]
    public_port: Option<u16>,
    #[serde(rename = "Type", default)]
    proto: String,
}

fn parse_containers(body: &[u8]) -> Result<Vec<DockerContainer>, serde_json::Error> {
    let rows: Vec<ContainerJson> = serde_json::from_slice(body)?;
    Ok(rows
        .into_iter()
        .map(|row| DockerContainer {
            id: row.id,
            name: row
                .names
                .first()
                .map(|name| name.trim_start_matches('/').to_string())
                .unwrap_or_default(),
            image: row.image,
            ports: dedupe_ports(
                row.ports
                    .into_iter()
                    .filter(|port| port.proto.is_empty() || port.proto.eq_ignore_ascii_case("tcp"))
                    .filter_map(|port| {
                        port.public_port.map(|host_port| DockerPort {
                            host_ip: port.ip,
                            host_port,
                            container_port: port.private_port,
                        })
                    })
                    .collect(),
            ),
        })
        .collect())
}

/// 双栈发布（`0.0.0.0` + `::`）是**同一个映射**的两条记录：按宿主端口去重。
///
/// 不去重会产出两条 `resource_id` 相同的 `container_port` 资源（`{id}:port:{port}`），
/// 下游按 id 去重时会丢掉一条、按条数统计时会重复，白跑一次握手。
/// 保 IPv4 那条：地址最终都会归一成回环，而 IPv4 的绑定地址更像「运维看到的东西」。
fn dedupe_ports(ports: Vec<DockerPort>) -> Vec<DockerPort> {
    let mut out: Vec<DockerPort> = Vec::with_capacity(ports.len());
    for port in ports {
        match out.iter().position(|seen| seen.host_port == port.host_port) {
            Some(index) => {
                if out[index].host_ip.contains(':') && !port.host_ip.contains(':') {
                    out[index] = port;
                }
            }
            None => out.push(port),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {"Id":"abc","Names":["/pg-probe-test"],"Image":"postgres:16",
       "Ports":[
         {"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":55999,"Type":"tcp"},
         {"IP":"::","PrivatePort":5432,"PublicPort":55999,"Type":"tcp"},
         {"PrivatePort":5432,"Type":"tcp"},
         {"IP":"0.0.0.0","PrivatePort":9187,"PublicPort":9187,"Type":"udp"}
       ]},
      {"Id":"def","Names":["/web"],"Image":"nginx","Ports":[]}
    ]"#;

    #[test]
    fn published_tcp_ports_are_kept_and_unpublished_ones_dropped() {
        let containers = parse_containers(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].name, "pg-probe-test", "要去掉前缀斜杠");
        assert_eq!(containers[0].image, "postgres:16");
        assert_eq!(
            containers[0].ports,
            vec![DockerPort {
                host_ip: "0.0.0.0".to_string(),
                host_port: 55999,
                container_port: 5432,
            }],
            "双栈发布是同一个映射：只留一条（保 IPv4），没发布与 udp 的映射都不算"
        );
    }

    #[test]
    fn ipv6_binding_is_replaced_by_the_ipv4_one_even_if_it_comes_first() {
        let body = br#"[{"Id":"x","Names":["/db"],"Image":"postgres:16",
          "Ports":[
            {"IP":"::","PrivatePort":5432,"PublicPort":55999,"Type":"tcp"},
            {"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":55999,"Type":"tcp"}
          ]}]"#;
        let containers = parse_containers(body).expect("parse");
        assert_eq!(containers[0].ports.len(), 1);
        assert_eq!(containers[0].ports[0].host_ip, "0.0.0.0");
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        // `{"a":1}` 分两块发：3 字节 + 4 字节 + 结束块。
        let body = b"3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), b"{\"a\":1}".to_vec());
    }

    #[test]
    fn chunked_decoder_tolerates_garbage() {
        assert!(dechunk(b"").is_empty());
        assert!(dechunk(b"not-a-chunk\r\n").is_empty());
        // 声明长度大于实际：把剩下的都给出去，而不是丢数据。
        assert_eq!(dechunk(b"ff\r\nabc"), b"abc".to_vec());
    }

    #[test]
    fn response_is_split_at_the_header_break() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nbody";
        let (headers, body) = split_response(raw).expect("split");
        assert!(header_has(&headers, "transfer-encoding", "chunked"));
        assert_eq!(body, b"body");
    }
}
