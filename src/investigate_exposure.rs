//! 暴露面（`wist-agentd investigate exposure`）：**这台机器此刻在等谁连进来**。
//!
//! 只答属性，不答行为：监听 socket 是机器的一种**状态**，一次枚举就是全集；而"它往外连了谁"
//! 是行为，只有连续观测才准，归采集面（且我们已经明确不建这种"有结构性缺口"的采集面）。
//!
//! 这题刻意**不做安全判定**（`EVIDENCE_ONLY_TOPICS`）：`0.0.0.0:8080` 是好是坏，取决于这台
//! 机器该不该有它、以及它前面有没有反代/安全组 —— 主机只看得见绑定地址，看不见可达性。
//! 所以它给证据，判定留给中心的 join：`listeners × software(漏洞) × 拓扑(是否真对外)`。
//!
//! 三条边界：
//!
//! 1. **只读** `/proc/net/tcp{,6}` / `udp{,6}` + `/proc/<pid>/fd`，不 exec `ss`/`netstat`。
//! 2. **只做快照**：没有观察窗口。短连接看不到，这一点必须写在报告的 `limits` 里。
//! 3. **容器 netns 不覆盖**：宿主只看得见自己的 netns；有容器运行时就把这条认知写出来，
//!    否则"没看到 8080"会被读成"容器没开 8080"。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Finding, InvestigateRequest, Row, running_as_root};
use crate::investigate_probe::{Tally, truncate_rows};
use crate::sys_sockets::{self, Socket};

pub(crate) fn investigate(
    request: &InvestigateRequest,
    _config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    if !cfg!(target_os = "linux") {
        return Err("exposure 调查暂只支持 Linux（macOS 需要 netstat/sysctl 的只读白名单）".into());
    }
    Ok(vec![listeners_finding(request.top)])
}

#[derive(Debug, Clone)]
struct Listener {
    proto: String,
    addr: String,
    port: u16,
    uid: u32,
    pids: BTreeSet<u32>,
    names: BTreeSet<String>,
}

fn listeners_finding(top: usize) -> Finding {
    let mut tally = Tally::default();
    let mut sockets: Vec<Socket> = Vec::new();
    let mut unreadable = 0usize;
    for (path, proto) in sys_sockets::SOURCES {
        match tally.read(Path::new(path)) {
            Some(text) => sockets.extend(sys_sockets::parse_proc_net(&text, proto)),
            None => unreadable += 1,
        }
    }
    if sockets.is_empty() && unreadable == 4 {
        return Finding::new(
            "exposure.listeners",
            Status::Unknown,
            "无法读取套接字表",
            "/proc/net/tcp{,6} 与 udp{,6} 都不可读",
        )
        .coverage(tally.coverage())
        .limit("本机可能是受限容器（/proc/net 被隐藏）");
    }

    let root = running_as_root();
    let (owners, owners_truncated) = if root {
        sys_sockets::socket_owners(sys_sockets::MAX_FDS, None)
    } else {
        (BTreeMap::new(), false)
    };

    // 聚合：同一个 (proto, 地址, 端口, uid) 下的多个 socket（SO_REUSEPORT）算一行。
    let mut grouped: BTreeMap<(String, String, u16, u32), Listener> = BTreeMap::new();
    let mut skipped = 0usize;
    for socket in sockets {
        // UDP 没有 LISTEN 状态（未连接 socket 显示 07），所以只对 TCP 过滤状态。
        if socket.proto.starts_with("tcp") && socket.state != "0A" {
            continue;
        }
        if socket.inode == 0 {
            // 内核内部 socket（如 ICMP），没有可归属的进程。
            skipped += 1;
            continue;
        }
        let key = (
            socket.proto.clone(),
            socket.addr.clone(),
            socket.port,
            socket.uid,
        );
        let entry = grouped.entry(key).or_insert_with(|| Listener {
            proto: socket.proto.clone(),
            addr: socket.addr.clone(),
            port: socket.port,
            uid: socket.uid,
            pids: BTreeSet::new(),
            names: BTreeSet::new(),
        });
        if let Some((pid, name)) = owners.get(&socket.inode) {
            entry.pids.insert(*pid);
            if !name.is_empty() {
                entry.names.insert(name.clone());
            }
        }
    }

    let mut listeners: Vec<Listener> = grouped.into_values().collect();
    // 对外的排前面：`all` → `specific` → `loopback`。
    listeners.sort_by_key(|listener| {
        (
            sys_sockets::scope_rank(&listener.addr),
            listener.port,
            listener.proto.clone(),
            listener.addr.clone(),
        )
    });

    let mut public = 0usize;
    let mut rows: Vec<Row> = Vec::new();
    for listener in &listeners {
        let scope = sys_sockets::bind_scope(&listener.addr);
        if scope == "all" {
            public += 1;
        }
        let mut note = scope.to_string();
        if !listener.names.is_empty() {
            note.push('；');
            note.push_str(
                &listener
                    .names
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        } else if !root {
            note.push_str("；属主不可见（非 root）");
        }
        rows.push(Row::new(
            format!("{}:{}", listener.addr, listener.port),
            format!("{} / uid {}", listener.proto, listener.uid),
            note,
        ));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let mut detail = format!(
        "监听套接字 {} 个；绑定全部地址（0.0.0.0 / ::）{} 个",
        listeners.len(),
        public
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    if unreadable > 0 {
        let _ =
            std::fmt::Write::write_fmt(&mut detail, format_args!("；{unreadable} 个来源不可读"));
    }

    let coverage = crate::investigate::Coverage::new(
        tally.checked,
        if root { 0 } else { 1 },
        skipped + tally.skipped + usize::from(owners_truncated),
    );
    let mut finding = Finding::new("exposure.listeners", Status::Ok, "监听端口已列出", detail)
        .rows(rows)
        .coverage(coverage)
        .limit("这是一次快照：生命周期短于一次读取的连接不会出现在报告里")
        .limit("只覆盖 agent 所在 netns；容器里的监听端口不在本报告里");

    if !root {
        finding =
            finding.limit("非 root：端口可见，但属主（pid/进程名）不可见 —— 以 root 重跑才完整");
    }
    if owners_truncated {
        // “预算用完”必须说出来：否则这张表看起来像“所有端口都归好属了”。
        finding = finding.limit(format!(
            "进程表超过扫描预算（{} 个 fd）：部分端口没有属主",
            sys_sockets::MAX_FDS
        ));
    }
    if Path::new("/var/run/docker.sock").exists()
        || Path::new("/run/containerd/containerd.sock").exists()
    {
        finding =
            finding.limit("本机有容器运行时：宿主 netns 之外的端口需要另行检查（container 题）");
    }
    finding.hint("绑定 `0.0.0.0` / `::` 只说明本机在听；是否真的对外取决于反代、安全组与拓扑")
}
