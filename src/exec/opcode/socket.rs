//! `socket.list`：本机监听（或全部）套接字。只读 `/proc/net/{tcp,tcp6,udp,udp6}` 与
//! `/proc/<pid>/fd`，**不 exec `ss` / `netstat`**。解析与调查面共用 `crate::sys_sockets`。
//!
//! 三条边界必须在输出里说出来，否则「没看到 8080」会被读成「没有 8080」：
//!
//! 1. **一次快照**：寿命短于一次读取的连接不会出现；
//! 2. **只覆盖 agent 所在 netns**：容器里的端口不在本结果里；
//! 3. **非 root 时属主不可见**（`owners_visible=false`），那不是「没有属主」。
//!
//! 另外：`listening_only=false` 会把已建立/其它状态的连接也列出来，这时 `state` 才有意义
//! （`established` / `time_wait` / …）。默认只给「在等连接」的那些。

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};
use crate::investigate::running_as_root;
use crate::sys_sockets::{self, Socket};

const SCHEMA: &str = "wist.opcode.socket_list/v1";
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;
const MAX_INODES: usize = 8;
const MAX_PIDS: usize = 20;

pub const LIST_SPEC: OpSpec = OpSpec {
    id: "socket.list",
    risk: RiskLevel::R0,
    platforms: &["linux"],
    budget: OpBudget::new(5_000, MAX_LIMIT, 0),
    handler: list,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    /// `tcp` / `udp`；缺省 = 两种都列（各自含 v4/v6）。
    #[serde(default)]
    proto: Option<String>,
    /// 默认 `true`：只要在等连接的那些。
    #[serde(default)]
    listening_only: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `tcp` 覆盖 `tcp` + `tcp6`；`udp` 同理。闭集，别的值直接拒。
fn parse_proto(value: Option<&str>) -> Result<Option<&'static str>, OpError> {
    match value {
        None => Ok(None),
        Some("tcp") => Ok(Some("tcp")),
        Some("udp") => Ok(Some("udp")),
        Some(other) => Err(OpError::new(
            codes::INVALID_ARGS,
            format!("proto 只能是 tcp | udp，收到 `{other}`"),
        )),
    }
}

/// 调用方给的证据面（单测可以直接构造）。
struct Evidence<'a> {
    owners: &'a BTreeMap<u64, (u32, String)>,
    owners_visible: bool,
    owners_complete: bool,
    /// `(请求的来源数, 不可读的来源数)`
    sources: (usize, usize),
}

/// 展示口径（已由调用方按预算解析好）。
struct Options {
    proto: Option<&'static str>,
    listening_only: bool,
    limit: usize,
}

#[derive(Debug)]
struct Group {
    proto: String,
    addr: String,
    port: u16,
    uid: u32,
    state: String,
    inodes: Vec<u64>,
    pids: BTreeSet<u32>,
    names: BTreeSet<String>,
}

fn row(group: &Group) -> Value {
    json!({
        "proto": group.proto,
        "family": sys_sockets::family_of(&group.proto),
        "addr": group.addr,
        "port": group.port,
        "scope": sys_sockets::bind_scope(&group.addr),
        "state": sys_sockets::state_name(&group.state, &group.proto),
        "uid": group.uid,
        "inodes": group.inodes,
        "pids": group.pids.iter().take(MAX_PIDS).collect::<Vec<_>>(),
        "processes": group.names.iter().take(MAX_PIDS).collect::<Vec<_>>(),
    })
}

/// 纯逻辑：套接字表与属主都由调用方给（单测因此不依赖本机的 `/proc`）。
fn build(sockets: &[Socket], evidence: &Evidence<'_>, options: &Options) -> Value {
    let mut grouped: BTreeMap<(String, String, u16, u32, String), Group> = BTreeMap::new();
    let mut non_listening = 0u64;
    let mut kernel_internal = 0u64;
    let mut other_proto = 0u64;

    for socket in sockets {
        if let Some(only) = options.proto
            && !socket.proto.starts_with(only)
        {
            other_proto += 1;
            continue;
        }
        if options.listening_only && !sys_sockets::is_listening(socket) {
            non_listening += 1;
            continue;
        }
        if socket.inode == 0 {
            // 内核内部 socket（如 ICMP），没有可归属的进程。
            kernel_internal += 1;
            continue;
        }
        let key = (
            socket.proto.clone(),
            socket.addr.clone(),
            socket.port,
            socket.uid,
            socket.state.clone(),
        );
        let group = grouped.entry(key).or_insert_with(|| Group {
            proto: socket.proto.clone(),
            addr: socket.addr.clone(),
            port: socket.port,
            uid: socket.uid,
            state: socket.state.clone(),
            inodes: Vec::new(),
            pids: BTreeSet::new(),
            names: BTreeSet::new(),
        });
        // `SO_REUSEPORT` 会让同一组出现多个 socket：留几个 inode 供与
        // `process.open_files` 对账，但不要无限长。
        if group.inodes.len() < MAX_INODES && !group.inodes.contains(&socket.inode) {
            group.inodes.push(socket.inode);
        }
        if let Some((pid, name)) = evidence.owners.get(&socket.inode) {
            group.pids.insert(*pid);
            if !name.is_empty() {
                group.names.insert(name.clone());
            }
        }
    }

    let mut groups: Vec<Group> = grouped.into_values().collect();
    // 对外的排前面：`all` → `specific` → `loopback`，再按端口。
    groups.sort_by(|a, b| {
        (
            sys_sockets::scope_rank(&a.addr),
            a.port,
            a.proto.clone(),
            a.addr.clone(),
            a.state.clone(),
        )
            .cmp(&(
                sys_sockets::scope_rank(&b.addr),
                b.port,
                b.proto.clone(),
                b.addr.clone(),
                b.state.clone(),
            ))
    });

    let total = groups.len();
    let rows: Vec<Value> = groups.iter().take(options.limit).map(row).collect();

    let mut notes: Vec<String> = vec![
        "一次快照：寿命短于一次读取的连接不会出现在这里".to_string(),
        "只覆盖 agent 所在 netns；容器里的监听端口不在本结果里".to_string(),
    ];
    if !evidence.owners_visible {
        notes.push(
            "非 root：端口可见，但属主（pid / 进程名）不可见 —— 这不是「没有属主」".to_string(),
        );
    } else if !evidence.owners_complete {
        notes.push(format!(
            "进程表超过扫描预算（{} 个 fd 或本步预算）：部分端口没有属主",
            sys_sockets::MAX_FDS
        ));
    }

    json!({
        "schema": SCHEMA,
        "proto": options.proto,
        "listening_only": options.listening_only,
        "sources": { "requested": evidence.sources.0, "unreadable": evidence.sources.1 },
        "owners_visible": evidence.owners_visible,
        "owners_complete": evidence.owners_complete,
        "total": total,
        "returned": rows.len(),
        "truncated": total > rows.len(),
        "listeners": rows,
        "skipped": {
            "non_listening": non_listening,
            "kernel_internal": kernel_internal,
            "other_proto": other_proto,
        },
        "limits": { "inodes_per_socket_group": MAX_INODES, "pids_per_socket_group": MAX_PIDS },
        "notes": notes,
    })
}

fn list(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: ListArgs = parse_args(input.args)?;
    let proto = parse_proto(args.proto.as_deref())?;
    let listening_only = args.listening_only.unwrap_or(true);
    let limit = args
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, input.budget.max_items.clamp(1, MAX_LIMIT));

    let mut sockets: Vec<Socket> = Vec::new();
    let mut requested = 0usize;
    let mut unreadable = 0usize;
    for (path, source_proto) in sys_sockets::SOURCES {
        if let Some(only) = proto
            && !source_proto.starts_with(only)
        {
            continue;
        }
        requested += 1;
        match std::fs::read_to_string(path) {
            Ok(text) => sockets.extend(sys_sockets::parse_proc_net(&text, source_proto)),
            Err(_) => unreadable += 1,
        }
    }
    if requested > 0 && unreadable == requested {
        return Err(OpError::new(
            codes::OP_FAILED,
            format!(
                "读不到套接字表（{requested} 个来源全部不可读）；本机可能是受限容器（/proc/net 被隐藏）"
            ),
        ));
    }

    let owners_visible = running_as_root();
    let (owners, owners_complete) = if owners_visible {
        // 时间与 fd 条数双预算：`socket_owners` 会把「没扫完」如实报回来。
        sys_sockets::socket_owners(
            sys_sockets::MAX_FDS,
            Some(Instant::now() + input.budget.duration()),
        )
    } else {
        (BTreeMap::new(), true)
    };

    let evidence = Evidence {
        owners: &owners,
        owners_visible,
        owners_complete,
        sources: (requested, unreadable),
    };
    Ok(OpOutput {
        value: build(
            &sockets,
            &evidence,
            &Options {
                proto,
                listening_only,
                limit,
            },
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(proto: &str, addr: &str, port: u16, uid: u32, inode: u64, state: &str) -> Socket {
        Socket {
            proto: proto.to_string(),
            addr: addr.to_string(),
            port,
            uid,
            inode,
            state: state.to_string(),
        }
    }

    fn evidence(owners: &BTreeMap<u64, (u32, String)>) -> Evidence<'_> {
        Evidence {
            owners,
            owners_visible: true,
            owners_complete: true,
            sources: (4, 0),
        }
    }

    fn opts(proto: Option<&'static str>, listening_only: bool, limit: usize) -> Options {
        Options {
            proto,
            listening_only,
            limit,
        }
    }

    fn names(value: &Value) -> Vec<String> {
        value["listeners"]
            .as_array()
            .expect("listeners")
            .iter()
            .map(|row| {
                format!(
                    "{}:{}",
                    row["addr"].as_str().unwrap_or_default(),
                    row["port"]
                )
            })
            .collect()
    }

    #[test]
    fn proto_is_a_closed_set() {
        assert_eq!(parse_proto(None).unwrap(), None);
        assert_eq!(parse_proto(Some("tcp")).unwrap(), Some("tcp"));
        assert_eq!(parse_proto(Some("udp")).unwrap(), Some("udp"));
        for bad in ["tcp6", "sctp", "TCP", ""] {
            assert_eq!(
                parse_proto(Some(bad)).unwrap_err().code,
                codes::INVALID_ARGS
            );
        }
    }

    #[test]
    fn default_listing_keeps_only_listeners_and_says_how_many_were_dropped() {
        let sockets = vec![
            socket("tcp", "0.0.0.0", 22, 0, 11, "0A"),
            socket("tcp", "10.0.0.5", 51234, 1000, 22, "01"),
            socket("udp", "0.0.0.0", 53, 0, 33, "07"),
            socket("tcp", "127.0.0.1", 6379, 0, 0, "0A"),
        ];
        let owners = BTreeMap::new();
        let value = build(&sockets, &evidence(&owners), &opts(None, true, 100));

        assert_eq!(
            value["total"], 2,
            "sshd 与 dns；redis 那条 inode=0 的内核内部 socket 被跳过"
        );
        assert_eq!(value["skipped"]["non_listening"], 1);
        assert_eq!(value["skipped"]["kernel_internal"], 1);
        assert_eq!(names(&value), vec!["0.0.0.0:22", "0.0.0.0:53"]);
        assert_eq!(value["listeners"][0]["scope"], "all");
        assert_eq!(value["listeners"][0]["family"], "ipv4");
        assert_eq!(value["listeners"][0]["state"], "listen");
        assert_eq!(value["listeners"][1]["state"], "unconnected");
    }

    #[test]
    fn listening_only_false_keeps_established_connections_with_state() {
        let sockets = vec![
            socket("tcp", "0.0.0.0", 22, 0, 11, "0A"),
            socket("tcp", "10.0.0.5", 51234, 1000, 22, "01"),
        ];
        let owners = BTreeMap::new();
        let value = build(&sockets, &evidence(&owners), &opts(None, false, 100));
        assert_eq!(value["total"], 2);
        let states: Vec<&str> = value["listeners"]
            .as_array()
            .expect("listeners")
            .iter()
            .map(|row| row["state"].as_str().unwrap_or_default())
            .collect();
        assert!(states.contains(&"established"));
        assert_eq!(value["skipped"]["non_listening"], 0);
    }

    #[test]
    fn proto_filter_covers_v4_and_v6_of_the_same_protocol() {
        let sockets = vec![
            socket("tcp", "0.0.0.0", 80, 0, 1, "0A"),
            socket("tcp6", "::", 80, 0, 2, "0A"),
            socket("udp", "0.0.0.0", 53, 0, 3, "07"),
        ];
        let owners = BTreeMap::new();
        let value = build(&sockets, &evidence(&owners), &opts(Some("tcp"), true, 100));
        assert_eq!(value["proto"], "tcp");
        assert_eq!(value["total"], 2);
        assert_eq!(value["skipped"]["other_proto"], 1);
        let families: Vec<&str> = value["listeners"]
            .as_array()
            .expect("listeners")
            .iter()
            .map(|row| row["family"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(families, vec!["ipv4", "ipv6"]);
    }

    #[test]
    fn reuseport_sockets_collapse_into_one_row_with_several_inodes() {
        let sockets = vec![
            socket("tcp", "0.0.0.0", 8080, 0, 100, "0A"),
            socket("tcp", "0.0.0.0", 8080, 0, 101, "0A"),
        ];
        let mut owners = BTreeMap::new();
        owners.insert(100, (4242, "java".to_string()));
        owners.insert(101, (4243, "java".to_string()));

        let value = build(&sockets, &evidence(&owners), &opts(None, true, 100));
        assert_eq!(value["total"], 1);
        let row = &value["listeners"][0];
        assert_eq!(row["inodes"], json!([100, 101]));
        assert_eq!(row["pids"], json!([4242, 4243]));
        assert_eq!(row["processes"], json!(["java"]));
    }

    #[test]
    fn non_root_output_says_owners_are_invisible() {
        let sockets = vec![socket("tcp", "0.0.0.0", 22, 0, 11, "0A")];
        let owners = BTreeMap::new();
        let mut evidence = evidence(&owners);
        evidence.owners_visible = false;
        let value = build(&sockets, &evidence, &opts(None, true, 100));
        assert_eq!(value["owners_visible"], false);
        assert!(
            value["listeners"][0]["pids"]
                .as_array()
                .expect("pids")
                .is_empty()
        );
        let notes = value["notes"].as_array().expect("notes");
        assert!(
            notes
                .iter()
                .any(|note| note.as_str().unwrap_or_default().contains("非 root")),
            "{notes:?}"
        );
    }

    #[test]
    fn an_exhausted_owner_scan_is_reported_not_hidden() {
        let sockets = vec![socket("tcp", "0.0.0.0", 22, 0, 11, "0A")];
        let owners = BTreeMap::new();
        let mut evidence = evidence(&owners);
        evidence.owners_complete = false;
        let value = build(&sockets, &evidence, &opts(None, true, 100));
        assert_eq!(value["owners_complete"], false);
        let notes = value["notes"].as_array().expect("notes");
        assert!(
            notes
                .iter()
                .any(|note| note.as_str().unwrap_or_default().contains("扫描预算")),
            "{notes:?}"
        );
    }

    #[test]
    fn listing_is_truncated_by_limit_but_total_stays_exact() {
        let sockets: Vec<Socket> = (0..5)
            .map(|index| {
                socket(
                    "tcp",
                    "0.0.0.0",
                    8000 + index,
                    0,
                    100 + u64::from(index),
                    "0A",
                )
            })
            .collect();
        let owners = BTreeMap::new();
        let value = build(&sockets, &evidence(&owners), &opts(None, true, 2));
        assert_eq!(value["total"], 5);
        assert_eq!(value["returned"], 2);
        assert_eq!(value["truncated"], true);
    }

    #[test]
    fn op_metadata_is_read_only_and_linux_only() {
        assert_eq!(LIST_SPEC.risk, RiskLevel::R0);
        assert_eq!(LIST_SPEC.platforms, &["linux"]);
    }
}
