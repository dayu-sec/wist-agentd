# Linux 主机采集源清单（设计参考）

## 1. 文档目的

本文档整理 **Linux** 主机上值得采集的日志与运行状态位置，作为：

- `wist-agentd` telemetry `file_inputs` / 数据面接入（`warp-parse`）的**源清单**；
- 两个常驻工作模板 `linux-compute`（计算服务器）、`linux-data`（数据服务器）的**内容依据**。

它不是：一份取证手册；也不是对某个发行版/版本的穷举路径索引。

> ⚠️ **核对状态：未核对。** 本文路径与命令来自 Linux 通用事实，**尚未在任何 Linux 真机验证过**
> （当前开发环境只有 macOS）。与 [`macos-security-audit-log-sources.md`](./macos-security-audit-log-sources.md)
> 不同，这里也**没有 `sample.dat`**：`data-plane/models/wpl/linux/` 目前是空目录。
> 因此每一条目的“真样本 + WPL + OML”三件套都还没开始，见 §9。
>
> 本文与模板的对应关系见 `doc/design/center/agent-work-templates.md`。

## 2. 范围与前提

- 适用：主流服务端发行版。**路径按发行版分叉**：RHEL 系用 `/var/log/secure`、`/var/log/messages`；
  Debian/Ubuntu 用 `/var/log/auth.log`、`/var/log/syslog`。采集配置必须同时覆盖两套（`glob` 并列）。
- Linux 的日志体系与 macOS 差异很大，核心事实：

  1. **文件型日志仍是主力，而且可以直接 tail**（与 macOS 依赖统一日志 predicate 相反）；
  2. **journald 是二进制**（`/var/log/journal`），不能 tail；要么 `journalctl -o json` 周期导出，
     要么让 journald 转发成文件（`ForwardToSyslog=yes`）再走 file input；
  3. **运行时状态不是日志**：`/proc`、`/sys`、`ss`、`df` 需要周期采集器（指标面）；
  4. **权限**：`secure`/`auth.log`、DB 日志、SMART、`auditd` 都需 `root`；
  5. 保留期由 `logrotate` 决定（通常数周），采集端要“近实时转发 + 周期归档”两条腿。

## 3. 采集面总览

| 采集面 | 载体 / 位置 | 价值的核心 |
|---|---|---|
| A. 文件型日志 | `/var/log/*`、DB 自带日志目录 | 认证、提权、包管理、内核、服务、数据库 |
| B. journald | `journalctl`（`/var/log/journal`） | systemd 单元状态、服务崩溃、shutdown/reboot |
| C. 周期导出 | `smartctl`、`nft`/`iptables-save`、`last`、`auditd` | 规则快照、磁盘健康、会话与命令审计（非文本流） |
| D. 指标 | `/proc`、`/sys`、`df` | CPU/内存/负载/磁盘/网络/GPU |

## 4. 优先级总表

优先级：**P0** 必采 / **P1** 建议 / **P2** 按需 / **—** 该类机器不采。

| 采集面 | 计算服务器 | 数据服务器 | 主要位置 |
|---|---|---|---|
| `LoginSession` 认证与会话 | P0 | P0 | `secure`/`auth.log`、`/var/log/wtmp`（`last`/`lastb`）、`sshd`、fail2ban |
| `PrivilegeExecution` 提权与命令执行 | P0 | P0 | `sudo`（`auth.log` / `/var/log/sudo.log`）、`auditd` execve 规则 |
| `SoftwareChange` 系统与软件变更 | P1 | P0 | `/var/log/dpkg.log`、`apt/history.log`、`dnf.log`、`yum.log`、journald `packagekit` |
| `ServiceLifecycle` 服务生命周期 | P1 | P0 | `journalctl -u`（unit start/stop/failed）、`syslog` |
| `CrashPanic` 崩溃与内核 panic | P1 | P1 | `/var/lib/systemd/coredump/*`、`/var/crash/*`（apport）、`dmesg` panic/oops/BUG |
| `NetworkFirewall` 网络与防火墙 | P1 | P1 | `nft list ruleset` / `iptables-save` 快照、`firewalld`/`ufw` journal |
| `RebootPower` 关机与重启 | P1 | P0 | journald shutdown/reboot、`last reboot` |
| `MiscSystem` 系统杂项 | P2 | P1 | `/var/log/cron`、`syslog` 杂项、`alternatives.log` |
| `KernelSystem` 内核与系统 | P0 | P0 | `kern.log`/`messages`、`dmesg`、OOM killer |
| `DatabaseService` 数据库服务 | — | P0 | `/var/log/postgresql/*`、MySQL/MariaDB error log、Redis、MongoDB |
| `StorageHealth` 存储与文件系统 | P1 | P0 | `smartctl`、`/var/log/fsck*`、`/proc/mdstat`、LVM、`df`/inode |
| `ComputeWorkload` 作业/调度/加速卡 | P0 | P1 | `/var/log/slurm/*`、`journalctl -u kubelet`、`/var/log/pods/*`、`dmesg` NVRM/Xid |
| `BackupJob` 备份与批处理 | P1 | P0 | borg / restic / rsync 任务日志、cron 结果 |
| `NetworkService` 网络服务 | P1 | P0 | nginx / apache 访问与错误日志、samba / NFS |
| `HostMetrics` 主机指标 | P0 | P0 | `/proc/stat`、`/proc/meminfo`、`/sys/block`、`/proc/net`、GPU |

> `NetworkFirewall`（网络事件与防火墙策略）与 `NetworkService`（对外服务的应用日志）是**两个面**，不要合并：
> 前者看“被拦了什么、策略变没变”，后者看“服务自身报了什么”。规则快照属于前者。

## 5. 分项说明

### 5.1 认证与会话（`LoginSession`）

- `/var/log/secure`（RHEL 系）/ `/var/log/auth.log`（Debian 系）：`sshd` 登录成功/失败、`su`、`sudo` 触发行；
- `/var/log/wtmp`（`last`）、`/var/log/btmp`（`lastb`，需 `root`）：会话起止、失败登录；
- 可选 fail2ban 日志（`/var/log/fail2ban.log`）：封禁动作。

### 5.2 提权与命令执行（`PrivilegeExecution`）

- `sudo`：Debian 系在 `auth.log`，RHEL 系在 `secure`；也可配 `Defaults logfile=/var/log/sudo.log`；
- 命令级审计的正统载体是 **`auditd`**（Linux 侧对应 macOS 的 OpenBSM）：需 `root` 且要写规则
  （`/etc/audit/rules.d/*.rules`，如 `-a always,exit -F arch=b64 -S execve`），用 `ausearch`/`aureport` 导出文本。

### 5.3 系统与软件变更（`SoftwareChange`）

- Debian 系：`/var/log/dpkg.log`、`/var/log/apt/history.log`；
- RHEL 系：`/var/log/dnf.log`、`/var/log/yum.log`；
- 内核/关键库升级（`linux-image`、`glibc`、`openssl`）建议单独打标 —— 它们与“是否需要重启”直接相关。

### 5.4 服务生命周期（`ServiceLifecycle`）

- `journalctl -u <unit>`：单元 start/stop/failed、重启风暴；
- `/var/log/syslog`（Debian 系）：非 journald 场景的兜底。

### 5.5 崩溃与内核 panic（`CrashPanic`）

- 应用崩溃：`/var/lib/systemd/coredump/*`（systemd-coredump）、`/var/crash/*`（Ubuntu apport）；
- 内核：`dmesg` 的 `panic` / `Oops` / `BUG:`（与 `KernelSystem` 同源，区别是本面只看崩溃类事件）。

### 5.6 网络与防火墙（`NetworkFirewall`）

- 规则快照：`nft list ruleset`、`iptables-save`（周期导出，对比差异比看流量更有用）；
- 拦截事件：`firewalld` / `ufw` 的 journal 输出。

### 5.7 关机与重启（`RebootPower`）

- journald 的 shutdown/reboot 记录、`last reboot` / `last shutdown`（`wtmp`）；
- 注意与 `CrashPanic` 对齐看“是正常重启还是崩溃”。

### 5.8 系统杂项（`MiscSystem`）

- `/var/log/cron`：定时任务执行结果（备份任务失败常在这里露头）；
- `/var/log/alternatives.log` 等低频杂项。

### 5.9 内核与系统（`KernelSystem`）

- `/var/log/kern.log`（Debian 系）/ `/var/log/messages`（RHEL 系）、`dmesg`；
- **OOM killer**（`Out of memory: Killed process`）：算力/数据服务器最高频的“事故解释”，单独打标。

### 5.10 数据库服务（`DatabaseService`）

- PostgreSQL：`/var/log/postgresql/*`（含 slow query，需配 `log_min_duration_statement`）；
- MySQL/MariaDB：`error log`（路径由配置决定，通常在 `/var/log/mysql/`）；
- Redis：`/var/log/redis/*`（默认 `loglevel notice`，AOF/RDB 失败是重点）；
- MongoDB：`/var/log/mongodb/*`。

### 5.11 存储与文件系统（`StorageHealth`）

- `smartctl -a` 周期导出（**盘要坏之前是能看见的**：reallocated/pending sector）；
- `/var/log/fsck*`、`/proc/mdstat`（软 RAID 降级）、LVM 状态；
- `df` / inode 使用率（磁盘满 vs inode 满是两种事故）。

### 5.12 作业/调度/加速卡（`ComputeWorkload`）

- Slurm：`/var/log/slurm/*`（`slurmctld`/`slurmd`，作业失败与节点 drain）；
- Kubernetes：`journalctl -u kubelet`、`/var/log/pods/*`（与 `k8s-node-pod-metrics-spec.md` 的指标面互补）；
- GPU：`dmesg` 的 `NVRM`/`Xid`（Xid 是掉卡/ECC 的第一现场）、`nvidia-smi` 周期导出。

### 5.13 备份与批处理（`BackupJob`）

- borg / restic / rsync 的任务日志（成功也要采：**“备份没跑”和“备份失败”一样危险**）；
- cron 结果与 §5.8 交叉。

### 5.14 网络服务（`NetworkService`）

- nginx / apache 访问与错误日志；
- samba / NFS 服务日志（共享目录被谁访问、权限拒绝）。

### 5.15 主机指标（`HostMetrics`）

- CPU/负载/内存/swap：`/proc/stat`、`/proc/loadavg`、`/proc/meminfo`；
- 磁盘 IO 与容量：`/sys/block/*/stat`、`df`；
- 网络与连接：`/proc/net/dev`、`ss -s`；
- GPU：`nvidia-smi`（算力机）。

## 6. journald 采集建议

- 只读入口是 `journalctl`，不支持直接 tail 底层文件（`/var/log/journal` 是私有格式）；
- 三种可行形态，**建议优先第 2 种**（复用已实现的 file input，不动 source 类型）：

  ```
  journalctl -o json --since -5m --unit sshd            # 周期导出（面窄，可控）
  ForwardToSyslog=yes                                    # journald 转发成文件 → 走 file input
  systemd-journal-remote                                 # 集中归档（本机不落文本）
  ```
- 不要全量导出：按 unit / `SYSLOG_IDENTIFIER` 订面，每个面一个采集任务。

## 7. 权限、保留期与合规

| 关注点 | 说明 |
|---|---|
| root | `secure`/`auth.log`、DB 日志、SMART、`mdstat`、`auditd` 均需 root；agentd 以系统服务运行（见 `agentd-service-deployment.md`） |
| 保留期 | `logrotate` 通常保留数周；`journald` 默认受 `SystemMaxUse` 限制；采集端必须近实时转发 |
| 合规 | DB 日志与访问日志含业务数据与个人信息，采集面要过合规评审；只采结构化事件，避免整表搬运 |
| 完整性 | 对本地 root 攻击者，日志应尽快转发离机；本机副本仅作短期缓冲 |

## 8. 接入 warp-insight 的落地路径（分级）

| 分级 | 采集对象 | 当前状态 | 做法 |
|---|---|---|---|
| A. 现成 | `secure`/`auth.log`、`messages`/`syslog`、`dpkg.log`、DB 日志、nginx | file input 已支持 tail/checkpoint/rotate | 直接配显式路径 + 规则解析 |
| B. 需“定时导出器” | journald、`last`/`lastb`、`smartctl`、`auditd`、`nft/iptables-save` | 非追加型文本 | 周期导出成文本 → 复用 file input |
| C. 需新 source | 无 | —— | Linux 不需要 macOS 那种 predicate source |
| D. 直发 | 已结构化事件 | `[telemetry.logs.output] kind = "tcp"`（NDJSON） | 见 `macos-agent-uplink-to-warp-parse.md` |

推荐首版最小集（P0 且改动小）：`secure`/`auth.log`、`dpkg.log`/`dnf.log`、`kern.log`/`messages`（OOM）、
DB 日志（数据服务器）、SMART + `df`、主机指标。

## 9. 缺口清单（这是与 macOS 侧最大的差别）

Linux 侧目前**只有本文档**：`data-plane/models/wpl/linux/` 为空，无 OML、无 `sample.dat`。
每条采集面都还缺三件套：

| 缺口 | 产物 | 当前 |
|---|---|---|
| 真样本 | `models/wpl/linux/<面>/sample.dat`（真机采集） | 0 条 |
| WPL 规则 | `models/mac-drafts/<面>/parse.wpl` 的 Linux 对应物 | 0 条 |
| OML 富化 | `models/oml/linux_*.oml` | 0 条 |

模板侧对应结论：`linux-compute` / `linux-data` 的 `unit_refs` 现在**全部落在 `status = draft`**
（`rule_ref` 为空），因此两个模板都只能是 `draft`，不能授权投产。

## 10. 待核对记录（未做）

**尚未在任何 Linux 真机执行过**。部署前必须在目标发行版与版本上确认路径、格式与权限，建议命令：

```bash
# 发行版与日志中枢
cat /etc/os-release; systemctl is-active systemd-journald
# 文件型日志存在性与权限
ls -l /var/log/secure /var/log/auth.log /var/log/messages /var/log/syslog \
      /var/log/dpkg.log /var/log/dnf.log /var/log/cron /var/log/wtmp /var/log/btmp
# journald 是否能按 unit 导出
journalctl -o json --since -5m --unit sshd | head -n 5
# 周期导出工具存在性
command -v smartctl nft iptables-save last ausearch nvidia-smi
# 运行时指标源
head -n 3 /proc/loadavg /proc/meminfo; df -h; df -i; cat /proc/mdstat
```

## 11. 相关文档

- [`macos-security-audit-log-sources.md`](./macos-security-audit-log-sources.md)：macOS 侧的同类清单
- [`log-file-input-spec.md`](./log-file-input-spec.md)：文件输入（tail/checkpoint/rotate）设计
- [`macos-agent-uplink-to-warp-parse.md`](./macos-agent-uplink-to-warp-parse.md)：数据面上报与 `warp-parse` 角色
- `doc/design/center/agent-work-templates.md`：4 个常驻工作模板（含两个 Linux 模板的组成）
