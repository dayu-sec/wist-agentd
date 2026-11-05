# Doris 指标采集（P0：BE 存活 / 容量 / tablet）

> 状态：**P0 已落地**（2026-11-05）。域 `doris_metrics` 已在 `wist-metrics 0.17.0` 注册。
> 运行时与凭据 key 的规则见 [mysql-metrics.md](./mysql-metrics.md) §3 —— 与 MySQL 同一套。

## 1. 能力边界（重要）

| 本机有什么 | 能不能采 | 说明 |
|---|---|---|
| FE（含单机 FE+BE 混部） | ✅ | 连 FE 的 MySQL 协议口（默认 9030），读 `SHOW BACKENDS` |
| 只有 BE | ❌ | `SHOW BACKENDS` 是 **FE** 的命令；连 BE 拿不到集群视图 |

这条边界是**故意的**：与其在只有 BE 的机器上猜一个远端 FE 地址（会把「猜地址」的活搬回
控制面、也打开 SSRF 面），不如老实不出指标 —— `doctor` 的 `discovery.doris` 和
`event=DorisProbeNoEndpoint` 都会说清楚。

## 2. 采什么

| 指标 | 事实键 | 类型 | label |
|---|---|---|---|
| `doris_be_up` | `doris.be.up` | gauge | `be` |
| `doris_be_capacity_bytes` | `doris.be.capacity_bytes` | gauge | `be` |
| `doris_be_available_bytes` | `doris.be.available_bytes` | gauge | `be` |
| `doris_be_tablets` | `doris.be.tablets` | gauge | `be` |

`be` = `IP:HeartbeatPort`（BE 没了端口就退回 IP）。

**为什么按 BE 拆**：一台 FE 管多台 BE。只报合计会把「一台写满、其余空闲」看成
「整体还有 60%」，而这正是最需要被看见的时刻。

**掉线的 BE 只出 `up=0`**，不出容量与 tablet：那几个列此时是上一轮的残留或 0，
按 0 报等于伪造。

## 3. 怎么连

```
用户：wist-probe
密码：/etc/wist-agentd/secrets/doris/<key>/password
CA  ：/etc/wist-agentd/secrets/doris/<key>/ca.pem（可选）
```

FE 上创建一个只读账号即可（Doris 的权限模型里 `SHOW BACKENDS` 需要 admin 或
`ADMIN_PRIV`；若不想给太高权限，用 **Node 级别的只读运维账号**）：

```sql
CREATE USER 'wist_probe' IDENTIFIED BY '<随机密码>';
GRANT ADMIN_PRIV ON *.*.* TO 'wist_probe';
```

> Doris 没有更细的「只看节点」权限：`SHOW BACKENDS` 属于管理语句。
> 如果客户不接受，替代方案是只用 FE 的 HTTP 接口（`/api/show_proc`）——
> 那是另一个传输，作为 P1 的可选项，不在本轮。

## 4. 失败怎么表现

| 情况 | 表现 |
|---|---|
| 本机没有 FE | 不出现 `doris_metrics` 域（`doctor` 里一行说明） |
| `SHOW BACKENDS` 失败 / 返回空 | 整轮 `attempted=1 / failed=1`，不造样本 |
| 某台 BE `Alive=false` | 该 BE 只出 `doris_be_up=0`，并留一条「N / M 台 BE 未存活」warning |
| 容量列解析不了（非数字/未知单位） | 丢那一条 + warning，不猜 |

容量列在 `SHOW BACKENDS` 里是**带单位的人类可读串**（`1.000 TB`），
采集侧按 1024 进制换算成字节。

## 5. 测试

- 采集：假 `SqlTransport` 注入 `SHOW BACKENDS` 结果，覆盖按 BE 拆分、掉线 BE 只报 up、
  空列表、查询失败、容量单位解析；
- 自探：假 `DbProc` + 假握手，覆盖 FE 识别、BE 排除、HTTP 端口被握手筛掉；
- **真集群未跑**：本机没有 Doris；有环境时补 `#[ignore]` live 用例。
