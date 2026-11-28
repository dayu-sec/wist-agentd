# 计划签发信任锚的下发与轮换（存量机队）

> 状态：**设计稿（未实现）**。本文只描述方案与落地顺序，不代表代码已存在。
> 上游设计：[`wist-gateway/docs/design/plan-attestation.md`](../../../wist-gateway/docs/design/plan-attestation.md)
> （类型 / 规范化 / 审批 / 签名 / 验签语义），以及
> [`plan-external-signing.md`](../../../wist-gateway/docs/design/plan-external-signing.md)
> （**谁持私钥**：审批人侧 CLI，网关只收签名）。本文只回答那个文档没回答的问题：
> **已经装好的机器，公钥怎么下去、怎么换。**
>
> **分期**：第一期（外部签发 + CLI）用现有 `trusted_keys` 列表就够（一把钥匙，手工/CM 铺）；
> 本文的目录化 + 升级搭车是**第二期**，解决规模与轮换，**不是先决条件**。

## 1. 问题

`plan-attestation.md` §7 把「信任锚」定义成「本地绝对路径 + 只能来自本地」，
但它没有回答运维最关心的一条：

> 已经部署了 N 台 agentd（本次现场是 40 台）。网关要开始签发，那这 40 台的
> `[attestation] trusted_keys` 怎么填进去？换钥匙的时候又怎么换？

手工 `scp + vim + 重启` × 40 不可接受；而 agentd 侧今天**没有任何**来自网关的配置写路径。

## 2. 现状事实（决定方案边界）

| 通道 | 管什么 | 能落配置吗 | 覆盖存量机器 |
|---|---|---|---|
| `install.sh` + `initial-config` | 装机时写一次 `agentd.toml`（CA PEM 就是内联进去的） | ✅ | ❌ 只新装 |
| 升级（`action=upgrade` → `wist-upgrader`） | 换二进制 | ❌ | ❌ |
| 本地运维（ansible / CM / ssh） | 改 `/etc/wist-agentd/*` | ✅ | ✅（唯一） |

配置在 agentd 里是**纯本地**的：网关没有任何 write path 到 `agentd.toml`。
这是有意的（否则「凭什么相信这份计划」的根就交出去了），代价就是存量机队只能靠运维面。

### 2.1 一个必须先认清的事实

升级通道的 `package_url` / `package_sha256` **都由网关填**，agentd 只校验 sha256，
**没有任何签名**：

```rust
// wist-agentd/src/upgrade.rs:1226
verify_digest(&bytes, &request.package_sha256)?;
```

也就是说：能往命令队列写一条 `action=upgrade` 的人，已经能在被管机上以 agentd 的身份
（系统安装 = root）执行任意二进制。

**推论**：让网关把「签发公钥」推下去，**不会**降低当前的安全等级 —— 当前等级本来就是
「网关被控 = 全部机器被控」（`plan-attestation.md` §8.2 已明示）。

所以「怎么下发」是**工程问题**，不是会破坏设计的问题。前提只有一条：
**落盘一次、之后只读本地**，不是每轮询去要（§6）。

## 3. 设计：信任锚目录化

把信任锚从 `agentd.toml` 里的数组，扩成**一个目录**：

```
<config-dir>/attestation/keys/<key_id>.pem      # SPKI PEM（-----BEGIN PUBLIC KEY-----）
```

| 规则 | 取值 / 语义 |
|---|---|
| 默认路径 | `<config-dir>/attestation/keys`（系统安装即 `/etc/wist-agentd/attestation/keys`） |
| 覆盖 | `[attestation] trusted_key_dir = "<绝对路径>"`（新键，可选） |
| 文件名 | 即 `key_id`，只允许 `[A-Za-z0-9._-]{1,64}`（防路径穿越，落盘前再断言仍在目录内） |
| 读取时机 | **每次 review 重新扫描**（与现有「公钥每次 review 重读」一致）；不缓存、不重启 |
| 文件上限 | 单文件 8 KiB（与现有公钥读取上限一致） |
| 权限 | 目录 root 拥有，文件 `0644`（公钥是公开信息）；不允 other-write |
| 空目录 + `enforced = true` | **仍然 fail-closed**：R2/R3 全拒（`unknown_signing_key`），与「空 `trusted_keys`」同语义 |
| 无 `[attestation]` 段但目录有文件 | 采用这些锚，`enforced` 取默认 `false`（**advisory**：验但不拦） |

**为什么值得改**：现在增删 `trusted_keys` 条目要**重启**，这是 40 台上最大的操作负担；
目录化之后「放一个文件 = 钉一把钥匙」，不重启、天然支持新旧并存，且 `ls` 就是「这台机器信谁」。

**为什么这样不弱化信任**：目录由 root 拥有，能往里写 = 已经是 root；与「0600 的
`agentd.toml` 里写 `trusted_keys`」是同一等级的保证。差别只在可操作性。

### 3.1 与现有 `trusted_keys` 的关系

- 两个来源**并存**：`trusted_keys`（显式列表，兼容旧配置）+ 目录扫描结果。
- 同一个 `key_id` 在两个来源里出现且**内容不同** → 启动期直接报错（`attestation_key_conflict`），
  不猜哪个是对的（静默择一会在事故现场变成「为什么换钥匙没生效」）。
- 内容相同 → 去重，正常启动。

## 4. 三个下发面（共用同一个落点）

三个面互不冲突，按场景选：

| 场景 | 用哪个 | 是否需要改 TOML |
|---|---|---|
| 新装机 | `install.sh` 内联公钥（与 `CA_CERT` 同写法） | 否（脚本自己拼绝对路径） |
| **存量 40 台（首次铺）** | **升级命令搭车** | 否（目录默认路径已可用） |
| 日常轮换 / 补漏 / 掉队机器 | 目录 + 同步（`anchor_sync` 命令或现有 CM） | 否 |

> 注意：只有「翻 `enforced = true`」这一步必须改 TOML 并重启 —— 它是本地策略开关，
> **刻意不交给控制面**（§5.2）。

### 4.1 升级搭车（首次铺 40 台的主通道）

理由：这 40 台为了拿到目录化能力**本来就要升一次 agentd**；搭车等于零额外运维轮次。
而且升级器已经拿到 `--config-dir`（`src/upgrade.rs:977`），落文件是它职权内的事。

升级命令的 params 增加 `anchors` 数组（**内联 PEM，不走 URL**）：

```json
{
  "package_url": "https://<gateway>/api/v1/agent/packages/...",
  "package_sha256": "…",
  "anchors": [
    {
      "key_id": "gw-plan-k1",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
      "expect_sha256": "a1b2c3d4…"
    }
  ]
}
```

为什么不走 URL：公钥只有 ~113 字节，多一个下载面 = 多一次可失败、多一个可伪造地址；
内联还让「这次升级到底带了哪把钥匙」直接出现在升级记录里。

**硬规则（实现时必须逐条满足）**：

1. **锚失败不阻断升级**。写失败记进结果 `detail`（`anchors: [{key_id, status, reason}]`），
   升级本身照常完成。否则一次锚写失败会让整台机器的 agentd 回滚，代价完全不成比例。
2. **升级不带 `enforced`**。它决定「拦不拦」，是本机安全阀，必须人工/CM 决定。
3. **`key_id` 严格校验**（`[A-Za-z0-9._-]{1,64}`），落盘前 `canonicalize` 断言仍在锚目录内。
4. **原子写**：临时名 + `rename`；`0644`。
5. **幂等 + 轮换可辨**：同 `key_id` 同内容 → `skipped`；同 `key_id` 不同内容 → 覆盖并标 `rotated`。
6. **回滚不动锚**：二进制回滚 ≠ 锚回滚。锚是数据、可并存；回滚到不认目录的旧版时它被忽略。

结果回报里带 `anchors_applied: [{key_id, fingerprint}]`，页面上能回答「这台机器的锚是哪次升上来的」。

### 4.2 装机内联

`install.sh` 已经从网关拿到内联的 `CA_CERT`（`wist-gateway/src/api/install.sh:222`），
公钥走同一套写法：脚本把 PEM 写到 `$CONFIG_DIR/attestation/keys/<key_id>.pem`。
绝对路径由脚本运行期拼，因此 **agentd 不需要支持相对路径或内联公钥**。

### 4.3 目录 + 同步（长期维护面）

```json
{
  "action": "anchor_sync",
  "mode": "add",                            // add | remove | replace
  "key_id": "gw-plan-k1",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----…",
  "expect_fingerprint": "a1b2c3d4e5f60718", // 操作员在页面上核对过的指纹
  "expires_at": "2026-12-01T00:00:00Z"
}
```

agentd：校验形状 → 算指纹 → 与 `expect_fingerprint` 比对 → 原子写 → 回报。
**页面上必须显示指纹并要求操作员核对**，否则又退化成「让被控方自己决定信任谁」。

## 5. 轮换

锚一次性钉住之后，正常轮换是**分钟级、不重启**的（公钥每次 review 重读）：

```
1. 新公钥写入 keys/<new-key-id>.pem      （新旧并存）
2. 签发方切到新 key_id（CLI 用新钥匙签 / 旧形态是网关 `[plan_signing] key_id`）
3. 等旧计划全部过期（≥ attestation.ttl_seconds 与 plan.expires_at）
4. 删除 keys/<old-key-id>.pem
```

窗口必须 ≥ 已签发未执行计划的存活时间，否则在途计划会 `unknown_signing_key`。

### 5.1 为什么「升级搭车」不能当长期机制

它把「换钥匙」绑死在「发版 + 滚 40 台」上：

- 轮换窗口从分钟级拉到几天，旧钥匙暴露期同步拉长；
- 每次轮换都要发一版 agentd，只为带一个文件；
- 掉队的机器（离线 / 版本钉死）会连带锚一起掉队。

所以分工是：**首次铺走升级搭车；之后走目录 + 同步（§4.3）或已有 CM**。

### 5.2 `enforced` 为什么不能远程翻

`enforced = true` 是「拦不拦」的开关，也是出事时的第一处置动作（`plan-attestation.md` §6）。
让它可被远程改，等于把安全阀的钥匙放在被 guard 的那一侧。它的变更路径只有：
本地编辑 + 重启，或运维 CM。

## 6. 明确不做：运行时向网关拉取公钥

> 公钥**只能来自本地绝对路径**。绝不「每次向网关要公钥」：那等于让被控方自己决定信任谁。
> —— `plan-attestation.md` §7

一旦改成运行时拉取，攻击面变成：任何能改网关（admin token 泄漏、命令表可写、
进程被控）的人，先把公钥换成自己的，再塞一份自签计划 —— agentd 会验签通过。

| 攻击者能力 | 本地 pin | 运行时拉取 |
|---|---|---|
| 能往命令队列写一条计划 | 验签失败，拒绝执行 | 通过 |
| 拿到 admin token | 同上 | 同上（先换公钥即可） |
| 网关进程被控 | 能塞计划，但签不出**原来那把钥匙**的签名 | 全通 |

「下发」与「运行时拉取」的区别就是这一条：**下发是落一次盘，之后只读本地**。

## 7. 边界

- **本机 root**：可以改锚目录、改 `enforced`、绕过 agentd 直接删文件。本机制不防本地 root
  （与 `plan-attestation.md` §8.1 一致）。
- **网关被控（当前阶段）**：网关能推 root 升级包（§2.1），所以它本来就能做任何事。
  pin 的现实收益是拆开「能塞命令 ≠ 能签发」，以及为 §8 的迁移留路。
- **签发方归属（§7 的终局）**：锚钉的永远是「**站点签署钥匙**」的公钥。这把钥匙最终应该落在
  客户能控制的那侧 —— 客户的 KMS/HSM、或审批人签名机上的 `wist-approve`（
  `wist-gateway/docs/design/plan-external-signing.md`），而不是我们运维的网关进程里。
  在此之前（网关自签）pin 只能拆开「能塞命令 ≠ 能签发」；换到外部签发后，
  锚才真正代表客户授权。本文的目录化对该迁移**无影响** —— 迁移时只是换了「谁签」，
  锚还是那份 PEM，不需要动 40 台。

## 8. 存量 40 台的落地顺序

```
① agentd：锚目录化（§3）+ 升级器支持 anchors（§4.1）→ 发版
② 用 rollout 滚 40 台：锚搭车落地，enforced 保持 false（advisory）
③ 网关登记审批公钥 + 打开外部签发（若是旧的自签形态：配 [plan_signing]）
④ 金丝雀验一条 R2 → 结果 detail 看「attestation 已验签」
⑤ 分环把 enforced 改成 true（本地/CM，写一行 + 重启）
⑥ 之后轮换只放文件，不发版、不重启
```

### 8.1 版本闸（先查再铺）

`AgentConfig` 是 `deny_unknown_fields`：**agentd < 0.40 读到 `[attestation]` 会直接拒启**
（`[attestation]` 自 0.40.0 起）。铺之前先拉清单，低于 0.40 的先用升级 rollout 升上去。

### 8.2 金丝雀口径（不删任何东西）

验签只在 R2/R3 触发，所以必须走一条 R2。挑一台可牺牲的机器，用**匹配不到文件**的参数：

```
op: disk.cleanup.apply, risk: R2
args: { target: "tmp", min_age_hours: 8760, max_files: 1, max_bytes: 1 }
```

一年以上的 tmp 文件基本不存在 → 实际零删除，但整条链路（重算 digest → 查 key_id → 验签 →
政策下限）全走一遍。结果 `detail` 应出现 `attestation 已验签`。

### 8.3 盘点（40 台必需）

否则事后没人说得清哪台钉了哪把钥匙：

- 每台：`ls /etc/wist-agentd/attestation/keys/` + 升级记录里的 `anchors_applied`；
- 全局：管理面列「agent / 锚 key_id / 指纹 / 最近一次升级时间」。

## 9. 各仓待改点（实现清单）

> 本节是**第二期（锚目录化 + 搭车）**的工作，不是 CLI 审批的前置。
> 第一期（外部签发 + CLI）用现有的 `trusted_keys` 列表就够，**不需要动 agentd**。
> 实施顺序见 `wist-gateway/docs/design/plan-approval-signing-impl.md`。

| 仓 | 改动 |
|---|---|
| `wist-agentd` | `AgentConfig` 加 `trusted_key_dir`；`validate.rs` 只校验形状；`attestation.rs` 目录扫描 + 逐文件降级（不整体失败）+ 冲突告警；`upgrade.rs` 支持 `anchors`（六条硬规则）；`wist-upgrader` 落盘 |
| `wist-gateway` | 升级派活处填 `anchors`（`src/api/rollout_ops.rs` 与一次性 upgrade 路径）；`anchor_sync` 命令与页面确认指纹 |
| `wist-gateway-web` | 展示锚指纹 / 已铺未铺；`anchor_sync` 的确认交互 |

> **`wist-gateway-stack` 不在本期改动内。** 站点签署钥匙由**审批人侧**（`wist-approve key generate`）
> 生成，不应在网关宿主上生成 —— 在栈里生成等于又把私钥放回我们的机器。
> （旧文里的 `init-plan-signing.sh` / `[plan_signing]` 模板块只属于「网关自签」旧形态，已删除。）

## 10. 未决问题

1. `trusted_key_dir` 是否允许**多个**目录（多来源：本机 CM 与网关各一个）？本期按单目录设计。
2. `anchor_sync` 是否需要走审批（R2 风格）？信任锚变更影响面大于单次清理，倾向 R2 或至少双人确认。
3. 锚目录是否需要「生效时间」（`active_from`）以支持预约轮换？本期不做。
