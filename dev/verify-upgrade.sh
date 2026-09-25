#!/usr/bin/env bash
# 升级链路的验收入口：单元 + 集成两层一次跑完。
#
#   bash dev/verify-upgrade.sh
#
# 覆盖：
#   * 单元（`src/upgrade.rs` 的 tests）：取包 / 验摘要 / 解包 / 让新件自报版本 / 换件 / 回滚
#     的每个零件，以及心跳的新鲜度判定；
#   * 集成（`tests/upgrade_e2e.rs`）：整条链路跑通 —— 升级成功、新版起不来回滚、
#     重启命令失败回滚、摘要不符不换件、裸包装机器回滚不留半套新件、
#     回退自己失败时报 failed 而不是 rolled_back。
#
# **不覆盖**（刻意）真机上那一段：真实 launchd / systemd 拉起与重启。
# 那需要一个服务管理器与（走网关时）一次真实派活，见 `dev/verify-system-install.sh`
# 与网关的 `admin/agents/{id}/work` 端点；本脚本全程在临时目录里跑假件，不要 root。
#
# 为什么要桩掉「重启」：`wist-upgrader apply --apply` 默认的重启手段是**本机的
# launchd / systemctl**，在开发机上直接跑它会把真的 agentd 服务重启掉。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${CRATE_ROOT}"

step() { printf '\n==> %s\n' "$*"; }
fail() {
  printf 'verify-upgrade: %s\n' "$*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail "找不到 cargo"

step "单元：升级器零件（src/upgrade.rs）"
cargo test --lib upgrade:: -- --nocapture

step "集成：整条链路（tests/upgrade_e2e.rs）"
cargo test --test upgrade_e2e -- --nocapture

printf '\n升级链路验收通过：单元 + 集成全绿。\n'
printf '真机上的那一段（服务管理器真实重启）请另跑 dev/verify-system-install.sh。\n'
