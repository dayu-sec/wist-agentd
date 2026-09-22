#!/usr/bin/env bash
# 用**本机编译产物**安装/更新 wist-agentd 常驻服务（开发机自用）。
#
# 与两个邻居的分工，别混：
#   install.sh（网关签发的那份）  从网关下载包 → 校验摘要 → 写初始配置 → 注册服务。生产/批量用。
#   sysrun/start.sh               开发态后台跑（pidfile + disown，**无自启、无崩溃拉起**），
#                                 配置读 ~/.wist-agentd —— 不是服务，`re-enroll.sh` 配的是这一套。
#   本脚本                        把 <crate>/target/release 里刚编出来的二进制装成**常驻服务**
#                                 并重启，供“我想让本机跑的就是我刚改的代码”用。
#
# 它**不下载任何东西**、不写初始配置、不碰注册与凭据 —— 升级前后 enrollment 与 state 保持不变
# （state 是 schema 化 JSON，不丢 checkpoint）。
#
# 用法：
#   sysrun/install-local.sh                  # 构建 → 备份旧二进制 → 换上 → 重启服务 → 验证
#   sysrun/install-local.sh --dry-run        # 只打印将执行的命令，不落任何字
#   sysrun/install-local.sh --rollback       # 换回最近一次备份并重启
#   SKIP_BUILD=1 sysrun/install-local.sh     # 不重新构建，用现有产物
#
# 前置：请以**普通用户**运行（不要 sudo）。需要 root 的步骤脚本自己提权 ——
# 若整个脚本以 root 跑，`cargo build` 会让 target/ 变成 root 属主，之后普通用户就构建不动了。
#
# 可覆盖 env：
#   WIST_AGENTD_SCOPE=system|user  安装作用域（默认 system，与 install.sh 同名同义）
#   WIST_AGENTD_BIN_DIR=<dir>      二进制目录（默认 /usr/local/bin | ~/bin）
#   WIST_AGENTD_HOME=<dir>         配置目录（默认 /etc/wist-agentd | ~/.wist-agentd）
#   WIST_AGENTD_BIN_SRC=<dir>      产物目录（默认 <crate>/target/release）
#   SKIP_BUILD=1                   跳过 cargo build
#   WIST_AGENTD_INSTALL_DRY_RUN=1  等价于 --dry-run
#   WIST_AGENTD_READY_WAIT_SECS    重启后就绪等待上限（默认 30s）
#
# 注意：`service install --force` 会按 bin/config-dir **重渲染服务定义**（等价于当前定义）。
# 手工改过 plist/unit 的内容会被覆盖 —— 要保留就改本脚本传的参数，别直接改定义文件。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# 与 src/service/mod.rs 的常量一致：改那里就得改这里（不一致的话重启会打到别的服务上）。
SERVICE_NAME="wist-agentd"
EXEC_NAME="wist-exec"
LAUNCHD_LABEL="com.dayu-sec.wist-agentd"

SCOPE="${WIST_AGENTD_SCOPE:-system}"
BIN_SRC_DIR="${WIST_AGENTD_BIN_SRC:-${CRATE_ROOT}/target/release}"
SKIP_BUILD="${SKIP_BUILD:-0}"
DRY_RUN="${WIST_AGENTD_INSTALL_DRY_RUN:-0}"
READY_WAIT_SECS="${WIST_AGENTD_READY_WAIT_SECS:-30}"

MODE="install"
ALLOW_STALE=0

# ---------------------------------------------------------------- 输出约定
# `==>` 是脚本自己推进的步骤；缩进的是外部工具的输出 —— 这样一眼能看出停在哪一步、
# 哪一行是谁打的。只在交互终端上色，重定向到文件时退化为纯文本。
if [ -t 1 ]; then
  BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"
  GREEN="$(printf '\033[32m')"; RED="$(printf '\033[31m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; DIM=""; GREEN=""; RED=""; RESET=""
fi
step() { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RESET"; }
note() { printf '    %s\n' "$1"; }
dim() { printf '    %s%s%s\n' "$DIM" "$1" "$RESET"; }
pass() { printf '    %sPASS%s  %s\n' "$GREEN" "$RESET" "$1"; }
bad() { printf '    %sFAIL%s  %s\n' "$RED" "$RESET" "$1" >&2; }
die() { printf '%s%s%s\n' "$RED" "$1" "$RESET" >&2; exit 2; }

usage() { awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --rollback) MODE="rollback" ;;
    --allow-stale) ALLOW_STALE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

run() {
  if [ "${DRY_RUN}" = "1" ]; then
    printf '    %s[dry-run]%s %s\n' "$DIM" "$RESET" "$*"
    return 0
  fi
  "$@"
}

# 轮询到条件成立或超时：launchd/systemd 是异步拉起进程的，刚重启完立刻断言必假失败。
wait_until() {
  local limit="$1" desc="$2"
  shift 2
  local waited=0
  while [ "${waited}" -lt "${limit}" ]; do
    if "$@" >/dev/null 2>&1; then
      [ "${waited}" -gt 0 ] && note "${desc}：等了 ${waited}s 才就绪"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

case "$(uname -s)" in
  Darwin) PLATFORM="launchd" ;;
  Linux) PLATFORM="systemd" ;;
  *) die "unsupported platform: $(uname -s) (macOS launchd / Linux systemd only)" ;;
esac

case "${SCOPE}" in
  system)
    SCOPE_ARG="--system"
    BIN_DST_DIR="${WIST_AGENTD_BIN_DIR:-/usr/local/bin}"
    CONFIG_DIR="${WIST_AGENTD_HOME:-/etc/wist-agentd}"
    LOG_DIR="/var/log/wist-agentd"
    SERVICE_TARGET="system/${LAUNCHD_LABEL}"
    ;;
  user)
    SCOPE_ARG="--user"
    BIN_DST_DIR="${WIST_AGENTD_BIN_DIR:-${HOME}/bin}"
    CONFIG_DIR="${WIST_AGENTD_HOME:-${HOME}/.wist-agentd}"
    LOG_DIR="${HOME}/Library/Logs/wist-agentd"
    SERVICE_TARGET="gui/$(id -u)/${LAUNCHD_LABEL}"
    ;;
  *) die "WIST_AGENTD_SCOPE 只能是 system 或 user，收到 ${SCOPE}" ;;
esac

# system 作用域要 root：脚本自己提权（而不是要求外层 sudo —— 那会把 cargo build 也变成 root）。
if [ "${SCOPE}" = "system" ]; then
  SUDO="sudo"
else
  SUDO=""
fi

DEST_BIN="${BIN_DST_DIR}/${SERVICE_NAME}"
DEST_EXEC="${BIN_DST_DIR}/${EXEC_NAME}"
SRC_BIN="${BIN_SRC_DIR}/${SERVICE_NAME}"
SRC_EXEC="${BIN_SRC_DIR}/${EXEC_NAME}"

short() {
  case "$1" in
    "$HOME"/*) printf '~%s' "${1#"$HOME"}" ;;
    *) printf '%s' "$1" ;;
  esac
}
sha12() { shasum -a 256 "$1" 2>/dev/null | awk '{print substr($1, 1, 12)}'; }

# ---------------------------------------------------------------- 运行状态查询

service_is_running() {
  if [ "${PLATFORM}" = "launchd" ]; then
    # system 域可免 sudo 查询；user 域本来就是当前用户。
    launchctl print "${SERVICE_TARGET}" 2>/dev/null | grep -q 'state = running'
  else
    if [ "${SCOPE}" = "system" ]; then
      systemctl is-active --quiet "${SERVICE_NAME}"
    else
      systemctl --user is-active --quiet "${SERVICE_NAME}"
    fi
  fi
}

service_program_path() {
  if [ "${PLATFORM}" = "launchd" ]; then
    launchctl print "${SERVICE_TARGET}" 2>/dev/null |
      awk -F'= ' '/^[[:space:]]*program = /{print $2; exit}'
  else
    if [ "${SCOPE}" = "system" ]; then
      systemctl show -p ExecStart --value "${SERVICE_NAME}" 2>/dev/null
    else
      systemctl --user show -p ExecStart --value "${SERVICE_NAME}" 2>/dev/null
    fi
  fi
}

# 服务定义文件在不在 —— 这是「首次安装」比配置可读性更可靠的判据：
# 系统级的 /etc/wist-agentd 对普通用户不可读，拿它判断会得出假结论。
service_definition_present() {
  if [ "${PLATFORM}" = "launchd" ]; then
    if [ "${SCOPE}" = "system" ]; then
      [ -f "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" ]
    else
      [ -f "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist" ]
    fi
  else
    if [ "${SCOPE}" = "system" ]; then
      [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]
    else
      [ -f "${HOME}/.config/systemd/user/${SERVICE_NAME}.service" ]
    fi
  fi
}

# ---------------------------------------------------------------- 步骤

preflight() {
  step "preflight"

  if [ "$(id -u)" = "0" ] && [ "${DRY_RUN}" != "1" ]; then
    die "别用 root 跑本脚本：cargo build 会让 target/ 变成 root 属主。
  用普通用户运行，需要 root 的步骤脚本会自己 sudo。"
  fi
  if [ "${SCOPE}" = "user" ] && [ "$(id -u)" = "0" ]; then
    die "user 作用域必须以目标用户身份安装（launchd gui 域/systemd --user 都属于该会话用户），不能 sudo。"
  fi

  note "platform=${PLATFORM} scope=${SCOPE} uid=$(id -u) dry_run=${DRY_RUN} mode=${MODE}"
  note "产物目录 ${BIN_SRC_DIR}"
  note "目标目录 $(short "${BIN_DST_DIR}")　配置目录 $(short "${CONFIG_DIR}")"
  note "服务目标 ${SERVICE_TARGET}"

  if ! service_definition_present; then
    note "没找到服务定义：这是一次**首次安装**（换二进制 + 注册服务，不写初始配置、不注册身份）"
    note "      要完成注册请用网关签发的 install.sh；dev 栈那套（~/.wist-agentd + sysrun/start.sh）是另一回事"
  fi

  # 系统级布局的前提：配置目录必须是 /etc/wist-agentd。落到别处 agentd 就不再当系统级
  # 看待（见 config_runtime 的 is_system_config_dir），数据/日志会退回配置目录下。
  if [ "${SCOPE}" = "system" ] && [ "${CONFIG_DIR}" != "/etc/wist-agentd" ]; then
    note "提醒：system 作用域但配置目录是 ${CONFIG_DIR}（非 /etc/wist-agentd）"
    note "      agentd 不把它当系统级，数据/日志不会落到 /var/lib|/var/log/wist-agentd"
  fi

  local current
  current="$(service_program_path || true)"
  if [ -n "${current}" ] && [ "${current}" != "${DEST_BIN}" ]; then
    # 本机曾同时存在 user/system 两套安装时最容易踩：换的是 A，跑的是 B。
    note "注意：当前服务跑的是 ${current}"
    note "      本脚本会把它改成 ${DEST_BIN}（service install --force 重写定义）"
  fi
}

build() {
  step "构建 release 产物"
  if [ "${SKIP_BUILD}" = "1" ]; then
    note "SKIP_BUILD=1：跳过 cargo build"
  else
    run cargo build --release --manifest-path "${CRATE_ROOT}/Cargo.toml"
  fi

  if [ "${DRY_RUN}" != "1" ]; then
    [ -x "${SRC_BIN}" ] || die "缺少 ${SRC_BIN}（先 cargo build --release，或用 WIST_AGENTD_BIN_SRC 指定）"
    [ -x "${SRC_EXEC}" ] || die "缺少 ${SRC_EXEC}（wist-exec 必须与 wist-agentd 一起换，版本错配会让执行类任务失败）"
  fi

  # 防“装了一个跟源码不一致的旧产物”：这种假成功最难查。
  if [ "${DRY_RUN}" != "1" ] && [ "${ALLOW_STALE}" != "1" ]; then
    local stale
    stale="$(find "${CRATE_ROOT}/src" "${CRATE_ROOT}/Cargo.toml" -type f -newer "${SRC_BIN}" 2>/dev/null | head -1 || true)"
    if [ -n "${stale}" ]; then
      die "产物比源码旧（如 ${stale#"${CRATE_ROOT}/"}）：先构建（或加 --allow-stale 明确表示要用旧产物）"
    fi
  fi

  if [ "${DRY_RUN}" != "1" ]; then
    note "$(basename "${SRC_BIN}")  $(sha12 "${SRC_BIN}")  $(date -r "${SRC_BIN}" '+%F %T')  $("${SRC_BIN}" --version 2>/dev/null || echo '?')"
  fi
}

swap_binaries() {
  step "备份并替换二进制"

  local ts
  ts="$(date '+%Y%m%d-%H%M%S')"
  local bak_bin="${DEST_BIN}.bak-${ts}"
  local bak_exec="${DEST_EXEC}.bak-${ts}"

  # 两个各自判存在：只换了其中一个（上次脚本中断、或有人手工拷过）时，
  # 无条件的 cp 会以一条看不懂的错误把整个脚本打断。
  if [ -f "${DEST_BIN}" ]; then
    note "旧 $(basename "${DEST_BIN}")  $(sha12 "${DEST_BIN}")  → 备份为 $(short "${bak_bin}")"
    run ${SUDO} cp -p "${DEST_BIN}" "${bak_bin}"
  else
    note "$(short "${DEST_BIN}") 不存在：这是一次**首次安装**（只装服务，不写配置、不注册）"
    bak_bin=""
  fi
  if [ -f "${DEST_EXEC}" ]; then
    run ${SUDO} cp -p "${DEST_EXEC}" "${bak_exec}"
  else
    bak_exec=""
  fi

  # 先落 .new 再 mv：mv 是原子改名（换 inode），而原地覆盖旧 inode 踩过坑 ——
  # 运行中的进程/随后 exec 会抓到旧内容。两个二进制都走同一条路径。
  local src_hash
  src_hash="$(sha12 "${SRC_BIN}")"
  for pair in "${SRC_BIN}:${DEST_BIN}" "${SRC_EXEC}:${DEST_EXEC}"; do
    local src="${pair%%:*}" dst="${pair##*:}"
    run ${SUDO} install -m 0755 "${src}" "${dst}.new"
    run ${SUDO} mv -f "${dst}.new" "${dst}"
  done

  if [ "${DRY_RUN}" = "1" ]; then
    note "将换上 $(basename "${DEST_BIN}")  ${src_hash}"
  else
    # 后置校验：换完的目标必须与产物逐字节一致。拷贝失败/写到了别处都在这里被拦住。
    local dst_hash
    dst_hash="$(sha12 "${DEST_BIN}")"
    if [ "${dst_hash}" = "${src_hash}" ]; then
      note "新 $(basename "${DEST_BIN}")  ${dst_hash}"
    else
      bad "换上后的摘要不符：产物 ${src_hash}，目标 ${dst_hash}"
      note "回滚：$(basename "${BASH_SOURCE[0]}") --rollback"
      return 1
    fi
  fi
  if [ -n "${bak_bin}" ]; then
    note "回滚：$(short "${SCRIPT_DIR}")/$(basename "${BASH_SOURCE[0]}") --rollback"
  fi
}

restart_service() {
  step "重写服务定义并重启（service install --force）"
  # 用刚装上去的那个二进制来渲染定义：它的 `--bin` 默认值就是「当前可执行文件」，
  # 所以必须显式传 --bin/--config-dir，别指望默认值猜对。
  run ${SUDO} "${DEST_BIN}" service install "${SCOPE_ARG}" --force \
    --bin "${DEST_BIN}" --config-dir "${CONFIG_DIR}"
}

rollback() {
  step "回滚到最近一次备份"

  local newest ts
  newest="$(ls -1 "${DEST_BIN}.bak-"* 2>/dev/null | sort | tail -1 || true)"
  if [ -z "${newest}" ]; then
    die "找不到备份（${DEST_BIN}.bak-*）：本脚本没在这台机器上装过，或备份已被清理"
  fi
  ts="${newest##*.bak-}"
  note "备份时间戳 ${ts}"

  for pair in "${newest}:${DEST_BIN}" "${DEST_EXEC}.bak-${ts}:${DEST_EXEC}"; do
    local src="${pair%%:*}" dst="${pair##*:}"
    [ -f "${src}" ] || die "缺少备份文件 ${src}"
    run ${SUDO} install -m 0755 "${src}" "${dst}.new"
    run ${SUDO} mv -f "${dst}.new" "${dst}"
  done
  note "已换回 $(sha12 "${DEST_BIN}")"

  restart_service
}

verify() {
  step "验证"

  if [ "${DRY_RUN}" = "1" ]; then
    note "dry-run：跳过验证"
    return 0
  fi

  if wait_until "${READY_WAIT_SECS}" "服务就绪" service_is_running; then
    pass "服务在跑（${SERVICE_TARGET}）"
  else
    bad "等了 ${READY_WAIT_SECS}s 服务仍未 running"
    note "看日志：$(short "${LOG_DIR}")/agentd.err"
    note "回滚：$(basename "${BASH_SOURCE[0]}") --rollback"
    return 1
  fi

  local program
  program="$(service_program_path || true)"
  if [ "${program}" = "${DEST_BIN}" ]; then
    pass "服务跑的就是 ${DEST_BIN}"
  else
    bad "服务定义里的程序仍是 ${program:-<未知>}（期望 ${DEST_BIN}）"
    return 1
  fi

  local installed_version src_version
  installed_version="$("${DEST_BIN}" --version 2>/dev/null || echo '?')"
  src_version="$("${SRC_BIN}" --version 2>/dev/null || echo '?')"
  if [ "${installed_version}" = "${src_version}" ]; then
    pass "版本一致：${installed_version}（版本号相同时靠 sha256 区分，见上一步）"
  else
    bad "版本不一致：已装 ${installed_version}，产物 ${src_version}"
    return 1
  fi

  if [ "${PLATFORM}" = "launchd" ]; then
    printf '    %s启动行：%s\n' "$DIM" "$RESET"
    ${SUDO} tail -n 3 "${LOG_DIR}/agentd.err" 2>/dev/null | sed 's/^/      /' || true
  fi
  return 0
}

# ---------------------------------------------------------------- main

step "用本机产物安装/更新 wist-agentd 常驻服务"
if [ "${MODE}" = "rollback" ]; then
  preflight
  rollback
  verify
else
  preflight
  build
  swap_binaries
  restart_service
  verify
fi

step "完成"
note "日志：$(short "${LOG_DIR}")/agentd.err"
note "状态：${DEST_BIN} service status ${SCOPE_ARG}"
if [ "${MODE}" = "install" ]; then
  note "确认本轮新功能是否在跑：grep -E 'DiscoveryPolicy' $(short "${LOG_DIR}")/agentd.err"
  note "  （没配策略表时会是 discovery policy fetch failed: HTTP 503，属预期：拉不到就用内建周期）"
fi
