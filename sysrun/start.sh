#!/usr/bin/env bash
# 启动 wist-agentd（macOS P0 采集实例）。
#
# 运行布局：
#   仓库 sysrun/           只放启停脚本（start.sh / stop.sh）
#   ~/.wist-agentd/        配置 agentd.toml + tasks/ + 运行时数据 run|state|log/
#
# 用法：
#   ./start.sh              常驻后台（pid/log 落 ~/.wist-agentd/log/）
#   ./start.sh --foreground 前台运行（联调看日志）
# 停止：./stop.sh
#
# 可覆盖 env：
#   WIST_AGENTD_BIN         wist-agentd 可执行文件（默认 crate 根 target/debug/wist-agentd）
#   WIST_AGENTD_CONFIG_DIR  配置目录（默认 ~/.wist-agentd，须含 agentd.toml）
#   WIST_AGENTD_HOME        运行时数据 home（默认 ~/.wist-agentd）
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# 本脚本位于 wist-agentd/sysrun/，crate 根（含 target/debug）是上一级目录。
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

AGENTD_HOME="${WIST_AGENTD_HOME:-${HOME}/.wist-agentd}"
CONFIG_DIR="${WIST_AGENTD_CONFIG_DIR:-${AGENTD_HOME}}"
LOG_DIR="${AGENTD_HOME}/log"
PIDFILE="${LOG_DIR}/agentd.pid"

resolve_bin() {
  if [[ -n "${WIST_AGENTD_BIN:-}" ]]; then
    printf '%s\n' "${WIST_AGENTD_BIN}"
  else
    printf '%s\n' "${CRATE_ROOT}/target/debug/wist-agentd"
  fi
}

BIN="$(resolve_bin)"

if [[ "${1:-}" == "--foreground" ]]; then
  echo "wist-agentd foreground: ${BIN} --config-dir ${CONFIG_DIR}"
  exec "${BIN}" --config-dir "${CONFIG_DIR}"
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1,28p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} //'
  exit 0
fi

if [[ ! -x "${BIN}" ]]; then
  echo "wist-agentd binary not found: ${BIN}" >&2
  echo "请先在 wist-agentd 目录 cargo build，或设置 WIST_AGENTD_BIN 指向可执行文件" >&2
  exit 1
fi
if [[ ! -f "${CONFIG_DIR}/agentd.toml" ]]; then
  echo "missing agentd.toml: ${CONFIG_DIR}/agentd.toml" >&2
  exit 1
fi
mkdir -p "${LOG_DIR}"

if [[ -f "${PIDFILE}" ]]; then
  OLD_PID="$(cat "${PIDFILE}")"
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    echo "wist-agentd already running (pid=${OLD_PID}, ${PIDFILE})" >&2
    exit 1
  fi
  echo "removing stale pidfile ${PIDFILE}" >&2
  rm -f "${PIDFILE}"
fi

# 直接后台启动（去掉 nohup：nohup 在 macOS 上会 fork，导致 $! 是 wrapper pid 而非
# agentd 真实 pid，pidfile 记录错 pid，stop.sh 就杀不掉、下次 start 又起新进程）。
# disown 让进程在 shell 退出时不被 SIGHUP。
"${BIN}" --config-dir "${CONFIG_DIR}" >>"${LOG_DIR}/agentd.out" 2>&1 &
AGENT_PID=$!
echo "${AGENT_PID}" >"${PIDFILE}"
disown "${AGENT_PID}" 2>/dev/null || true

echo "wist-agentd started pid=${AGENT_PID}"
echo "  binary    : ${BIN}"
echo "  config-dir: ${CONFIG_DIR}"
echo "  stdout log: ${LOG_DIR}/agentd.out"
echo "  stop      : ${SCRIPT_DIR}/stop.sh"
