#!/usr/bin/env bash
# 停止 wist-agentd（配合 start.sh）。
# 用法：./stop.sh
set -euo pipefail

AGENTD_HOME="${WIST_AGENTD_HOME:-${HOME}/.wist-agentd}"
PIDFILE="${AGENTD_HOME}/log/agentd.pid"

if [[ ! -f "${PIDFILE}" ]]; then
  echo "wist-agentd not running (no pidfile ${PIDFILE})"
  exit 0
fi

PID="$(cat "${PIDFILE}")"
if kill -0 "${PID}" 2>/dev/null; then
  kill "${PID}"
  echo "stopped wist-agentd pid=${PID}"
else
  echo "wist-agentd not running (stale pidfile pid=${PID})"
fi
rm -f "${PIDFILE}"
