#!/usr/bin/env bash
# wist-agentd 系统级安装真机验收（需要 root，显式触发）。
#
# 覆盖自动测试覆盖不到的两类内容：
#   1) systemd / launchd 的**真实加载**：enabled、running、崩溃拉起、单实例
#   2) 系统级**目录落点成功路径**：/etc/wist-agentd 配置、/var/lib/wist-agentd 数据（含采集输出）、
#      /var/log/wist-agentd 日志
#
# 用法：
#   sudo sysrun/verify-system-install.sh                 # 全量验收（装服务 → 轮询就绪 → 断言 → 清理）
#   sudo sysrun/verify-system-install.sh --keep          # 验收后保留安装（不自动清理）
#   sudo sysrun/verify-system-install.sh --after-reboot  # 重启后复检“自启 + 仍在跑”
#   sudo sysrun/verify-system-install.sh --cleanup       # 清理本脚本安装的东西
#
# 可覆盖 env：
#   WIST_VERIFY_BIN_DIR    release 二进制目录（默认 <crate>/target/release）
#   WIST_VERIFY_DRY_RUN=1  只打印将要执行的命令（非 root 也可跑）
#   WIST_VERIFY_ENDPOINT / WIST_VERIFY_TOKEN  给了就顺带验收注册（token 不落盘）
#   WIST_VERIFY_RESTART_WAIT_SECS  崩溃拉起等待上限（默认 40s）
#   WIST_VERIFY_READY_WAIT_SECS    服务就绪等待上限（默认 30s）
#
# 注意：本脚本会在**本机**创建 /etc/wist-agentd、/var/lib/wist-agentd、/var/log/wist-agentd，
# 并把两个二进制放到 /usr/local/bin；请在一次性验收机上执行，别在跑着正式 agent 的机器上跑。
# 有 FAIL 时会**保留现场**并自动 dump 诊断（日志尾部、launchctl/systemctl 详情、前台直跑输出）。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BIN_SRC_DIR="${WIST_VERIFY_BIN_DIR:-${CRATE_ROOT}/target/release}"
BIN_DST_DIR="/usr/local/bin"
CONFIG_DIR="/etc/wist-agentd"
DATA_DIR="/var/lib/wist-agentd"
LOG_DIR="/var/log/wist-agentd"
SERVICE_NAME="wist-agentd"
LAUNCHD_LABEL="com.dayu-sec.wist-agentd"
MARKER_FILE="${CONFIG_DIR}/.verify-script"
SAMPLE_LOG="/var/tmp/wist-verify-sample.log"
RECORD_FILE="${DATA_DIR}/data/wist-records.ndjson"
RESTART_WAIT_SECS="${WIST_VERIFY_RESTART_WAIT_SECS:-40}"
READY_WAIT_SECS="${WIST_VERIFY_READY_WAIT_SECS:-30}"
DRY_RUN="${WIST_VERIFY_DRY_RUN:-0}"
KEEP=0
MODE="verify"

AGENTD_BIN="${BIN_DST_DIR}/${SERVICE_NAME}"

PASS_COUNT=0
FAIL_COUNT=0

usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --after-reboot) MODE="after-reboot" ;;
    --cleanup) MODE="cleanup" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

pass() { printf '  PASS  %s\n' "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { printf '  ....  %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

run() {
  if [ "${DRY_RUN}" = "1" ]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

# 轮询到条件成立或超时：launchd/systemd 是异步拉起进程的，刚 install 完立刻断言必假失败。
wait_until() {
  local limit="$1" desc="$2"
  shift 2
  local waited=0
  while [ "${waited}" -lt "${limit}" ]; do
    if "$@" >/dev/null 2>&1; then
      [ "${waited}" -gt 0 ] && info "${desc}：等了 ${waited}s 才就绪"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

case "$(uname -s)" in
  Linux) PLATFORM="systemd" ;;
  Darwin) PLATFORM="launchd" ;;
  *) echo "unsupported platform: $(uname -s) (Linux systemd / macOS launchd only)" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------- preflight

preflight() {
  step "preflight"
  if [ "$(id -u)" != "0" ] && [ "${DRY_RUN}" != "1" ]; then
    echo "需要 root：请用 sudo 运行（或设 WIST_VERIFY_DRY_RUN=1 只看将执行的命令）" >&2
    exit 2
  fi
  info "platform=${PLATFORM} uid=$(id -u) dry_run=${DRY_RUN}"

  if [ ! -x "${BIN_SRC_DIR}/${SERVICE_NAME}" ] || [ ! -x "${BIN_SRC_DIR}/wist-exec" ]; then
    echo "缺少可执行文件：${BIN_SRC_DIR}/{${SERVICE_NAME},wist-exec}（先 cargo build --release，或用 WIST_VERIFY_BIN_DIR 指定）" >&2
    exit 2
  fi

  # 防止验收一个跟源码不一致的旧二进制（假失败/假成功都很难查）。
  local stale_src
  stale_src="$(find "${CRATE_ROOT}/src" "${CRATE_ROOT}/Cargo.toml" \
    -type f -newer "${BIN_SRC_DIR}/${SERVICE_NAME}" 2>/dev/null | head -1 || true)"
  if [ -n "${stale_src}" ]; then
    echo "release 二进制比源码旧（如 ${stale_src}）：先 cargo build --release（别用 sudo，避免 target/ 变 root 属主）再验收" >&2
    exit 2
  fi
  info "release 二进制：${BIN_SRC_DIR}（构建于 $(date -r "${BIN_SRC_DIR}/${SERVICE_NAME}" '+%F %T')，版本 $("${BIN_SRC_DIR}/${SERVICE_NAME}" version 2>/dev/null || echo '?'))"

  if [ -e "${MARKER_FILE}" ]; then
    info "检测到本脚本上次的安装标记：${MARKER_FILE}"
  elif [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ] ||
    [ -f "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" ]; then
    echo "本机已有 wist-agentd 系统级安装痕迹；请先 --cleanup 或换一台干净机器验收" >&2
    exit 2
  fi
}

# ------------------------------------------------------- service accessors

# 服务定义落盘位置（按平台）。
definition_path() {
  case "${PLATFORM}" in
    systemd) printf '%s\n' "/etc/systemd/system/${SERVICE_NAME}.service" ;;
    launchd) printf '%s\n' "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" ;;
  esac
}

service_main_pid() {
  case "${PLATFORM}" in
    systemd) systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || true ;;
    launchd) launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | awk '/pid = /{print $3; exit}' || true ;;
  esac
}

service_is_running() {
  case "${PLATFORM}" in
    systemd) [ "$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true)" = "active" ] ;;
    launchd) launchctl print "system/${LAUNCHD_LABEL}" 2>/dev/null | grep -q 'state = running' ;;
  esac
}

service_is_enabled() {
  case "${PLATFORM}" in
    systemd) [ "$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || true)" = "enabled" ] ;;
    launchd) launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 ;;
  esac
}

dirs_ready() {
  [ -d "${DATA_DIR}/run" ] && [ -d "${DATA_DIR}/state" ] && [ -d "${LOG_DIR}" ]
}

status_reports_running() {
  "${AGENTD_BIN}" service status --system 2>/dev/null | grep -q '^running=true$'
}

read_startup_line() {
  case "${PLATFORM}" in
    systemd) journalctl -u "${SERVICE_NAME}" -n 200 --no-pager 2>/dev/null | grep -F 'starting: config=' | tail -1 || true ;;
    launchd) grep -F 'starting: config=' "${LOG_DIR}/agentd.err" 2>/dev/null | tail -1 || true ;;
  esac
}

# ------------------------------------------------------------------ phases

write_marker() {
  [ "${DRY_RUN}" = "1" ] && return 0
  mkdir -p "${CONFIG_DIR}"
  {
    echo "# 由 sysrun/verify-system-install.sh 写入；--cleanup 据此清理。"
    echo "binaries=${BIN_DST_DIR}/${SERVICE_NAME},${BIN_DST_DIR}/wist-exec"
    echo "config_dir=${CONFIG_DIR}"
    echo "data_dir=${DATA_DIR}"
    echo "log_dir=${LOG_DIR}"
  } >"${MARKER_FILE}"
}

install_service() {
  local force="${1:-}"
  # 定义已存在（例如没 --cleanup 的重跑）时必须 --force，否则 install 会直接拒绝。
  if [ "${force}" = "force" ] || [ -e "$(definition_path)" ]; then
    run "${AGENTD_BIN}" service install --system --bin "${AGENTD_BIN}" --config-dir "${CONFIG_DIR}" --force
  else
    run "${AGENTD_BIN}" service install --system --bin "${AGENTD_BIN}" --config-dir "${CONFIG_DIR}"
  fi
}

phase_install() {
  step "安装（系统级）"
  run install -m 0755 "${BIN_SRC_DIR}/${SERVICE_NAME}" "${BIN_SRC_DIR}/wist-exec" "${BIN_DST_DIR}/"
  run "${AGENTD_BIN}" init-config --config-dir "${CONFIG_DIR}"
  write_marker

  if [ -n "${WIST_VERIFY_ENDPOINT:-}" ]; then
    : "${WIST_VERIFY_TOKEN:?WIST_VERIFY_ENDPOINT 需要同时给 WIST_VERIFY_TOKEN}"
    info "顺带验收注册（endpoint=${WIST_VERIFY_ENDPOINT}，token 不落盘）"
    run "${AGENTD_BIN}" service install --system --bin "${AGENTD_BIN}" \
      --config-dir "${CONFIG_DIR}" --enrollment-token "${WIST_VERIFY_TOKEN}"
  else
    info "standalone 模式：不需要控制面与 token，只验服务托管与目录落点"
    install_service
  fi

  info "等待服务就绪（≤${READY_WAIT_SECS}s）"
  wait_until "${READY_WAIT_SECS}" "服务 running" service_is_running ||
    fail "服务未在 ${READY_WAIT_SECS}s 内进入 running"
}

phase_assert_definition() {
  step "定义 / 自启 / 运行"
  local definition
  definition="$(definition_path)"
  if [ -f "${definition}" ]; then
    pass "服务定义已落盘：${definition}"
  else
    fail "缺少服务定义：${definition}"
  fi

  if service_is_enabled; then pass "已启用（开机自启）"; else fail "未启用（开机不会自启）"; fi
  if service_is_running; then pass "服务 running（pid=$(service_main_pid)）"; else fail "服务不在 running"; fi

  local status_out
  status_out="$("${AGENTD_BIN}" service status --system 2>&1 || true)"
  printf '%s\n' "${status_out}" | sed 's/^/  | /'
  if wait_until "${READY_WAIT_SECS}" "单实例锁被持有" status_reports_running; then
    pass "service status 报告 running=true"
  else
    fail "service status 未报告 running=true"
  fi
}

phase_assert_layout() {
  step "目录落点（配置 / 数据 / 日志分离）"
  if wait_until "${READY_WAIT_SECS}" "数据/日志目录" dirs_ready; then
    pass "数据与日志目录已创建"
  else
    fail "数据/日志目录未在 ${READY_WAIT_SECS}s 内创建"
  fi
  for dir in "${DATA_DIR}/run" "${DATA_DIR}/state" "${LOG_DIR}"; do
    if [ -d "${dir}" ]; then pass "目录存在：${dir}"; else fail "目录缺失：${dir}"; fi
  done
  for path in "${CONFIG_DIR}/state" "${CONFIG_DIR}/run" "${CONFIG_DIR}/data"; do
    if [ -e "${path}" ]; then
      fail "配置目录里混入了数据：${path}"
    else
      pass "配置目录未混入数据：${path}"
    fi
  done

  if ! wait_until "${READY_WAIT_SECS}" "启动行" read_startup_line; then
    fail "日志里没有启动行（拿不到实际落点）"
    return 0
  fi
  local startup_line state_dir
  startup_line="$(read_startup_line)"
  printf '  | %s\n' "${startup_line}"
  state_dir="$(printf '%s\n' "${startup_line}" | sed -n 's/.*state_dir=\([^ ]*\).*/\1/p')"
  if [ "${state_dir}" = "${DATA_DIR}/state" ]; then
    pass "启动行 state_dir=${state_dir}"
  else
    fail "启动行 state_dir=${state_dir:-none}（期望 ${DATA_DIR}/state）"
  fi
}

phase_assert_collection() {
  step "采集输出落到数据目录"
  info "临时加一个文件输入：${SAMPLE_LOG}（验收后还原配置）"
  run cp -f "${CONFIG_DIR}/agentd.toml" "${CONFIG_DIR}/agentd.toml.verify-backup"
  printf 'verify line\n' >"${SAMPLE_LOG}"
  cat >>"${CONFIG_DIR}/agentd.toml" <<EOF

[[telemetry.logs.file_inputs]]
input_id = "verify"
path = "${SAMPLE_LOG}"
startup_position = "head"
multiline_mode = "none"
EOF
  if ! install_service force; then
    fail "无法用 --force 重装服务（见上面的报错），采集输出断言跳过"
    run cp -f "${CONFIG_DIR}/agentd.toml.verify-backup" "${CONFIG_DIR}/agentd.toml"
    run rm -f "${CONFIG_DIR}/agentd.toml.verify-backup"
    return 0
  fi
  wait_until "${READY_WAIT_SECS}" "服务重新 running" service_is_running ||
    fail "改配置后服务未在 ${READY_WAIT_SECS}s 内 running"

  local waited=0
  while [ "${waited}" -lt 15 ]; do
    if grep -q "verify line" "${RECORD_FILE}" 2>/dev/null; then break; fi
    sleep 1
    waited=$((waited + 1))
  done
  if grep -q "verify line" "${RECORD_FILE}" 2>/dev/null; then
    pass "采集输出已写入 ${RECORD_FILE}"
  else
    fail "采集输出未写入 ${RECORD_FILE}（等 ${waited}s）"
  fi

  run cp -f "${CONFIG_DIR}/agentd.toml.verify-backup" "${CONFIG_DIR}/agentd.toml"
  run rm -f "${CONFIG_DIR}/agentd.toml.verify-backup"
}

phase_assert_restart() {
  step "崩溃拉起"
  local before after waited=0
  before="$(service_main_pid)"
  if [ -z "${before}" ] || [ "${before}" = "0" ]; then
    fail "拿不到主进程 pid，跳过拉起验证"
    return 0
  fi
  info "kill -9 ${before}"
  kill -9 "${before}" 2>/dev/null || true

  while [ "${waited}" -lt "${RESTART_WAIT_SECS}" ]; do
    after="$(service_main_pid)"
    if [ -n "${after}" ] && [ "${after}" != "0" ] && [ "${after}" != "${before}" ] && service_is_running; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if [ -n "${after:-}" ] && [ "${after}" != "${before}" ] && service_is_running; then
    pass "已被拉起：pid ${before} -> ${after}（${waited}s）"
  else
    fail "未在 ${RESTART_WAIT_SECS}s 内拉起（before=${before} after=${after:-none}）"
  fi
}

phase_assert_single_instance() {
  step "单实例（flock）"
  local out_file probe_pid status
  out_file="$(mktemp)"
  # 前台启动第二个实例：锁生效应立刻非零退出；若 3s 后仍在跑，说明锁没生效（杀掉它并判 FAIL）。
  "${AGENTD_BIN}" --config-dir "${CONFIG_DIR}" >"${out_file}" 2>&1 &
  probe_pid=$!
  sleep 3
  set +e
  if kill -0 "${probe_pid}" 2>/dev/null; then
    kill "${probe_pid}" 2>/dev/null
    wait "${probe_pid}" 2>/dev/null
    status="running"
  else
    wait "${probe_pid}"
    status=$?
  fi
  set -e

  head -3 "${out_file}" | sed 's/^/  | /'
  rm -f "${out_file}"
  if [ "${status}" != "running" ] && [ "${status}" != "0" ]; then
    pass "第二个实例被拒绝（exit=${status}）"
  else
    fail "第二个实例未被拒绝（exit=${status}）"
  fi
  if service_is_running; then pass "原实例未受影响"; else fail "原实例被影响（不再 running）"; fi
}

phase_report_log_volume() {
  step "日志量（信息性）"
  case "${PLATFORM}" in
    systemd)
      local lines
      lines="$(journalctl -u "${SERVICE_NAME}" --since '2 min ago' --no-pager 2>/dev/null | wc -l | tr -d ' ')"
      info "journald 最近 2 分钟 ${lines} 行（收敛后应远低于逐轮打印的 ~2.3 行/秒）"
      ;;
    launchd)
      local size
      size="$(wc -c <"${LOG_DIR}/agentd.err" 2>/dev/null | tr -d ' ' || echo 0)"
      info "${LOG_DIR}/agentd.err ${size} bytes（需配合 newsyslog 轮转）"
      ;;
  esac
}

phase_after_reboot() {
  step "重启后复检（自启）"
  if wait_until "${READY_WAIT_SECS}" "服务 running" service_is_running &&
    service_is_enabled; then
    pass "服务已自动拉起（pid=$(service_main_pid)）"
  else
    fail "重启后服务未自动运行"
  fi
}

dump_diagnostics() {
  step "诊断信息（自动采集）"
  info "service status："
  "${AGENTD_BIN}" service status --system 2>&1 | sed 's/^/  | /' || true
  info "服务管理器视图："
  case "${PLATFORM}" in
    systemd)
      systemctl status "${SERVICE_NAME}" --no-pager 2>&1 | head -20 | sed 's/^/  | /' || true
      systemctl cat "${SERVICE_NAME}" --no-pager 2>&1 | sed 's/^/  | /' || true
      ;;
    launchd) launchctl print "system/${LAUNCHD_LABEL}" 2>&1 | head -40 | sed 's/^/  | /' || true ;;
  esac
  info "日志尾部："
  case "${PLATFORM}" in
    systemd) journalctl -u "${SERVICE_NAME}" -n 40 --no-pager 2>&1 | sed 's/^/  | /' || true ;;
    launchd) tail -n 40 "${LOG_DIR}/agentd.err" 2>&1 | sed 's/^/  | /' || true ;;
  esac
  info "目录："
  ls -la "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}" 2>&1 | sed 's/^/  | /' || true
  info "前台直跑 5s（看它到底报什么；已在跑时应报 already running）："
  local out
  out="$(mktemp)"
  "${AGENTD_BIN}" --config-dir "${CONFIG_DIR}" >"${out}" 2>&1 &
  local probe_pid=$!
  sleep 5
  kill "${probe_pid}" 2>/dev/null || true
  wait "${probe_pid}" 2>/dev/null || true
  head -n 10 "${out}" | sed 's/^/  | /'
  rm -f "${out}"
}

phase_cleanup() {
  step "清理"
  if [ ! -e "${MARKER_FILE}" ]; then
    echo "没有找到 ${MARKER_FILE}：本脚本没有安装记录，拒绝清理（避免误删别人的部署）" >&2
    exit 2
  fi
  run "${AGENTD_BIN}" service uninstall --system || true
  info "将删除本脚本创建的：${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR}"
  info "以及 ${BIN_DST_DIR}/${SERVICE_NAME} ${BIN_DST_DIR}/wist-exec ${SAMPLE_LOG}"
  run rm -rf "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  run rm -f "${BIN_DST_DIR}/${SERVICE_NAME}" "${BIN_DST_DIR}/wist-exec" "${SAMPLE_LOG}"
  printf '\ncleanup done\n'
}

main() {
  preflight
  case "${MODE}" in
    cleanup)
      phase_cleanup
      return 0
      ;;
    after-reboot)
      phase_after_reboot
      ;;
    verify)
      if [ "${DRY_RUN}" = "1" ]; then
        phase_install
        printf '\n[dry-run] 断言阶段需要 root 真机，已跳过\n'
        return 0
      fi
      # 断言阶段关掉 `set -e`：一条命令失败不该让脚本**提前退出**，
      # 否则会丢掉后面的断言与诊断 dump（失败仍会计入 FAIL_COUNT 并保留现场）。
      set +e
      phase_install
      phase_assert_definition
      phase_assert_layout
      phase_assert_collection
      phase_assert_restart
      phase_assert_single_instance
      phase_report_log_volume
      set -e
      if [ "${FAIL_COUNT}" != "0" ]; then
        dump_diagnostics
        info "有 FAIL：保留现场不清理（排查后可用 --cleanup 清理）"
      elif [ "${KEEP}" = "1" ]; then
        info "保留安装（--keep）：重启后用 --after-reboot 复检自启，用 --cleanup 清理"
      else
        phase_cleanup
      fi
      ;;
  esac

  printf '\n结果：PASS=%s FAIL=%s\n' "${PASS_COUNT}" "${FAIL_COUNT}"
  if [ "${FAIL_COUNT}" != "0" ]; then
    exit 1
  fi
}

main
