#!/usr/bin/env bash
# Kafka 协议探针的**真 broker** 验收（docs/design/kafka-sasl-implementation.md §9）。
#
# 只做一件事：起一个容器（两条 listener、三种 SASL 机制），把那组
# `#[ignore]` 用例跑通。**已有集群**（研发 / 测试环境）不用跑这个脚本，
# 直接把环境变量指过去即可 —— 见 README。
#
# 成本控制：一个容器、无 TLS（证书链由离线用例覆盖），不进 CI，按需手动跑。
#
# 用法：
#   dev/kafka-sasl/run.sh             # 起 → 测 → 收拾
#   dev/kafka-sasl/run.sh --keep      # 跑完保留集群
#
# 可覆盖 env：
#   WIST_KAFKA_IMAGE             broker 镜像（默认 apache/kafka:3.9.1；**别用 4.x**，见 compose 注释）
#   WIST_KAFKA_SASL_USER         用户名（默认 wist-probe）
#   WIST_KAFKA_SASL_PASSWORD     密码（默认 wist-plain-secret；须与 server.properties 里的 PLAIN 用户一致）
#   WIST_KAFKA_LIVE_ALLOW_SKIP=1 没有 docker 时退 77 而不是 1
#   DOCKER                       docker 可执行文件
#
# 退出码：0 通过；1 失败；77 环境跑不了（仅 ALLOW_SKIP=1）。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

DOCKER="${DOCKER:-docker}"
KAFKA_USER="${WIST_KAFKA_SASL_USER:-wist-probe}"
KAFKA_PASSWORD="${WIST_KAFKA_SASL_PASSWORD:-wist-plain-secret}"
PLAINTEXT_PORT=9093
SASL_PLAINTEXT_PORT=9092

KEEP=0
if [[ "${1:-}" == "--keep" ]]; then
  KEEP=1
fi

compose() {
  "${DOCKER}" compose -f "${SCRIPT_DIR}/docker-compose.yml" \
    --project-directory "${SCRIPT_DIR}" "$@"
}

skip_or_fail() {
  echo "[kafka-sasl] $1" >&2
  if [[ "${WIST_KAFKA_LIVE_ALLOW_SKIP:-0}" == "1" ]]; then
    exit 77
  fi
  exit 1
}

# 环境就绪但集群真的坏了：**不能**退 77（那会被当成「这台机器验不了」）。
fail() {
  echo "[kafka-sasl] $1" >&2
  "${DOCKER}" logs --tail 40 wist-kafka-sasl >&2 2>/dev/null || true
  exit 1
}

command -v "${DOCKER}" >/dev/null 2>&1 || skip_or_fail "找不到 docker（装 Docker Desktop，或设 DOCKER=...）"
"${DOCKER}" info >/dev/null 2>&1 || skip_or_fail "docker 守护进程没起来"

cleanup() {
  if [[ "${KEEP}" == "1" ]]; then
    echo "[kafka-sasl] 集群保留；收掉用：${DOCKER} compose -f ${SCRIPT_DIR}/docker-compose.yml --project-directory ${SCRIPT_DIR} down -v"
    return
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---- 1. 起 broker ----
# 第一次会拉镜像（~600MB），之后就只是 JVM 启动的十几秒。
compose up -d --wait kafka || fail "broker 起不来（看上面的 docker 输出）"

# ---- 2. SCRAM 凭据 ----
compose exec -T kafka /opt/kafka/bin/kafka-configs.sh \
  --bootstrap-server kafka:19092 --alter \
  --add-config "SCRAM-SHA-256=[password=${KAFKA_PASSWORD}],SCRAM-SHA-512=[password=${KAFKA_PASSWORD}]" \
  --entity-type users --entity-name "${KAFKA_USER}" \
  || fail "SCRAM 用户初始化失败"

# ---- 3. 跑用例 ----
# 两条 listener 各跑一轮：PLAINTEXT 验报文布局，SASL_PLAINTEXT 验三种机制。
run_suite() {
  local bootstrap="$1" protocol="$2" mechanisms="$3" user="${4:-}" password="${5:-}"
  echo "[kafka-sasl] ${protocol} ${bootstrap}"
  (
    cd "${CRATE_ROOT}"
    env \
      WIST_KAFKA_LIVE=1 \
      WIST_KAFKA_LIVE_BOOTSTRAP="${bootstrap}" \
      WIST_KAFKA_LIVE_PROTOCOL="${protocol}" \
      WIST_KAFKA_LIVE_MECHANISMS="${mechanisms}" \
      WIST_KAFKA_LIVE_USER="${user}" \
      WIST_KAFKA_LIVE_PASSWORD="${password}" \
      cargo test --lib telemetry::metrics::kafka_live -- --ignored --test-threads=1 --nocapture
  )
}

status=0
run_suite "localhost:${PLAINTEXT_PORT}" PLAINTEXT "" "" "" || status=$?
run_suite "localhost:${SASL_PLAINTEXT_PORT}" SASL_PLAINTEXT \
  "PLAIN,SCRAM-SHA-256,SCRAM-SHA-512" "${KAFKA_USER}" "${KAFKA_PASSWORD}" || status=$?

if [[ "${status}" -ne 0 ]]; then
  fail "用例失败（退出码 ${status}）"
fi
echo "[kafka-sasl] 全部通过"
