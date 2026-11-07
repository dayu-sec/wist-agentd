#!/usr/bin/env bash
# 本机验一遍 PG 指标采集：起一个一次性 PostgreSQL → 建只读账号 → 跑真库用例。
#
#   dev/verify-pg-metrics.sh              # 起库 + 建账号 + 跑用例（跑完不删库）
#   WIST_PG_KEEP=0 dev/verify-pg-metrics.sh   # 跑完把临时库删掉
#   WIST_PG_ADDR=127.0.0.1:55440 dev/verify-pg-metrics.sh
#
# 不依赖网关 / 授权 / 安装包：直接调采集器（`probe_once`），验的是
# 「真驱动 + 真服务端 + 真 SQL」这条链路，与单测的假结果集互补。
#
# 为什么不需要 Linux：采集走 TCP，任何能连到 PG 的平台都行。
# 例外是**自探**（`discovery/pg_source.rs` 读 `/proc/<pid>/net/tcp`）—— 那是 Linux 专有，
# 本脚本不覆盖，见 docs/design/pg-metrics.md §6。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

ADDR="${WIST_PG_ADDR:-127.0.0.1:55439}"
PORT="${ADDR##*:}"
CONTAINER="${WIST_PG_CONTAINER:-wist-pg-live}"
SUPER_PASSWORD="${WIST_PG_SUPER_PASSWORD:-LiveProbe-2026}"
PROBE_PASSWORD="${WIST_PG_PROBE_PASSWORD:-ProbePw-2026}"
KEEP="${WIST_PG_KEEP:-1}"
IMAGE="${WIST_PG_IMAGE:-postgres:16}"

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
fail() {
  printf 'verify-pg-metrics: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "找不到 docker"
command -v cargo >/dev/null 2>&1 || fail "找不到 cargo"

SECRET_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${SECRET_DIR}"
  if [ "${KEEP}" != "1" ]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

step "准备 PostgreSQL（${ADDR}）"
if docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  info "复用已有容器 ${CONTAINER}"
  docker start "${CONTAINER}" >/dev/null 2>&1 || true
else
  docker run -d --name "${CONTAINER}" \
    -e "POSTGRES_PASSWORD=${SUPER_PASSWORD}" \
    -e POSTGRES_DB=wist_live \
    -p "${ADDR}:5432" "${IMAGE}" >/dev/null
  info "已启动 ${CONTAINER}（${IMAGE}）"
fi

for _ in $(seq 1 60); do
  if docker exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1 \
  || fail "PostgreSQL 没有在 60s 内就绪"
info "postgres 就绪"

step "准备只读探针账号（与 docs/design/pg-metrics.md §3 一致）"
HAS_ROLE="$(docker exec "${CONTAINER}" psql -U postgres -d postgres -tAc \
  "SELECT 1 FROM pg_roles WHERE rolname = 'wist-probe'")"
if [ "${HAS_ROLE}" != "1" ]; then
  docker exec "${CONTAINER}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
    -c "CREATE ROLE \"wist-probe\" LOGIN PASSWORD '${PROBE_PASSWORD}'" >/dev/null
  info "已创建 wist-probe"
else
  docker exec "${CONTAINER}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
    -c "ALTER ROLE \"wist-probe\" PASSWORD '${PROBE_PASSWORD}'" >/dev/null
  info "已重置 wist-probe 密码"
fi
docker exec "${CONTAINER}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
  -c 'GRANT pg_monitor TO "wist-probe"' >/dev/null
info "已 GRANT pg_monitor（不需要 superuser）"

# 造一点会被采到的活：库大小、事务计数、缓存命中都有真实数字。
docker exec "${CONTAINER}" psql -U postgres -d wist_live -v ON_ERROR_STOP=1 -q \
  -c 'CREATE TABLE IF NOT EXISTS live_probe_demo (id bigint, note text)' \
  -c 'INSERT INTO live_probe_demo SELECT g, md5(g::text) FROM generate_series(1, 5000) g' \
  >/dev/null 2>&1 || info "（造数跳过：表已存在）"

PASSWORD_FILE="${SECRET_DIR}/password"
printf '%s' "${PROBE_PASSWORD}" >"${PASSWORD_FILE}"
chmod 600 "${PASSWORD_FILE}"
info "密码文件（0600）：${PASSWORD_FILE}"

step "跑真库用例"
cd "${CRATE_ROOT}"
WIST_PG_LIVE=1 \
  WIST_PG_LIVE_ADDR="${ADDR}" \
  WIST_PG_LIVE_PASSWORD_FILE="${PASSWORD_FILE}" \
  cargo test --lib telemetry::metrics::postgres_live -- --ignored --test-threads=1 --nocapture

step "完成"
info "容器 ${CONTAINER} $(if [ "${KEEP}" = "1" ]; then echo '保留（WIST_PG_KEEP=0 可删）'; else echo '已删除'; fi)"
