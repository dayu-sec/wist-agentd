#!/usr/bin/env bash
# 本地升级测试：打一份**能升上去**的 agent 制品，并给出直接填进网关
# 「Agent 升级」→「新建升级计划」的三个值（目标版本 / 包地址 / 包摘要）。
#
#   dev/package-local-upgrade.sh
#       用当前 crate 版本打包（前提：目标机上现装的 agentd 比它旧）。
#
#   dev/package-local-upgrade.sh --version 0.1.5
#       先按 0.1.5 构建（**临时**改 Cargo.toml / version.txt，脚本退出时自动还原），再打包。
#       本地升级测试通常需要它 —— 升级器只前进，同版本/降级会被直接拒绝。
#
#   dev/package-local-upgrade.sh --from 0.1.4
#       声明目标机现装版本；脚本会用**真实现装版本**再让升级器演练一次，
#       升级器自己会判定「有没有更新」，失败即版本没往上走。
#
#   WIST_PACKAGE_BIN_DIR=target/release dev/package-local-upgrade.sh
#       用已有产物，不重新编译（与 package-agentd.sh 同一开关；此时不能再用 --version）。
#
# 产出与 package-agentd.sh 相同：target/package/wist-agentd-<版本>-<host triple>.tar.gz
# （包内一层同名目录，三件齐全；打完会喂给升级器演练一遍）。本脚本在其之上补两件事：
#   1. 用真实现装版本（--from）校验「确实更新」；
#   2. 打印可直接填进「Agent 升级」表单的三个值，并说清「本地路径 = 目标机上的路径」。
#
# 相关：dev/package-agentd.sh（通用发布打包）、dev/verify-upgrade.sh（升级链路验收）。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
fail() {
  printf 'package-local-upgrade: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

BUMP_VERSION=""
FROM_VERSION=""
BIN_DIR="${WIST_PACKAGE_BIN_DIR:-${CRATE_ROOT}/target/release}"
OUT_DIR="${WIST_PACKAGE_OUT_DIR:-${CRATE_ROOT}/target/package}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      BUMP_VERSION="${2:-}"
      [ -n "${BUMP_VERSION}" ] || fail "--version 需要一个版本号（如 0.1.5）"
      shift 2
      ;;
    --version=*)
      BUMP_VERSION="${1#--version=}"
      shift
      ;;
    --from)
      FROM_VERSION="${2:-}"
      [ -n "${FROM_VERSION}" ] || fail "--from 需要一个版本号（目标机现装版本）"
      shift 2
      ;;
    --from=*)
      FROM_VERSION="${1#--from=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "未知参数：$1（--help 看用法）"
      ;;
  esac
done

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    fail "找不到 shasum / sha256sum"
  fi
}

CARGO_TOML="${CRATE_ROOT}/Cargo.toml"
VERSION_TXT="${CRATE_ROOT}/version.txt"
BACKUP_DIR=""

# 临时改版本后一定要还原：即使中途失败（set -e）也要把仓还原干净。
restore_version_files() {
  if [ -n "${BACKUP_DIR}" ]; then
    [ -f "${BACKUP_DIR}/Cargo.toml" ] && cp -f "${BACKUP_DIR}/Cargo.toml" "${CARGO_TOML}"
    [ -f "${BACKUP_DIR}/version.txt" ] && cp -f "${BACKUP_DIR}/version.txt" "${VERSION_TXT}"
    rm -rf "${BACKUP_DIR}"
    BACKUP_DIR=""
    info "已还原 Cargo.toml / version.txt"
  fi
}
trap restore_version_files EXIT INT TERM

apply_bump() {
  step "临时把 crate 版本改成 ${BUMP_VERSION}（打完自动还原）"
  if [ -n "${WIST_PACKAGE_BIN_DIR:-}" ]; then
    fail "--version 与 WIST_PACKAGE_BIN_DIR 不能同时用（后者跳过编译，改版本没意义）"
  fi
  BACKUP_DIR="$(mktemp -d)"
  cp -f "${CARGO_TOML}" "${BACKUP_DIR}/Cargo.toml"
  [ -f "${VERSION_TXT}" ] && cp -f "${VERSION_TXT}" "${BACKUP_DIR}/version.txt"
  # 只改 [package] 那行版本（带 #@gxl:set(version) 标记），不碰依赖里的 version。
  sed "s/^version = \"[^\"]*\" *#@gxl:set(version)/version = \"${BUMP_VERSION}\" #@gxl:set(version)/" \
    "${CARGO_TOML}" >"${CARGO_TOML}.tmp"
  mv "${CARGO_TOML}.tmp" "${CARGO_TOML}"
  printf '%s\n' "${BUMP_VERSION}" >"${VERSION_TXT}"
  info "Cargo.toml / version.txt -> ${BUMP_VERSION}"
}

# 1) 打包：复用通用打包器（构建 → 三件齐校验 → 打包 → 校验内容 → 升级器演练）。
if [ -n "${BUMP_VERSION}" ]; then
  apply_bump
fi
if [ -n "${WIST_PACKAGE_BIN_DIR:-}" ]; then
  WIST_PACKAGE_OUT_DIR="${OUT_DIR}" WIST_PACKAGE_BIN_DIR="${WIST_PACKAGE_BIN_DIR}" \
    "${SCRIPT_DIR}/package-agentd.sh"
else
  WIST_PACKAGE_OUT_DIR="${OUT_DIR}" "${SCRIPT_DIR}/package-agentd.sh"
fi

VERSION="$("${BIN_DIR}/wist-agentd" version | awk '{print $NF}')"
case "${VERSION}" in
  "" | *[!0-9.]*) fail "从 wist-agentd version 拿到的版本不像版本号: '${VERSION}'" ;;
esac
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
[ -n "${HOST_TRIPLE}" ] || fail "拿不到 host triple（rustc 不可用？）"
ARCHIVE="${OUT_DIR}/wist-agentd-${VERSION}-${HOST_TRIPLE}.tar.gz"
[ -f "${ARCHIVE}" ] || fail "没找到刚打出来的制品：${ARCHIVE}"
SHA256="$(sha256_of "${ARCHIVE}")"

# 2) 用真实现装版本再演练一次：升级器自己会拒绝「没更新」。
if [ -n "${FROM_VERSION}" ]; then
  step "用真实现装版本（${FROM_VERSION}）演练：升级器应判定 ${FROM_VERSION} -> ${VERSION} 合法"
  CHECK_DIR="$(mktemp -d)"
  if ! "${BIN_DIR}/wist-agentd" init-config --config-dir "${CHECK_DIR}" >/dev/null ||
    ! "${BIN_DIR}/wist-upgrader" apply \
      --config-dir "${CHECK_DIR}" \
      --work-id local-upgrade-check \
      --target-version "${VERSION}" \
      --current-version "${FROM_VERSION}" \
      --package-url "${ARCHIVE}" \
      --package-sha256 "${SHA256}"; then
    rm -rf "${CHECK_DIR}"
    fail "升级器拒绝了这次演练 —— 多半是目标版本没比现装的 ${FROM_VERSION} 新（升级器拒绝降级与重装）。\
用 --version 指定一个更高的版本（如 --version 0.1.5）再打一次。"
  fi
  rm -rf "${CHECK_DIR}"
  info "演练通过：${FROM_VERSION} -> ${VERSION} 是一次合法升级"
fi

# 3) 打印可直接填进「Agent 升级」表单的三个值。
printf '\n%s\n' "本地升级测试制品就绪"
printf '  制品     %s\n' "${ARCHIVE}"
printf '  sha256   %s\n' "${SHA256}"
printf '  版本     %s（%s）\n' "${VERSION}" "${HOST_TRIPLE}"
printf '  内容     wist-agentd · wist-exec · wist-upgrader\n'

printf '\n%s\n' "填进网关「Agent 升级」→「新建升级计划」："
printf '  目标版本   %s\n' "${VERSION}"
printf '  包地址     %s\n' "${ARCHIVE}"
printf '  包摘要     %s\n' "${SHA256}"

printf '\n%s\n' "注意："
printf '  · 包地址对升级器来说是**目标 Agent 主机**上的绝对路径（它直接读本机文件）。\n'
printf '    上面是打包机的路径；目标机不是本机时，把该文件放到目标机的同一路径。\n'
printf '  · 目标版本必须比目标机现装的 agentd 新；现装太新就用 --version 打更高的版本。\n'
printf '  · 分批测试：第一段只放 1 台（金丝雀），确认无问题再推进下一段。\n'
