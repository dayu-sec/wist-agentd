#!/usr/bin/env bash
# 在**开发环境**打一份可发布的 agent 制品（tarball）。
#
#   dev/package-agentd.sh                                       # 构建 release → 打包 → 校验
#   WIST_PACKAGE_BIN_DIR=target/release dev/package-agentd.sh   # 用已有产物，不重新构建
#   WIST_PACKAGE_OUT_DIR=/tmp/dist dev/package-agentd.sh        # 换个产出目录
#
# 产出：<crate>/target/package/wist-agentd-<版本>-<host triple>.tar.gz
#       包里一层同名目录，放着 wist-agentd / wist-exec / wist-upgrader 三件。
#
# 为什么要有它：网关下发的安装脚本（`install.sh`）要求制品**三件齐全**（缺一件就拒绝安装），
# 而在此之前「谁负责把三件打进去」没有任何工具负责 —— 漏打一个件，机器上就会留下
# 「agentd 新版 + exec 旧版」的混合版本，而且是**静默**的（摘要校验管不了：网关按它自己
# 缓存的那份字节算，漏打包的包自己跟自己对得上）。把这件事做在**打包**这一步，
# 比在升级器里事后校验更省事，也更早。
#
# 打完会自己验一遍：把制品喂给升级器做一次**演练**（取包 → 验摘要 → 解包 → 让新件自报版本），
# 确认「解出来的 agentd 自报的版本」就是包名里那个。演练不动任何已装二进制。
#
# 相关：dev/verify-upgrade.sh（升级链路验收）、dev/install-local.sh（本机装/换）。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BIN_DIR="${WIST_PACKAGE_BIN_DIR:-${CRATE_ROOT}/target/release}"
OUT_DIR="${WIST_PACKAGE_OUT_DIR:-${CRATE_ROOT}/target/package}"

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
fail() {
  printf 'package-agentd: %s\n' "$*" >&2
  exit 1
}

# 校验阶段用的「当前版本」：只要求比目标旧（升级器会拒绝降级与重装）。
CHECK_FROM_VERSION="0.0.1"

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    fail "找不到 shasum / sha256sum"
  fi
}

build() {
  if [ -n "${WIST_PACKAGE_BIN_DIR:-}" ]; then
    step "用已有产物：${BIN_DIR}"
    return 0
  fi
  step "构建 release（三个 bin 一次编出来，版本天然一致）"
  command -v cargo >/dev/null 2>&1 || fail "找不到 cargo"
  (cd "${CRATE_ROOT}" && cargo build --release)
}

check_binaries() {
  step "检查三件是否都在 ${BIN_DIR}"
  MISSING=""
  for bin in wist-agentd wist-exec wist-upgrader; do
    if [ -x "${BIN_DIR}/${bin}" ]; then
      info "${bin} ✓"
    else
      info "${bin} ✗ 不在或不可执行"
      MISSING="${MISSING} ${bin}"
    fi
  done
  if [ -n "${MISSING}" ]; then
    fail "缺:${MISSING} —— 制品必须三件齐全（缺件会让机器变成混合版本）。\
先 cargo build --release，或用 WIST_PACKAGE_BIN_DIR 指向一份完整的产物目录。"
  fi
}

stage() {
  step "暂存到 ${STAGE_REL}/"
  mkdir -p "${STAGE_DIR}"
  for bin in wist-agentd wist-exec wist-upgrader; do
    cp -f "${BIN_DIR}/${bin}" "${STAGE_DIR}/${bin}"
    chmod 0755 "${STAGE_DIR}/${bin}"
  done
}

pack() {
  step "打包"
  mkdir -p "${OUT_DIR}"
  tar czf "${ARCHIVE}" -C "${WORK_DIR}" "${STAGE_REL}"
  info "$(short_path "${ARCHIVE}")"
}

# 包里三件都得在（这是「漏件制品」唯一的硬闸门）。
verify_contents() {
  step "校验包内容"
  LISTED="$(tar tzf "${ARCHIVE}")"
  for bin in wist-agentd wist-exec wist-upgrader; do
    case "${LISTED}" in
      *"${STAGE_REL}/${bin}"*) info "${bin} ✓" ;;
      *) fail "${ARCHIVE} 里没有 ${bin} —— 这就是「漏件制品」的来源，打住。" ;;
    esac
  done
}

# 演练：把**刚打出来的包**喂给升级器走一遍取包 / 验摘要 / 解包 / 验版本。
# 它证明的是「这个包是自洽的」（解出来的 agentd 自报的就是包名里那个版本），
# 与安装脚本、升级器用的是同一套解析逻辑。
verify_with_upgrader() {
  step "演练一遍（不动任何已装二进制）"
  CHECK_DIR="$(mktemp -d)"
  trap 'rm -rf "${CHECK_DIR}"' EXIT INT TERM
  "${BIN_DIR}/wist-agentd" init-config --config-dir "${CHECK_DIR}" >/dev/null
  if ! "${BIN_DIR}/wist-upgrader" apply \
    --config-dir "${CHECK_DIR}" \
    --work-id package-check \
    --target-version "${VERSION}" \
    --current-version "${CHECK_FROM_VERSION}" \
    --package-url "${ARCHIVE}" \
    --package-sha256 "${SHA256}"; then
    fail "升级器演练这个包失败：上面的报错就是制品的问题（打包不对，或版本对不上）。"
  fi
  rm -rf "${CHECK_DIR}"
  trap - EXIT INT TERM
}

short_path() {
  case "$1" in
    "${CRATE_ROOT}/"*) printf '%s' "${1#"${CRATE_ROOT}/"}" ;;
    *) printf '%s' "$1" ;;
  esac
}

main() {
  local host_triple
  host_triple="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
  [ -n "${host_triple}" ] || fail "拿不到 host triple（rustc 不可用？）"

  build
  check_binaries

  local version
  version="$("${BIN_DIR}/wist-agentd" version | awk '{print $NF}')"
  case "${version}" in
    "" | *[!0-9.]*) fail "从 wist-agentd version 拿到的版本不像版本号: '${version}'" ;;
  esac

  VERSION="${version}"
  STAGE_REL="wist-agentd-${VERSION}-${host_triple}"
  WORK_DIR="$(mktemp -d)"
  STAGE_DIR="${WORK_DIR}/${STAGE_REL}"
  ARCHIVE="${OUT_DIR}/${STAGE_REL}.tar.gz"
  trap 'rm -rf "${WORK_DIR}"' EXIT INT TERM

  stage
  pack
  verify_contents

  SHA256="$(sha256_of "${ARCHIVE}")"
  verify_with_upgrader

  printf '\n%s\n' "制品就绪"
  printf '  路径    %s\n' "${ARCHIVE}"
  printf '  大小    %s 字节\n' "$(wc -c <"${ARCHIVE}" | tr -d ' ')"
  printf '  sha256  %s\n' "${SHA256}"
  printf '  版本    %s（%s）\n' "${VERSION}" "${host_triple}"
  printf '  内容    wist-agentd · wist-exec · wist-upgrader\n'
  printf '\n怎么用：在网关的「设置」页把「安装包来源地址」填成这个文件的**绝对路径**\n'
  printf '（网关也接受 https 链接；它会下载到自己的缓存，并按缓存那份字节算摘要，摘要不用手抄）。\n'
}

main "$@"
