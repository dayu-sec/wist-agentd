#!/usr/bin/env bash
# 内核日志导出器（W3，`journalctl-kernel`）真机验收。
#
# 自动化测试跑在 macOS 上，只能用假命令；这里补上**真 journald** 的那部分契约 ——
# 也就是 agentd 代码里写死、但单元测试证明不了的事：
#   1) `-k -p 4 -o json` 是「一行一条」的 JSON，每行都能解析，且带 `__CURSOR`
#   2) 窗口里没有条目时 stdout 是**空的**（不变成假记录；`--quiet` 让这点跨版本恒定）
#   3) `--after-cursor=<上轮游标>` 能续读，且第二轮**不重放**第一轮（游标真的推进了）
#   4) 游标形态与失败语义（实测 systemd 259，代码的假设必须与它一致）：
#      · 畸形游标：退出码非 0，stderr 含 `Failed to seek to cursor`（→ is_cursor_error）
#      · 格式合法但已不存在的游标：**退出码 0**，静默从窗口起点重读
#        （→ 无法给重读加时间上限，只能靠超时 + should_reset_cursor 自愈）
#      · `--since` 与 `--after-cursor` 同时给：直接报错（→ argv 必须「替换」而不是「追加」）
#   5) `-p 4` 真的按优先级过滤（warning 及以上留下，info 不要）
#
# 用法（任意 systemd Linux；读 journal 与写 /dev/kmsg 都要 root）：
#   sudo dev/verify-journal-exporter.sh
#
# 可覆盖 env：
#   WIST_VERIFY_SINCE       回看窗口（默认 -2h）
#   WIST_VERIFY_NO_KMSG=1   不往 /dev/kmsg 写消息（只读验收；第 3/5 项会 SKIP）
#   WIST_VERIFY_ALLOW_SKIP=1  环境根本采不到 journald 时退 77（CI 用来区分「跳过」与「失败」）
#
# 退出码：0 = 全部通过（允许有 SKIP）；1 = 有 FAIL；77 = 环境无法验证（只在其 ALLOW_SKIP 时）。
set -uo pipefail

SINCE="${WIST_VERIFY_SINCE:--2h}"
NO_KMSG="${WIST_VERIFY_NO_KMSG:-0}"
ALLOW_SKIP="${WIST_VERIFY_ALLOW_SKIP:-0}"

fail=0
skipped=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; skipped=$((skipped + 1)); }
info() { printf '      %s\n' "$*"; }

die_env() {
  printf 'ENV   %s\n' "$*"
  if [ "$ALLOW_SKIP" = "1" ]; then
    exit 77
  fi
  echo "FAIL  环境无法验证（设 WIST_VERIFY_ALLOW_SKIP=1 可把它当『跳过』而不是失败）"
  exit 1
}

# 往内核环形缓冲写一条消息（journald 会把它当 `_TRANSPORT=kernel` 收下）。
# 成功 = 写进去了；**不代表** journald 采到了（那是 probe 的事）。
inject() {
  if [ -w /dev/kmsg ] && printf '%s\n' "$1" > /dev/kmsg 2>/dev/null; then
    return 0
  fi
  printf '%s\n' "$1" | sudo tee /dev/kmsg >/dev/null 2>&1
}

if ! command -v journalctl >/dev/null 2>&1; then
  die_env "没有 journalctl（不是 systemd 主机？）—— 这个面本来就不会派活"
fi
if ! command -v python3 >/dev/null 2>&1; then
  die_env "需要 python3 解析 JSON"
fi

distro="unknown"
[ -r /etc/os-release ] && distro="$( . /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}" )"
printf '环境：%s / kernel %s / %s\n\n' \
  "$distro" \
  "$(uname -r)" \
  "$(journalctl --version | head -n 1)"

# ── 能力探测：能不能采到内核日志 ─────────────────────────────────────────────
# 先看现成的；没有的话写一条再确认 journald 真的收下了（否则这份验收什么都证明不了）。
readable=0
window=$(journalctl -k -p 4 -o json --no-pager --quiet --since "$SINCE" 2>/dev/null || true)
if [ -n "$window" ]; then
  readable=1
fi

writable=0
if [ "$NO_KMSG" != "1" ]; then
  marker="wist-verify-probe-$$"
  if inject "<4>$marker"; then
    sleep 2
    window=$(journalctl -k -p 4 -o json --no-pager --quiet --since "$SINCE" 2>/dev/null || true)
    case "$window" in
      *"$marker"*) writable=1 ; readable=1 ;;
    esac
    if [ "$writable" -eq 0 ]; then
      info "写入 /dev/kmsg 成功但 journald 没采到（journald 没在跑？）"
    fi
  else
    info "/dev/kmsg 不可写（非 root？）"
  fi
fi

if [ "$readable" -eq 0 ] && [ "$writable" -eq 0 ]; then
  die_env "这台机器上没有可读的内核日志，也没有可注入的 journald —— 无法验证"
fi

# ── 1. 一行一条 JSON，且带 __CURSOR ───────────────────────────────────────────
cursor=""
if [ -z "$window" ]; then
  skip "窗口 $SINCE 内没有内核日志：跳过 JSON 形状检查"
else
  stats=$(printf '%s\n' "$window" | python3 -c '
import json, sys
lines = [line for line in sys.stdin.read().splitlines() if line.strip()]
broken = 0
cursor = ""
for line in lines:
    try:
        entry = json.loads(line)
    except Exception:
        broken += 1
        continue
    if isinstance(entry.get("__CURSOR"), str):
        cursor = entry["__CURSOR"]
print(len(lines), broken, cursor)
')
  set -- $stats
  total=$1
  broken=$2
  cursor="${3:-}"

  if [ "$broken" -eq 0 ]; then
    pass "一行一条 JSON：$total 行全部可解析"
  else
    bad "有 $broken 行不是 JSON（$total 行）—— 记录会被切坏"
  fi
  if [ -n "$cursor" ]; then
    pass "__CURSOR 可取：$cursor"
  else
    bad "输出里没有 __CURSOR —— 游标续读拿不到起点，每轮都会重读同一段"
  fi
fi

# ── 2. 空窗口时 stdout 必须为空（--quiet） ────────────────────────────────────
quiet_bytes=$(journalctl -o json --no-pager --quiet --unit=wist-verify-no-such-unit.service 2>/dev/null | wc -c | tr -d ' ')
loud_bytes=$(journalctl -o json --no-pager --unit=wist-verify-no-such-unit.service 2>/dev/null | wc -c | tr -d ' ')
if [ "$quiet_bytes" -eq 0 ]; then
  pass "空窗口 + --quiet：stdout 0 字节"
else
  bad "空窗口 + --quiet：stdout 有 $quiet_bytes 字节（会变成假记录）"
  journalctl -o json --no-pager --quiet --unit=wist-verify-no-such-unit.service 2>/dev/null | head -n 3
fi
info "对照：不带 --quiet 时 stdout $loud_bytes 字节（差值就是 --quiet 压掉的提示）"

# ── 3. 有效游标能续读 ────────────────────────────────────────────────────────
if [ -n "$cursor" ]; then
  if journalctl -k -o json --no-pager --quiet --after-cursor="$cursor" >/dev/null 2>&1; then
    pass "--after-cursor 续读退出码 0"
  else
    bad "--after-cursor 用真实游标也失败了 —— 续读这条路走不通"
  fi
else
  skip "跳过续读检查（没有游标）"
fi

# ── 4. 游标形态与失败语义 ────────────────────────────────────────────────────
# 4a. 畸形游标：必须非 0 + 能认（is_cursor_error 靠这个回退）
err=$(journalctl -k -o json --no-pager --quiet --after-cursor=garbage 2>&1 >/dev/null)
rc=$?
if [ "$rc" -ne 0 ]; then
  pass "畸形游标退出码非 0（$rc）"
else
  bad "畸形游标居然退出码 0 —— agentd 会把空输出当成「正常没数据」"
fi
case "$err" in
  *"seek to cursor"* | *"cursor not found"*)
    pass "stderr 与 is_cursor_error 匹配：$(printf '%s' "$err" | head -n 1)"
    ;;
  *)
    bad "stderr 里的措辞与 is_cursor_error 不匹配，会漏判：${err:-<空>}"
    ;;
esac

# 4b. 格式合法但不存在的游标：实测**不报错**。如果哪天变成报错了，
# is_cursor_error 应该能接住（这里只报告，不判 FAIL）。
stale='s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=0;t=0;x=0'
stale_out=$(journalctl -k -p 4 -o json --no-pager --quiet --after-cursor="$stale" 2>/dev/null)
stale_rc=$?
stale_lines=$(printf '%s' "$stale_out" | wc -l | tr -d ' ')
if [ "$stale_rc" -eq 0 ]; then
  info "已不存在的游标：退出码 0，返回 $stale_lines 行（静默重读 → 靠超时自愈，靠不了 --since）"
else
  info "已不存在的游标：退出码 $stale_rc（旧版本行为，is_cursor_error 会接住）"
fi

# 4c. --since 与 --after-cursor 不能同时给（agentd 用「替换」而不是「追加」的原因）
both=$(journalctl -k -o json --no-pager --quiet --since -1m --after-cursor="$stale" 2>&1 >/dev/null)
case "$both" in
  *"only one of"*) pass "--since + --after-cursor 一起给会被拒绝（所以 argv 必须替换时间窗口）" ;;
  "") skip "--since + --after-cursor 同时给没有报错（行为变了，检查 argv 策略）" ;;
  *) info "--since + --after-cursor：$(printf '%s' "$both" | head -n 1)" ;;
esac

# ── 5. 模拟一轮真实循环：第二轮不重放第一轮的条目 ────────────────────────────
if [ "$writable" -eq 0 ]; then
  skip "跳过循环模拟（无法注入内核消息）"
else
  inject "<3>wist-verify-loop-1" || bad "注入第 1 轮消息失败"
  sleep 1
  out1=$(journalctl -k -p 4 -o json --no-pager --quiet --since -5m 2>/dev/null)
  c1=$(printf '%s\n' "$out1" | python3 -c '
import json, sys
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
print(json.loads(lines[-1])["__CURSOR"] if lines else "")
')

  inject "<3>wist-verify-loop-2" || bad "注入第 2 轮消息失败"
  sleep 1
  out2=$(journalctl -k -p 4 -o json --no-pager --quiet --after-cursor="$c1" 2>/dev/null)

  case "$out2" in
    *wist-verify-loop-2*) pass "续读拿到了第二轮新条目" ;;
    *) bad "续读没拿到第二轮新条目 —— 游标推进没生效" ;;
  esac
  case "$out2" in
    *wist-verify-loop-1*) bad "续读重放了第一轮的条目 —— 游标没用上（会重复上送）" ;;
    *) pass "续读未重放第一轮的条目" ;;
  esac
fi

# ── 6. `-p 4` 真的过滤优先级 ─────────────────────────────────────────────────
if [ "$writable" -eq 0 ]; then
  skip "跳过优先级检查（无法注入内核消息）"
else
  inject "<3>wist-verify-kernel-warning" || bad "注入 warning 级消息失败"
  inject "<6>wist-verify-kernel-info" || bad "注入 info 级消息失败"
  sleep 1
  recent=$(journalctl -k -p 4 -o json --no-pager --quiet --since -1m 2>/dev/null)
  case "$recent" in
    *wist-verify-kernel-warning*) pass "<3> 的测试消息出现在 -p 4 里" ;;
    *) bad "<3> 的测试消息没出现 —— 优先级过滤把该留的也滤掉了" ;;
  esac
  case "$recent" in
    *wist-verify-kernel-info*) bad "<6> 的测试消息出现在 -p 4 里 —— 过滤没生效（info 噪声会灌进来）" ;;
    *) pass "<6> 的测试消息被 -p 4 滤掉" ;;
  esac
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
  echo "有 FAIL —— 先别把内核面翻 active，先按上面每条的提示改 argv 或判定。"
elif [ "$skipped" -ne 0 ]; then
  echo "通过，但有 $skipped 项被跳过（见上面的 SKIP；不是全量验证）。"
else
  echo "全部通过：journalctl 契约与 agentd 的假设一致。"
fi
exit "$fail"
