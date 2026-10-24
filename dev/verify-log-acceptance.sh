#!/usr/bin/env bash
# 日志采集的**真文件系统**验收（G1–G3 / W1–W4 的端到端回归）。
#
# 为什么需要它：单元测试证明的是"给定行 → 给定记录"，证明不了
#   * glob / symlink / realpath / inode 轮转；
#   * checkpoint 跨进程（重启）续读；
#   * 噪音行丢弃与 `seq` 不取号；
#   * `postgres_csv` / `mysql_slow` 在真实文件上的边界（引号内换行、`# Time:` 分块）。
#
# 做法：**agentd + file sink**（不经过数据面）。所有断言都是可判定的计数/逐字比对，
# 不靠"看日志像不像"。数据面解析（log_type/字段）不在这里验，它属于另一层。
#
# 用法（不需要 root；fixture 全在临时目录）：
#   dev/verify-log-acceptance.sh
#   WIST_AGENTD_BIN=target/release/wist-agentd dev/verify-log-acceptance.sh
#
# 可覆盖 env：
#   WIST_AGENTD_BIN           agentd 可执行文件（默认 target/release/wist-agentd，回落 target/debug）
#   WIST_ACCEPT_KEEP=1        保留临时目录（失败时总是保留并打印路径）
#   WIST_ACCEPT_SKIP_TORN=1   跳过"截断行 + 跨批恢复"两个用例（CI 快速通道）
#   WIST_ACCEPT_ALLOW_SKIP=1  环境根本跑不了（无 python3 / 非 bash）时退 77 而不是 1
#   WIST_ACCEPT_TICK_WAIT=7   每个阶段等待多少秒（默认 7，覆盖 ≥2 个 3s tick）
#
# 退出码：0 = 通过（允许 SKIP）；1 = 有 FAIL；77 = 环境无法验证（仅 ALLOW_SKIP=1）。
#
# 与 `dev/verify-journal-exporter.sh` 的分工：那边验**真 journald**（只能真机/CI runner），
# 这边验**文件输入**（任何 Linux/macOS 都能跑，CI 直接跑）。
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRATE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BIN="${WIST_AGENTD_BIN:-}"
if [[ -z "${BIN}" ]]; then
  if [[ -x "${CRATE_ROOT}/target/release/wist-agentd" ]]; then
    BIN="${CRATE_ROOT}/target/release/wist-agentd"
  elif [[ -x "${CRATE_ROOT}/target/debug/wist-agentd" ]]; then
    BIN="${CRATE_ROOT}/target/debug/wist-agentd"
  fi
fi
KEEP="${WIST_ACCEPT_KEEP:-0}"
SKIP_TORN="${WIST_ACCEPT_SKIP_TORN:-0}"
ALLOW_SKIP="${WIST_ACCEPT_ALLOW_SKIP:-0}"
TICK_WAIT="${WIST_ACCEPT_TICK_WAIT:-7}"

fail=0
skipped=0
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; skipped=$((skipped + 1)); }
info() { printf '      %s\n' "$*"; }
die_env() {
  printf 'ENV   %s\n' "$*"
  if [[ "${ALLOW_SKIP}" == "1" ]]; then exit 77; fi
  echo "FAIL  环境无法验证（设 WIST_ACCEPT_ALLOW_SKIP=1 可把它当『跳过』）"
  exit 1
}

command -v python3 >/dev/null 2>&1 || die_env "需要 python3 做断言"
if [[ -z "${BIN}" || ! -x "${BIN}" ]]; then
  echo "FAIL  找不到 wist-agentd（先 cargo build --release，或设 WIST_AGENTD_BIN）" >&2
  exit 1
fi
printf 'agentd  %s\n' "${BIN}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/wist-log-accept.XXXXXX")" || exit 1
cleanup() {
  stop_agentd
  if [[ "${KEEP}" == "1" || "${fail}" -ne 0 ]]; then
    printf '\n保留现场：%s\n' "${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

# ── 断言器（Python）────────────────────────────────────────────────────────
cat > "${WORK}/check.py" <<'PY'
import json
import os
import re
import sys


def records(phase):
    path = os.path.join(phase, "out.ndjson")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def log(phase):
    path = os.path.join(phase, "agentd.out")
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def by_input(recs, name):
    return [r for r in recs if r.get("input_id") == name]


def info(msg):
    print("      " + msg)


def fail(msg):
    print("FAIL  " + msg)
    return False


def body_multiset(recs):
    return sorted(r["body"] for r in recs)


def check_offsets(recs, source, label):
    """每条记录的 [file_offset, file_offset_end) 必须与来源字节一致，且互不重叠。"""
    raw = open(source, "rb").read()
    ordered = sorted(recs, key=lambda r: r["file_offset"])
    ok = True
    prev_end = 0
    for r in ordered:
        start, end = r["file_offset"], r["file_offset_end"]
        if start < prev_end:
            ok = fail("%s 记录区间重叠：%s < %s" % (label, start, prev_end))
        if end > len(raw):
            ok = fail("%s 记录区间越界：%s > %s" % (label, end, len(raw)))
        elif raw[start:end] != r["body"].encode("utf-8"):
            ok = fail("%s 记录正文与来源字节不一致（offset %s..%s）" % (label, start, end))
        prev_end = max(prev_end, end)
    if ordered and prev_end != len(raw):
        ok = fail("%s 最后一条未读到文件尾：%s != %s" % (label, prev_end, len(raw)))
    return ok


def count_markers(recs, markers, label):
    ok = True
    bodies = [r["body"] for r in recs]
    for marker in markers:
        hits = [b for b in bodies if marker in b]
        if len(hits) != 1:
            ok = fail("%s marker %s 命中 %d 次（期望 1）" % (label, marker, len(hits)))
    return ok


def magnitude(text, pattern):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def static(phase, auth_path, csv_path, slow_path, needles_csv):
    needles = [n for n in needles_csv.split("|") if n]
    recs = records(phase)
    text = log(phase)
    ok = True

    # ── auth：噪音整条丢弃、其余逐字保留、不占 seq、丢弃数可对账 ──
    auth = by_input(recs, "auth")
    lines = open(auth_path, "r", encoding="utf-8").read().splitlines(True)
    expected = [ln for ln in lines if not any(n in ln for n in needles)]
    noise = len(lines) - len(expected)
    if body_multiset(auth) != sorted(expected):
        ok = fail("auth 记录集合与期望不一致（%d vs %d）" % (len(auth), len(expected)))
    ok = check_offsets(auth, auth_path, "auth") and ok
    seqs = [r["seq"] for r in auth]
    if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
        ok = fail("auth seq 不是严格递增：%s" % seqs)
    dropped = magnitude(text, r"telemetry noise dropped input_id=auth .*records=(\d+)")
    if dropped != noise:
        ok = fail("auth 丢弃数 self-observability = %s，期望 %s" % (dropped, noise))
    else:
        info("auth 丢弃 %d 条噪音，%d 条上送" % (noise, len(auth)))

    # ── postgres csvlog：引号内换行/转义引号必须留在同一条记录里 ──
    csv = by_input(recs, "csv")
    if len(csv) != 2:
        ok = fail("csv 记录数 = %d（期望 2）" % len(csv))
    else:
        ordered = sorted(csv, key=lambda r: r["file_offset"])
        if '"multi\nline"' not in ordered[0]["body"] or '""quoted""' not in ordered[0]["body"]:
            ok = fail("csv 第一条没有保留引号内换行/转义引号：%r" % ordered[0]["body"])
        if "CSV2" not in ordered[1]["body"]:
            ok = fail("csv 第二条不是 CSV2：%r" % ordered[1]["body"])
        ok = check_offsets(csv, csv_path, "csv") and ok

    # ── mysql slow log：# Time: 起块，SQL 里同前缀的注释不得误切 ──
    slow = by_input(recs, "slow")
    if len(slow) != 2:
        ok = fail("slow 记录数 = %d（期望 2）" % len(slow))
    else:
        ordered = sorted(slow, key=lambda r: r["file_offset"])
        if "SLOW1" not in ordered[0]["body"] or "# Time: the report runs daily" not in ordered[0]["body"]:
            ok = fail("slow 第一块丢了 SQL 注释行或被误切：%r" % ordered[0]["body"])
        if "SLOW2" not in ordered[1]["body"]:
            ok = fail("slow 第二块不是 SLOW2：%r" % ordered[1]["body"])
        ok = check_offsets(slow, slow_path, "slow") and ok

    # ── 容器 stdout：每个 marker 恰好一次；source_path 是 symlink 路径 ──
    containers = by_input(recs, "containers")
    markers = ["POD-ns1-pod1-%02d" % i for i in range(1, 4)]
    markers += ["POD-ns1-pod2-%02d" % i for i in range(1, 3)]
    markers += ["POD-ns2-pod3-%02d" % i for i in range(1, 3)]
    ok = count_markers(containers, markers, "containers") and ok
    if len(containers) != len(markers):
        ok = fail("containers 记录数 = %d（期望 %d）" % (len(containers), len(markers)))
    for r in containers:
        if "/containers/" not in r["source_path"]:
            ok = fail("containers source_path 不是 symlink 路径：%s" % r["source_path"])
            break
    return ok


def rotate(phase, marker_prefix, expected, source_name):
    recs = records(phase)
    ok = count_markers(recs, ["%s-%02d" % (marker_prefix, i) for i in range(1, expected + 1)], source_name)
    if len(recs) != expected:
        ok = fail("%s 记录数 = %d（期望 %d）" % (source_name, len(recs), expected))
    return ok


def container_rotation(phase):
    recs = records(phase)
    markers = ["CR-01", "CR-02", "CR-03", "CR-TAIL", "CR-NEW"]
    ok = count_markers(recs, markers, "container-rotation")
    if len(recs) != len(markers):
        ok = fail("container-rotation 记录数 = %d（期望 %d）" % (len(recs), len(markers)))
    # CR-TAIL 是从**被改名的真实文件**里排空出来的：轮转尾巴的 source_path 是真实路径。
    # 其余（当前文件里的行）必须保留 symlink 路径（D4：filename 形状不变）。
    for r in recs:
        if "CR-TAIL" in r["body"]:
            continue
        if "/containers/" not in r["source_path"]:
            ok = fail("container-rotation 当前文件的 source_path 不是 symlink：%s" % r["source_path"])
            break
    tails = [r for r in recs if "CR-TAIL" in r["body"]]
    if tails and "/pods/" not in tails[0]["source_path"] and "/containers/" not in tails[0]["source_path"]:
        ok = fail("container-rotation 轮转尾巴的 source_path 异常：%s" % tails[0]["source_path"])
    return ok


def torn_resume(phase):
    recs = records(phase)
    bodies = sorted(r["body"] for r in recs)
    expected = sorted(['T1,"a\nb",x\n', '2,"ok",y\n'])
    if bodies != expected:
        fail("torn 跨批恢复的记录集合不对：%r" % bodies)
        return False
    return True


def torn_recovery(phase):
    recs = records(phase)
    text = log(phase)
    ok = True
    if recs:
        ok = fail("残缺记录不该下发，实际有 %d 条：%r" % (len(recs), [r["body"] for r in recs]))
    withheld = magnitude(text, r"telemetry record withheld input_id=torn .*records=(\d+)")
    if withheld != 1:
        ok = fail("torn recovery 的 withheld 计数 = %s（期望 1）" % withheld)
    return ok


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "static":
        ok = static(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif cmd == "rotate":
        ok = rotate(sys.argv[2], "ROT", 10, "rotate")
    elif cmd == "restart":
        ok = rotate(sys.argv[2], "RESTART", 6, "restart")
    elif cmd == "container-rotation":
        ok = container_rotation(sys.argv[2])
    elif cmd == "torn-resume":
        ok = torn_resume(sys.argv[2])
    elif cmd == "torn-recovery":
        ok = torn_recovery(sys.argv[2])
    else:
        print("unknown check: " + cmd)
        sys.exit(2)
    sys.exit(0 if ok else 1)
PY

write_config() { # $1 = phase dir, $2 = file_inputs TOML
  mkdir -p "$1/home"
  cat > "$1/home/agentd.toml" <<EOF
schema_version = "v1"

[paths]
root_dir = "$1/home"
run_dir = "run"
state_dir = "state"
log_dir = "log"

[telemetry.logs]
max_read_bytes_per_tick = 4194304
max_lines_per_tick = 4096

[telemetry.logs.output]
enabled = true
kind = "file"

[telemetry.logs.output.file]
path = "$1/out.ndjson"

$2
EOF
}

AGENTD_PID=""
start_agentd() { # $1 = phase dir
  local dir="$1"
  : >"${dir}/agentd.out"
  # 在子 shell 里启动，只把 pid 带出来：这样 agentd 不是本 shell 的作业，
  # stop_agentd 杀它时 bash 不会往终端打 `PID Terminated: 15` 之类的作业通知。
  # （agentd 随即被 reparent 到 init，所以停不下来时没有 `wait` 可用，靠轮询 `kill -0`。）
  (
    "${BIN}" --config-dir "${dir}/home" >>"${dir}/agentd.out" 2>&1 &
    echo $! >"${dir}/agentd.pid"
  )
  AGENTD_PID="$(cat "${dir}/agentd.pid" 2>/dev/null || true)"
  if [[ -z "${AGENTD_PID}" ]]; then
    bad "agentd 启动失败（phase=$(basename "${dir}")，没拿到 pid）"
    return 1
  fi
  local waited=0
  while [[ ${waited} -lt 50 ]]; do
    if ! kill -0 "${AGENTD_PID}" 2>/dev/null; then
      bad "agentd 启动失败（phase=$(basename "${dir}")）"
      sed -n '1,40p' "${dir}/agentd.out" | sed 's/^/      /'
      AGENTD_PID=""
      return 1
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  return 0
}

stop_agentd() {
  [[ -n "${AGENTD_PID}" ]] || return 0
  local pid="${AGENTD_PID}" waited=0
  # 先 TERM 让它自己 flush 落盘（file sink 有缓冲），5s 不走再 KILL。
  kill -TERM "${pid}" 2>/dev/null || true
  while kill -0 "${pid}" 2>/dev/null && [[ ${waited} -lt 50 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  kill -KILL "${pid}" 2>/dev/null || true
  AGENTD_PID=""
}

run_phase() { # $1 = phase dir（已写好 config）；启动、等待、停止
  local dir="$1"
  start_agentd "${dir}" || return 1
  sleep "${TICK_WAIT}"
  stop_agentd
  return 0
}

check() { # $1 = 描述, 其余 = check.py 参数
  local desc="$1"; shift
  if python3 "${WORK}/check.py" "$@"; then
    pass "${desc}"
  else
    bad "${desc}"
  fi
}

# ── phase 1：静态正确性（auth / csv / slow / 容器）────────────────────────
P1="${WORK}/p1"
FIX="${P1}/fixtures"
mkdir -p "${FIX}/containers" "${FIX}/pods"
cat > "${FIX}/auth.log" <<'EOF'
AUTH-OK-1 Accepted publickey for deploy from 10.0.0.1 port 22 ssh2
AUTH-OK-2 pam_unix(sshd:session): session opened for user deploy
AUTH-OK-3 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/true
pam_unix(cron:session): session opened for user root by (uid=0)
systemd-logind: New seat seat0.
pam_unix(systemd-user:session): session opened for user deploy
AUTH-OK-4 Failed password for invalid user admin from 10.0.0.9 port 40022 ssh2
EOF
# csvlog：第一条含「引号内换行」+「转义引号」，第二条正常。
printf 'CSV1,"multi\nline","he said ""quoted""",tail\nCSV2,"ok",plain,end\n' > "${FIX}/postgresql.csv"
cat > "${FIX}/slow.log" <<'EOF'
# Time: 2026-10-24T01:02:03.123456Z
# User@Host: app[app] @ localhost []
# Query_time: 12.5  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 100
SELECT 1; -- SLOW1
# Time: the report runs daily
SELECT 2;
# Time: 2026-10-24T01:02:04.123456Z
# User@Host: app[app] @ localhost []
SELECT 3; -- SLOW2
EOF
# 2 ns × 3 pod 的 symlink（文件名带 pod/ns/container，指向 /pods 下的真实文件）。
for spec in "ns1 pod1 3" "ns1 pod2 2" "ns2 pod3 2"; do
  set -- ${spec}
  ns="$1"; pod="$2"; count="$3"
  real_dir="${FIX}/pods/${ns}_${pod}_uid"
  mkdir -p "${real_dir}"
  real="${real_dir}/0.log"
  : >"${real}"
  i=1
  while [[ ${i} -le ${count} ]]; do
    printf 'POD-%s-%s-%02d marker\n' "${ns}" "${pod}" "${i}" >>"${real}"
    i=$((i + 1))
  done
  ln -s "${real}" "${FIX}/containers/${pod}_${ns}_app-abc123.log"
done

write_config "${P1}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "auth"
path = "${FIX}/auth.log"
startup_position = "head"
multiline_mode = "none"
drop_if_contains = [
  "pam_unix(cron:session)",
  "systemd-logind",
  "pam_unix(systemd-user:session)",
]

[[telemetry.logs.file_inputs]]
input_id = "csv"
path = "${FIX}/postgresql.csv"
startup_position = "head"
multiline_mode = "postgres_csv"

[[telemetry.logs.file_inputs]]
input_id = "slow"
path = "${FIX}/slow.log"
startup_position = "head"
multiline_mode = "mysql_slow"

[[telemetry.logs.file_inputs]]
input_id = "containers"
path = "${FIX}/containers/*.log"
startup_position = "head"
multiline_mode = "none"
EOF
)"
if run_phase "${P1}"; then
  check "静态：auth 噪音丢弃 / csvlog 引号 / slow 分块 / 容器 marker" \
    static "${P1}" "${FIX}/auth.log" "${FIX}/postgresql.csv" "${FIX}/slow.log" \
    "pam_unix(cron:session)|systemd-logind|pam_unix(systemd-user:session)"
else
  fail=1
fi

# ── phase 2：单文件轮转（mv + 新文件，按 inode 排空旧尾巴）───────────────
P2="${WORK}/p2"
mkdir -p "${P2}/fixtures"
ROT="${P2}/fixtures/app.log"
: >"${ROT}"
i=1
while [[ ${i} -le 5 ]]; do printf 'ROT-%02d line\n' "${i}" >>"${ROT}"; i=$((i + 1)); done
write_config "${P2}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "rotate"
path = "${ROT}"
startup_position = "head"
multiline_mode = "none"
EOF
)"
if run_phase "${P2}"; then :; else fail=1; fi
mv "${ROT}" "${ROT}.1"
: >"${ROT}"
i=6
while [[ ${i} -le 10 ]]; do printf 'ROT-%02d line\n' "${i}" >>"${ROT}"; i=$((i + 1)); done
if run_phase "${P2}"; then check "轮转：旧文件排空 + 新文件续采，不重不漏" rotate "${P2}"; else fail=1; fi

# ── phase 3：重启续读（checkpoint）─────────────────────────────────────
P3="${WORK}/p3"
mkdir -p "${P3}/fixtures"
RESTART="${P3}/fixtures/app.log"
: >"${RESTART}"
i=1
while [[ ${i} -le 3 ]]; do printf 'RESTART-%02d line\n' "${i}" >>"${RESTART}"; i=$((i + 1)); done
write_config "${P3}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "restart"
path = "${RESTART}"
startup_position = "head"
multiline_mode = "none"
EOF
)"
if run_phase "${P3}"; then :; else fail=1; fi
i=4
while [[ ${i} -le 6 ]]; do printf 'RESTART-%02d line\n' "${i}" >>"${RESTART}"; i=$((i + 1)); done
if run_phase "${P3}"; then check "重启：从 checkpoint 续读，不重放不丢行" restart "${P3}"; else fail=1; fi

# ── phase 4：容器 symlink 轮转（真实文件改名，symlink 路径不变）─────────
P4="${WORK}/p4"
mkdir -p "${P4}/fixtures/containers" "${P4}/fixtures/pods/ns1_pod1_uid"
REAL="${P4}/fixtures/pods/ns1_pod1_uid/0.log"
LINK="${P4}/fixtures/containers/pod1_ns1_app-abc123.log"
: >"${REAL}"
for n in 1 2 3; do printf 'CR-%02d line\n' "${n}" >>"${REAL}"; done
ln -s "${REAL}" "${LINK}"
write_config "${P4}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "containers"
path = "${P4}/fixtures/containers/*.log"
startup_position = "head"
multiline_mode = "none"
EOF
)"
if run_phase "${P4}"; then :; else fail=1; fi
# 轮转：真实文件改名 + 新建同名文件；旧文件在改名**之后**又写了一条尾巴。
mv "${REAL}" "${REAL}.20261024-000000"
: >"${REAL}"
printf 'CR-TAIL after rotate\n' >>"${REAL}.20261024-000000"
printf 'CR-NEW in new file\n' >>"${REAL}"
if run_phase "${P4}"; then
  check "容器：symlink 不变时按 realpath 排空旧尾巴 + 采新文件" container-rotation "${P4}"
else
  fail=1
fi

# ── phase 5/6：截断行跨批 + torn-write 恢复（可跳过）────────────────────
if [[ "${SKIP_TORN}" == "1" ]]; then
  skip "torn write 用例（WIST_ACCEPT_SKIP_TORN=1）"
else
  # 5：引号内跨读批恢复（两条记录各写一半）
  P5="${WORK}/p5"
  mkdir -p "${P5}/fixtures"
  TORN="${P5}/fixtures/postgresql.csv"
  printf 'T1,"a\n' >"${TORN}"
  write_config "${P5}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "torn"
path = "${TORN}"
startup_position = "head"
multiline_mode = "postgres_csv"
EOF
)"
  if run_phase "${P5}"; then :; else fail=1; fi
  printf 'b",x\n2,"ok",y\n' >>"${TORN}"
  if run_phase "${P5}"; then check "csvlog：跨读批的半个引号块从 pending 续上" torn-resume "${P5}"; else fail=1; fi

  # 6：写到一半的记录（引号奇偶永久失衡）不能无限吸收后续行。
  #    把 checkpoint 的 last_updated_at 拨老，模拟 60s 空闲 → 应按 Oversized 挡下。
  P6="${WORK}/p6"
  mkdir -p "${P6}/fixtures"
  TORN2="${P6}/fixtures/postgresql.csv"
  printf 'T2,"torn\n' >"${TORN2}"
  write_config "${P6}" "$(cat <<EOF
[[telemetry.logs.file_inputs]]
input_id = "torn"
path = "${TORN2}"
startup_position = "head"
multiline_mode = "postgres_csv"
EOF
)"
  if run_phase "${P6}"; then :; else fail=1; fi
  if ! python3 - "${P6}" <<'PY'
import glob, json, sys
aged = 0
paths = glob.glob(sys.argv[1] + "/home/state/logs/file_inputs/*/checkpoints.json")
for p in paths:
    try:
        with open(p) as fh:
            data = json.load(fh)
    except Exception:
        continue
    targets = []
    top = data.get("pending_multiline") if isinstance(data, dict) else None
    if isinstance(top, dict):
        targets.append(top)
    for entry in (data.get("files") or []) if isinstance(data, dict) else []:
        if isinstance(entry, dict) and isinstance(entry.get("pending_multiline"), dict):
            targets.append(entry["pending_multiline"])
    for pending in targets:
        if pending.get("last_updated_at"):
            pending["last_updated_at"] = "2000-01-01T00:00:00Z"
            aged += 1
    if targets:
        with open(p, "w") as fh:
            json.dump(data, fh)
if aged == 0:
    print("FAIL  没找到 pending_multiline checkpoint（路径/格式变了？）")
    sys.exit(1)
PY
  then
    fail=1
  fi
  if run_phase "${P6}"; then check "csvlog：残缺记录按 Oversized 挡下并清掉 pending" torn-recovery "${P6}"; else fail=1; fi
  # 恢复后下一行必须能正常上送（证明 pending 没粘住后续行）。
  printf 'T3,"fresh",ok\n' >>"${TORN2}"
  if run_phase "${P6}"; then
    if python3 - "${P6}" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "out.ndjson")
bodies = []
if os.path.exists(path):
    for line in open(path):
        if line.strip():
            bodies.append(json.loads(line)["body"])
sys.exit(0 if bodies == ['T3,"fresh",ok\n'] else 1)
PY
    then
      pass "csvlog：恢复后新行独立成条"
    else
      bad "csvlog：恢复后新行没有独立成条"
    fi
  else
    fail=1
  fi
fi

# ── 汇总 ──────────────────────────────────────────────────────────────────
echo
if [[ ${fail} -ne 0 ]]; then
  echo "结果：FAIL（skipped=${skipped}）"
  exit 1
fi
echo "结果：PASS（skipped=${skipped}）"
exit 0
