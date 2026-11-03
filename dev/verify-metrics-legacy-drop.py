#!/usr/bin/env python3
"""WP7 收尾门禁：确认旧指标名在 VictoriaMetrics 里已经不再写入。

规范名不会包含 `.`（见 metrics-data-spec.md §2.2），旧名则是 `system.memory.total`
这种点分写法。因此「还在用旧名」等价于「VM 里存在带点、且属于我们命名空间的序列」。

脚本做三件事：
  1. 保留期自检：先确认**新名**在窗口内有数据，否则「旧名没数据」不能说明任何问题；
  2. 列出窗口内仍有点的旧名，并给出最后写入时间；
  3. 默认再按 `agent` 展开，指出还在写旧名的是哪几台机器。

退出码：
  0  窗口内没有任何旧名写入（可以进入 WP7 的删除步骤）
  1  仍有旧名在写入（附名单与最后写入时间）
  2  查询失败 / 参数错误（无法判断）
  3  保留期自检不通过（窗口内连新名都没有数据，结论不可信）

用法：
  dev/verify-metrics-legacy-drop.py
  dev/verify-metrics-legacy-drop.py --vm-url http://vm.example:8428 --window 7d
  dev/verify-metrics-legacy-drop.py --json
  WIST_VM_URL=http://127.0.0.1:18429 dev/verify-metrics-legacy-drop.py

依赖：Python 3.8+（只用标准库），不需要 curl / jq。
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.server
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import NoReturn

# 旧名只可能出现在我们自己的命名空间里；带点的外部指标不应影响结论。
NAMESPACES = ("system.", "process.", "container.", "agent.")

# 保留期自检用的“肯定在写”的新名（任一有数据即可）。
RETENTION_PROBES = (
    "agent_uplink_metrics_failed_total",
    "system_uptime_seconds",
    "system_load_average_1m",
    "process_cpu_seconds_total",
)

DURATION = re.compile(r"^([1-9][0-9]*)(ms|s|m|h|d|w|y)$")
DURATION_SECONDS = {
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 7 * 86400,
    "y": 365 * 86400,
}


def duration_seconds(text: str) -> float:
    match = DURATION.match(text)
    if not match:
        fail(f"--window 必须是 PromQL duration，例如 7d / 24h，收到 {text!r}", 2)
    return int(match.group(1)) * DURATION_SECONDS[match.group(2)]


def fail(message: str, code: int) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def http_get_json(base: str, path: str, params: dict[str, str], timeout: float) -> dict:
    query = urllib.parse.urlencode(params)
    url = f"{base.rstrip('/')}{path}" + (f"?{query}" if query else "")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    token = os.environ.get("WIST_VM_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")[:500]
        fail(f"GET {url} -> HTTP {err.code}: {detail}", 2)
    except (urllib.error.URLError, TimeoutError) as err:
        fail(f"GET {url} 失败: {err}", 2)
    if payload.get("status") != "success":
        fail(f"查询失败: {json.dumps(payload)[:500]}", 2)
    return payload


def metric_names(base: str, timeout: float) -> list[str]:
    payload = http_get_json(base, "/api/v1/label/__name__/values", {}, timeout)
    return [name for name in payload.get("data", []) if isinstance(name, str)]


def query_vector(base: str, expr: str, timeout: float) -> list[dict]:
    payload = http_get_json(base, "/api/v1/query", {"query": expr}, timeout)
    return payload.get("data", {}).get("result", [])


def sum_values(result: list[dict]) -> float:
    total = 0.0
    for series in result:
        value = series.get("value", [None, "0"])
        try:
            total += float(value[1])
        except (TypeError, ValueError, IndexError):
            continue
    return total


def iso_utc(epoch: float | None) -> str:
    if epoch is None:
        return "-"
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="确认旧指标名（带点的 system./process./container./agent. 序列）已不再写入",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--vm-url",
        default=os.environ.get("WIST_VM_URL", "http://127.0.0.1:18429"),
        help="VictoriaMetrics 基址（默认 $WIST_VM_URL 或 http://127.0.0.1:18429）",
    )
    parser.add_argument(
        "--window",
        default="7d",
        help="判定窗口（PromQL duration，默认 7d；规范要求至少 7 天）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="单次 HTTP 超时秒数（默认 15）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出机器可读 JSON（供发布流水线判断）",
    )
    parser.add_argument(
        "--skip-retention-guard",
        action="store_true",
        help="跳过保留期自检（仅供排障；正式判定不要用）",
    )
    parser.add_argument(
        "--no-agents",
        action="store_true",
        help="不展开“哪台 agent 还在写”",
    )
    parser.add_argument(
        "--allow-short-window",
        action="store_true",
        help="允许窗口短于 7 天（规范要求 7 天，仅排障时使用）",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="用内置假 VM 跑三组用例（不需要真实环境）",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    window_seconds = duration_seconds(args.window)
    if window_seconds < 7 * 86400 and not args.allow_short_window:
        fail(
            f"--window 至少 7d（规范要求旧名 7 天无写入），收到 {args.window!r}；"
            "排障时可加 --allow-short-window",
            2,
        )

    base = args.vm_url.rstrip("/")
    names = metric_names(base, args.timeout)

    legacy = sorted(
        name
        for name in names
        if "." in name and name.startswith(NAMESPACES)
    )

    # 保留期自检：窗口内必须有新名数据，否则“旧名为 0”可能只是因为 VM 只留了 3 天。
    retention_ok = True
    probe_counts: dict[str, float] = {}
    if not args.skip_retention_guard:
        probe_expr = " or ".join(
            f'count_over_time({{__name__="{probe}"}}[{args.window}])' for probe in RETENTION_PROBES
        )
        probe_result = query_vector(base, probe_expr, args.timeout)
        for series in probe_result:
            name = series.get("metric", {}).get("__name__", "")
            probe_counts[name] = sum_values([series])
        retention_ok = any(count > 0 for count in probe_counts.values())

    report: dict = {
        "vm_url": base,
        "window": args.window,
        "retention_guard": {
            "ok": retention_ok,
            "skipped": args.skip_retention_guard,
            "probes": probe_counts,
        },
        "legacy_names_seen": legacy,
        "still_writing": [],
    }

    if legacy:
        # 一次查询拿全部旧名的窗口内点数，再取最后写入时间，避免按名字发几十个请求。
        # 旧名只含 [a-z0-9._]，直接拼接即可；PromQL 字符串里 `\.` 不是合法转义，
        # 点按正则通配符看待不影响匹配（窗口内不存在同名近似序列）。
        names_regex = "|".join(legacy)
        counts: dict[str, float] = {}
        counts_result = query_vector(
            base,
            f'sum by (__name__) (count_over_time({{__name__=~"{names_regex}"}}[{args.window}]))',
            args.timeout,
        )
        for series in counts_result:
            name = series.get("metric", {}).get("__name__", "")
            counts[name] = sum_values([series])

        last_seen: dict[str, float] = {}
        last_result = query_vector(
            base,
            f'max by (__name__) (timestamp(last_over_time({{__name__=~"{names_regex}"}}[{args.window}])))',
            args.timeout,
        )
        for series in last_result:
            name = series.get("metric", {}).get("__name__", "")
            try:
                last_seen[name] = float(series["value"][1])
            except (KeyError, TypeError, ValueError, IndexError):
                continue

        offenders = [name for name in legacy if counts.get(name, 0) > 0]
        agents: dict[str, list[str]] = {}
        if offenders and not args.no_agents:
            offenders_regex = "|".join(offenders)
            agents_result = query_vector(
                base,
                f'max by (__name__, agent) (timestamp(last_over_time({{__name__=~"{offenders_regex}"}}[{args.window}])))',
                args.timeout,
            )
            for series in agents_result:
                metric = series.get("metric", {})
                agents.setdefault(metric.get("__name__", ""), []).append(
                    metric.get("agent", "")
                )

        for name in offenders:
            report["still_writing"].append(
                {
                    "name": name,
                    "samples": int(counts.get(name, 0)),
                    "last_seen": iso_utc(last_seen.get(name)),
                    "agents": sorted(agents.get(name, [])),
                }
            )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"VM: {base}   窗口: {args.window}")
        if args.skip_retention_guard:
            print("保留期自检: 已跳过（结论不可作为 WP7 依据）")
        elif retention_ok:
            probes = ", ".join(
                f"{name}={int(count)}" for name, count in sorted(probe_counts.items())
            )
            print(f"保留期自检: OK（窗口内新名有数据：{probes}）")
        else:
            print(
                "保留期自检: FAIL —— 窗口内新名也没有数据；"
                "请确认 VM 保留期 ≥ 窗口，或改用 --window 重新跑。"
            )
        print()
        if not legacy:
            print("旧名: VM 里没有任何带点的 system./process./container./agent. 序列")
        elif not report["still_writing"]:
            print(f"旧名: 共 {len(legacy)} 个仍在 VM 的历史里，窗口内均为 0 写入")
            for name in legacy:
                print(f"  - {name}")
        else:
            print(f"旧名仍在写入: {len(report['still_writing'])} 个")
            print(f"{'NAME':44} {'SAMPLES':>9}  {'LAST_WRITE':20}  AGENTS")
            for row in report["still_writing"]:
                agents = ",".join(row["agents"]) or "-"
                print(
                    f"{row['name']:44} {row['samples']:>9}  {row['last_seen']:20}  {agents}"
                )
        print()

    if not retention_ok and not args.skip_retention_guard:
        print("结论: 无法判断（保留期自检未通过）", file=sys.stderr)
        return 3
    if report["still_writing"]:
        print(
            f"结论: {len(report['still_writing'])} 个旧名在 {args.window} 内仍有写入，"
            "暂不满足 WP7 删除条件。",
            file=sys.stderr,
        )
        return 1
    print(f"结论: 窗口 {args.window} 内无旧名写入，可以进入 WP7 删除步骤。")
    return 0


NEW_NAME_SAMPLES = (
    "agent_uplink_metrics_failed_total",
    "system_uptime_seconds",
    "system_load_average_1m",
    "process_cpu_seconds_total",
    "agent_memory_bytes",
)
LEGACY_SAMPLES = (
    "system.memory.total",
    "system.filesystem.usage",
    "process.memory.rss_kb",
)


class FakeVmHandler(http.server.BaseHTTPRequestHandler):
    """自检用的假 VM：按查询语句返回三种场景的数据。"""

    case = "clean"

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/api/v1/label/__name__/values":
            names = list(NEW_NAME_SAMPLES)
            if self.case != "clean":
                names += list(LEGACY_SAMPLES)
            body = {"status": "success", "data": names}
        elif parsed.path == "/api/v1/query":
            query = params.get("query", [""])[0]
            body = {"status": "success", "data": {"result": self.answer(query)}}
        else:
            self.send_error(404)
            return
        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args: object) -> None:  # 不刷访问日志
        return

    @classmethod
    def answer(cls, query: str) -> list[dict]:
        if "max by (__name__, agent)" in query:
            return [
                {
                    "metric": {"__name__": "system.memory.total", "agent": "agent-1"},
                    "value": [1_700_000_000, "1700000000"],
                }
            ]
        if query.startswith("max by (__name__)"):
            return [
                {
                    "metric": {"__name__": name},
                    "value": [1_700_000_000, "1700000000"],
                }
                for name in LEGACY_SAMPLES
            ]
        if query.startswith("sum by (__name__)"):
            return [
                {
                    "metric": {"__name__": name},
                    "value": [1_700_000_000, "12"],
                }
                for name in LEGACY_SAMPLES
            ]
        # 保留期探针：`A or B or C` 形式的 count_over_time。
        if cls.case == "retention-fail":
            return []
        return [
            {"metric": {"__name__": probe}, "value": [1_700_000_000, "5"]}
            for probe in RETENTION_PROBES
        ]


def run_self_test() -> int:
    """用本地假 VM 验证三种判定：干净 / 仍在写 / 保留期不足。"""
    import pathlib
    import subprocess

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeVmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    script = str(pathlib.Path(__file__).resolve())
    failures: list[str] = []

    def run(case: str) -> tuple[int, str, str]:
        FakeVmHandler.case = case
        completed = subprocess.run(
            [
                sys.executable,
                script,
                "--vm-url",
                f"http://127.0.0.1:{port}",
                "--window",
                "7d",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return completed.returncode, completed.stdout, completed.stderr

    try:
        code, out, err = run("clean")
        if code != 0 or "可以进入 WP7" not in out:
            failures.append(f"clean 场景应退 0，实际 {code}\nstdout={out}\nstderr={err}")

        code, out, err = run("still-writing")
        if code != 1 or "system.memory.total" not in out or "agent-1" not in out:
            failures.append(
                f"still-writing 场景应退 1 并点名，实际 {code}\nstdout={out}\nstderr={err}"
            )

        code, out, err = run("retention-fail")
        if code != 3:
            failures.append(f"retention-fail 场景应退 3，实际 {code}\nstdout={out}\nstderr={err}")
    finally:
        server.shutdown()
        server.server_close()

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("self-test: OK（clean → 0，still-writing → 1，retention-fail → 3）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
