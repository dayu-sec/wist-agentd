#!/usr/bin/env python3
"""确认旧指标名在 VictoriaMetrics 里已经不再写入。

规范名不会包含 `.`（见 metrics-data-spec.md §2.2），旧名则是 `system.memory.total`
这种点分写法。因此「还在用旧名」等价于「VM 里存在带点、且属于我们命名空间的序列」。

脚本做三件事：
  1. 保留期自检：先确认**新名**在窗口内有数据，否则「旧名没数据」不能说明任何问题；
  2. 列出窗口内仍有点的旧名，并给出最后写入时间；
  3. 默认再按 `agent` 展开，指出还在写旧名的是哪几台机器（通常是漏升级的旧版本 agent）。

退出码：
  0  窗口内没有任何旧名写入
  1  仍有旧名在写入（附名单与最后写入时间）
  2  查询失败 / 参数错误（无法判断）
  3  保留期自检不通过（窗口内连新名都没有数据，结论不可信）

用法：
  dev/verify-metrics-legacy-drop.py
  dev/verify-metrics-legacy-drop.py --vm-url http://vm.example:8428 --window 24h
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
        default="1h",
        help="判定窗口（PromQL duration，默认 1h；应 ≥ 2× 采集间隔）",
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
    if window_seconds < 10 * 60:
        # 采集间隔可能到 5 分钟，窗口太短时“没看到旧名”不代表没写。
        print(
            f"WARN: 窗口 {args.window} 短于 10m，采集间隔较长的指标可能被漏掉",
            file=sys.stderr,
        )

    base = args.vm_url.rstrip("/")
    names = metric_names(base, args.timeout)

    legacy = sorted(
        name
        for name in names
        if "." in name and name.startswith(NAMESPACES)
    )

    # 保留期自检：窗口内必须有新名数据，否则“旧名为 0”可能只是因为 VM 只留了 3 天。
    # 注意 `count_over_time` 会丢掉 `__name__`，所以这里不按名字分组，只看总量。
    retention_ok = True
    probe_total: float | None = None
    if not args.skip_retention_guard:
        probes_regex = "|".join(RETENTION_PROBES)
        probe_result = query_vector(
            base,
            f'sum(count_over_time({{__name__=~"{probes_regex}"}}[{args.window}]))',
            args.timeout,
        )
        probe_total = sum_values(probe_result)
        retention_ok = probe_total > 0

    report: dict = {
        "vm_url": base,
        "window": args.window,
        "retention_guard": {
            "ok": retention_ok,
            "skipped": args.skip_retention_guard,
            "samples": probe_total,
        },
        "legacy_names_seen": legacy,
        "still_writing": [],
    }

    if legacy:
        # 每个旧名单独查：`count_over_time` / `tlast_over_time` 都会丢掉 `__name__`，
        # 用 `sum by (__name__)` 分组拿不到名字；旧名数量是个位数到几十，逐个查最简单可靠。
        #
        # `tlast_over_time` 是 MetricsQL 函数，返回**原始样本时间戳**；
        # PromQL 的 `timestamp(last_over_time(...))` 返回的是上卷时间，会把“最后写入”算错。
        counts: dict[str, float] = {}
        last_seen: dict[str, float] = {}
        for name in legacy:
            selector = f'{{__name__="{name}"}}[{args.window}]'
            counts[name] = sum_values(
                query_vector(
                    base, f"sum(count_over_time({selector}))", args.timeout
                )
            )
            if counts[name] > 0:
                last_points = query_vector(
                    base, f"max(tlast_over_time({selector}))", args.timeout
                )
                if last_points:
                    try:
                        # `tlast_over_time` 返回秒（带毫秒小数），不是毫秒。
                        last_seen[name] = float(last_points[0]["value"][1])
                    except (KeyError, TypeError, ValueError, IndexError):
                        pass

        offenders = [name for name in legacy if counts.get(name, 0) > 0]
        agents: dict[str, list[str]] = {}
        if offenders and not args.no_agents:
            for name in offenders:
                selector = f'{{__name__="{name}"}}[{args.window}]'
                for series in query_vector(
                    base,
                    f"max by (agent) (tlast_over_time({selector}))",
                    args.timeout,
                ):
                    agent = series.get("metric", {}).get("agent", "")
                    if agent:
                        agents.setdefault(name, []).append(agent)

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
            print(
                f"保留期自检: OK（窗口内新名有 {int(probe_total or 0)} 个样本）"
            )
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
        if query.startswith("max by (agent)"):
            return [
                {
                    "metric": {"agent": "agent-1"},
                    "value": [1_700_000_000, "1700000000"],
                }
            ]
        if query.startswith("max(tlast_over_time"):
            return [{"metric": {}, "value": [1_700_000_000, "1700000000"]}]
        # 保留期探针：`sum(count_over_time({__name__=~"..."}[W]))`。
        if "__name__=~" in query:
            if cls.case == "retention-fail":
                return []
            return [{"metric": {}, "value": [1_700_000_000, "5"]}]
        # 逐个旧名的窗口内点数。
        if query.startswith("sum(count_over_time"):
            return [{"metric": {}, "value": [1_700_000_000, "12"]}]
        return []


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
