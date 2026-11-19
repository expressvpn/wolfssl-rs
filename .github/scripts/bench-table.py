#!/usr/bin/env python3
"""Render Criterion results from several runners as a Markdown comparison table.

Usage: bench-table.py RESULTS_DIR

RESULTS_DIR holds one directory per runner, named bench-<OS>, each containing a
CRITERION_HOME tree with `base-N` and `pr-N` baselines (one per round, run
alternately on the same machine) and a cpu.txt.
"""

import json
import re
import statistics
import sys
from pathlib import Path

# Hidden marker used to find and update the PR comment
MARKER = "<!-- wolfssl-rs-bench -->"
# Per runner, by runner.os: changes within this many percent are treated as
# noise. Rounds of the same code vary by a median of ~1% on Linux and Windows,
# but ~20% on the virtualised M1 macOS runner, where medians of unchanged code
# have moved by up to ~30%, so macOS only flags large changes. Lists every
# runner the workflow runs on; one with no results is reported as missing.
# TODO: the macOS threshold is provisional, set from only four base-vs-PR runs
# (November 2026), two of which still had one noise flag each at 25%. Tune it
# once more runs of unchanged code are available, or if the runner gets quieter.
THRESHOLDS = {"Linux": 3.0, "macOS": 25.0, "Windows": 3.0}


def load(criterion_home):
    """Return {full_id: {"base"|"pr": [seconds_per_iter per round], "bytes": n}}."""
    results = {}
    for bench in criterion_home.glob("**/benchmark.json"):
        match = re.fullmatch(r"(base|pr)-\d+", bench.parent.name)
        if not match:
            continue
        baseline = match.group(1)
        info = json.loads(bench.read_text())
        estimates = json.loads((bench.parent / "estimates.json").read_text())
        # Criterion reports the slope when it has one, as in its own output
        estimate = estimates.get("slope") or estimates["mean"]
        entry = results.setdefault(info["full_id"], {})
        entry.setdefault(baseline, []).append(estimate["point_estimate"] * 1e-9)
        entry["bytes"] = (info.get("throughput") or {}).get("Bytes")
    return results


def fmt_time(seconds):
    for unit, scale in (("s", 1), ("ms", 1e-3), ("µs", 1e-6), ("ns", 1e-9)):
        if seconds >= scale:
            break
    return f"{seconds / scale:.3g} {unit}"


def fmt_rate(nbytes, seconds):
    rate = nbytes / seconds
    for unit, scale in (("GiB/s", 2**30), ("MiB/s", 2**20), ("KiB/s", 2**10), ("B/s", 1)):
        if rate >= scale:
            break
    return f"{rate / scale:.3g} {unit}"


def delta(entry, threshold):
    """Return (cell text, verdict) where verdict is "slower", "faster", "same" or None."""
    base, pr = entry.get("base"), entry.get("pr")
    if not base or not pr:
        return "—", None
    change = (statistics.median(pr) - statistics.median(base)) / statistics.median(base) * 100
    # Only flag when every round agrees, so one noisy round cannot cause it
    if change > threshold and min(pr) > max(base):
        return f"🔴 {change:+.1f}%", "slower"
    if change < -threshold and max(pr) < min(base):
        return f"🟢 {change:+.1f}%", "faster"
    return f"{change:+.1f}%", "same"


def delta_cell(entry, os_name):
    return delta(entry, THRESHOLDS[os_name])[0]


def fmt_result(entry, _os_name=None):
    """The PR's result: throughput where the benchmark has one, else time."""
    if not entry.get("pr"):
        return "—"
    t = statistics.median(entry["pr"])
    return fmt_rate(entry["bytes"], t) if entry.get("bytes") else fmt_time(t)


def sort_key(full_id):
    # Numeric parts (sizes) sort numerically and before words, so an int is never compared
    # with a str (e.g. "encrypt/64" vs "encrypt/in_place")
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[/_]", full_id)]


def table(runners, ids, cell, grouped=False):
    """A Markdown table with a row per benchmark and a column per runner."""
    lines = ["| Benchmark | " + " | ".join(runners) + " |",
             "|---|" + "--:|" * len(runners)]
    group = None
    for bench_id in ids:
        name = bench_id
        if grouped:
            prefix, _, rest = bench_id.partition("/")
            if prefix != group:
                group = prefix
                lines.append(f"| **{group}** |" + " |" * len(runners))
            name = rest or bench_id
        cells = [cell(results.get(bench_id, {}), os_name)
                 for os_name, (results, _) in runners.items()]
        lines.append(f"| `{name}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    results_dir = Path(sys.argv[1])
    runners = {}
    for d in sorted(results_dir.glob("bench-*"), key=lambda d: d.name.lower()):
        os_name = d.name.removeprefix("bench-")
        cpu = d / "cpu.txt"
        runners[os_name] = (load(d), cpu.read_text().strip() if cpu.exists() else "unknown CPU")
    if unknown := sorted(runners.keys() - THRESHOLDS.keys()):
        sys.exit(f"No threshold for runner(s) {', '.join(unknown)}; add them to THRESHOLDS")

    print(MARKER)
    print("## Benchmark results\n")
    # A runner whose job failed uploads nothing, so say so rather than drop its column
    if missing := [os_name for os_name in THRESHOLDS if os_name not in runners]:
        jobs = "its benchmark job" if len(missing) == 1 else "their benchmark jobs"
        print(f"⚠️ **No results from {', '.join(missing)}**: {jobs} failed, see the workflow run.\n")
    if not runners:
        return

    ids = sorted({i for r, _ in runners.values() for i in r}, key=sort_key)
    verdicts = {i: [delta(r.get(i, {}), THRESHOLDS[os_name])[1]
                    for os_name, (r, _) in runners.items()] for i in ids}
    flagged = [i for i in ids if {"slower", "faster"} & set(verdicts[i])]
    has_base = any(v is not None for vs in verdicts.values() for v in vs)

    if not has_base:
        print("The base branch has none of these benchmarks yet, so there is nothing to compare. "
              "PR results:\n")
        print(table(runners, ids, fmt_result, grouped=True))
    else:
        slower = sum("slower" in v for v in verdicts.values())
        faster = sum("faster" in v and "slower" not in v for v in verdicts.values())
        # New or removed benchmarks have nothing to compare, so are not "within noise"
        compared = sum(any(v is not None for v in vs) for vs in verdicts.values())
        summary = [f"🔴 **{slower} slower**" if slower else None,
                   f"🟢 **{faster} faster**" if faster else None,
                   f"{compared - len(flagged)} within noise",
                   f"{len(ids) - compared} only on one branch" if compared < len(ids) else None]
        print(("✅ No significant changes · " if not flagged else "")
              + " · ".join(p for p in summary if p) + "\n")
        if "macOS" in runners:
            print(f"⚠️ macOS flags are provisional: its runner varies by ~20% between rounds, so "
                  f"its ±{THRESHOLDS['macOS']:g}% threshold can still flag noise.\n")
        if flagged:
            print(table(runners, flagged, delta_cell))
            print()
        print(f"<details><summary>All {len(ids)} benchmarks (PR vs base)</summary>\n")
        print(table(runners, ids, delta_cell, grouped=True))
        print("\n</details>\n")
        print("<details><summary>PR results (throughput, or time per iteration)</summary>\n")
        print(table(runners, ids, fmt_result, grouped=True))
        print("\n</details>")

    print()
    print("Base and PR alternate in rounds on the same runner; medians are compared. 🔴/🟢 means "
          "the median moved beyond the runner's noise threshold and every PR round was slower/faster "
          "than every base round. — means only on one branch. Runners (threshold): "
          + ", ".join(f"{os_name} ±{THRESHOLDS[os_name]:g}% ({cpu})"
                      for os_name, (_, cpu) in runners.items()) + ".")


if __name__ == "__main__":
    main()
