#!/usr/bin/env python3
"""Fail if unit-test line coverage of src/parser.cpp is under 80%."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys

THRESHOLD = 80.0


def find_tool(names: list[str]) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    for name in names:
        matches = sorted(glob.glob(f"/usr/bin/{name}-[0-9]*")) + sorted(
            glob.glob(f"/usr/lib/llvm-*/bin/{name}")
        )
        if matches:
            return matches[-1]
    return None


def parse_percent(text: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*%", text)
    if not match:
        return None
    return float(match.group(1))


def llvm_line_cover(build_dir: str) -> float | None:
    profraw = os.path.join(build_dir, "default.profraw")
    if not os.path.isfile(profraw) or os.path.getsize(profraw) == 0:
        return None
    llvm_profdata = find_tool(["llvm-profdata"])
    llvm_cov = find_tool(["llvm-cov"])
    tests = os.path.join(build_dir, "wirecut-tests")
    if not llvm_profdata or not llvm_cov or not os.path.isfile(tests):
        return None
    profdata = os.path.join(build_dir, "default.profdata")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(repo, "src", "parser.cpp")
    subprocess.check_call([llvm_profdata, "merge", "-sparse", profraw, "-o", profdata])
    report = subprocess.check_output(
        [
            llvm_cov,
            "report",
            tests,
            f"-instr-profile={profdata}",
            src,
            "-show-branch-summary=false",
            "-show-region-summary=false",
        ],
        text=True,
    )
    print(report)
    for line in report.splitlines():
        if "parser.cpp" in line:
            percents = re.findall(r"([0-9]+(?:\.[0-9]+)?)%", line)
            if percents:
                return float(percents[-1])
    return None


def gcov_line_cover(build_dir: str) -> float | None:
    gcov = find_tool(["gcov"])
    if not gcov:
        return None
    gcda_files = glob.glob(os.path.join(build_dir, "**", "parser.cpp.gcda"), recursive=True)
    if not gcda_files:
        return None
    gcda = os.path.abspath(gcda_files[0])
    out = subprocess.check_output(
        [gcov, "-b", os.path.basename(gcda)],
        text=True,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(gcda),
    )
    print(out)
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "src/parser.cpp" not in line and not line.endswith("parser.cpp'"):
            continue
        if "File" not in line:
            continue
        for nxt in lines[i + 1 : i + 8]:
            if "Lines executed" in nxt:
                value = parse_percent(nxt)
                if value is not None:
                    return value
    return None


def main() -> int:
    build_dir = sys.argv[1] if len(sys.argv) > 1 else "build-cov"
    try:
        cover = llvm_line_cover(build_dir)
        if cover is None:
            cover = gcov_line_cover(build_dir)
    except subprocess.CalledProcessError as exc:
        output = exc.output if isinstance(exc.output, str) else ""
        if output:
            print(output)
        print(f"error: coverage tool failed: {exc}", file=sys.stderr)
        return 2
    if cover is None:
        print("error: could not measure parser.cpp line coverage", file=sys.stderr)
        return 2
    print(f"parser.cpp line coverage: {cover:.2f}% (threshold {THRESHOLD:.0f}%)")
    if cover < THRESHOLD:
        print("error: parser.cpp line coverage is under 80%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
