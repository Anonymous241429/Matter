#!/usr/bin/env python3
"""
detect_gap1195.py
============================================================
GAP-1195: kTag_NumberOfDevices Missing from ECM TLV Content
          CHIPDeviceController.cpp switch ~line 3131

ROOT CAUSES OF 0 FINDINGS:
  1. [^}]{0,600} regex: stops at first nested { } brace
     in the real switch body — never reaches CommissioningTimeout
  2. pattern-not-regex suppression: kTag_NumberOfDevices
     appears in comments and enum definitions within the
     SAME MATCH REGION, suppressing findings
  3. File-level pattern-not-regex: when kTag_NumberOfDevices
     exists in ANY function in the file (e.g. the fixed path
     or OpenJointCommissioningWindow), file-level rules fire
     incorrectly

CORRECT APPROACH:
  - Use a 2-phase sliding window detector:
    Phase 1: Find kArmFailsafe CASE (not enum definition, not comment)
    Phase 2: Scan the case body ONLY (stop at next 'case' or end of switch)
    Phase 3: In the case body, check for CommissioningTimeout write
             WITHOUT a kTag_NumberOfDevices Put() call on a CODE line
    This is function-scoped and comment-aware.
============================================================
"""

import sys
import re
import argparse
import subprocess
from pathlib import Path

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
BLUE="\033[0;34m"; BOLD="\033[1m"; NC="\033[0m"

def ok(m):   print(f"  {GREEN}✓{NC}  {m}")
def fail(m): print(f"  {RED}✗{NC}  {m}")
def info(m): print(f"  {BLUE}●{NC}  {m}")
def warn(m): print(f"  {YELLOW}⚠{NC}  {m}")
def hdr(m):  print(f"\n{BOLD}{BLUE}── {m} ──{NC}")

# ── Patterns ──────────────────────────────────────────────────
# Matches case kArmFailsafe (not enum definition, not comment)
PAT_CASE_FAILSAFE = re.compile(
    r'case\s+(?:chip::)?CommissioningStage::kArmFailsafe'
    r'|case\s+kStage_kArmFailsafe'
    r'|case\s+CommissioningStage::kArmFailsafe'
)
# Next case statement — marks end of kArmFailsafe body
PAT_NEXT_CASE  = re.compile(r'^\s*case\s+')
PAT_SWITCH_END = re.compile(r'^\s*\}\s*$')  # closing brace of switch

# In case body: CommissioningTimeout written (TLV Put call)
PAT_TIMEOUT_PUT = re.compile(
    r'\.Put\s*\([^)]*Timeout|'
    r'kTag_CommissioningTimeout|'
    r'GetFailsafeTimerSeconds|'
    r'ArmFailsafe\s*\('
)
# NumberOfDevices ACTUALLY WRITTEN (Put call, not just mentioned)
PAT_NUM_DEV_PUT = re.compile(
    r'\.Put\s*\([^)]*NumberOfDevices|'
    r'kTag_NumberOfDevices\s*,'
)

def is_comment(line: str) -> bool:
    s = line.strip()
    return (s.startswith('//') or s.startswith('*')
            or s.startswith('/*'))


def extract_case_body(lines: list, case_start: int) -> list:
    """
    Extract lines belonging to the kArmFailsafe case body only.
    Stops at: next 'case', 'default:', or end of switch block.
    Returns list of (absolute_lineno, line_text) tuples.
    """
    body = []
    n = len(lines)
    i = case_start + 1   # start after the 'case kArmFailsafe:' line
    depth = 0

    while i < n and i < case_start + 80:  # max 80 lines per case
        line = lines[i]
        # Stop at next case or default
        if (PAT_NEXT_CASE.match(line)
                and 'kArmFailsafe' not in line):
            break
        if re.match(r'^\s*default\s*:', line):
            break
        # Track brace depth to detect end of switch
        depth += line.count('{') - line.count('}')
        if depth < -1:   # we've exited the switch
            break
        body.append((i + 1, line))
        i += 1

    return body


def analyse_file(path: Path) -> list:
    try:
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except Exception as e:
        warn(f"Cannot read {path}: {e}")
        return []

    findings = []
    n = len(lines)

    for i, line in enumerate(lines):
        # Skip comment and enum lines
        if is_comment(line):
            continue
        # Must be a real 'case kArmFailsafe:' statement
        if not PAT_CASE_FAILSAFE.search(line):
            continue

        # Extract case body (code lines only)
        body = extract_case_body(lines, i)
        code_body = [(ln, l) for ln, l in body
                     if not is_comment(l)]

        code_text = '\n'.join(l for _, l in code_body)

        has_timeout = bool(PAT_TIMEOUT_PUT.search(code_text))
        # Check for actual Put(kTag_NumberOfDevices, ...) call
        has_num_dev = bool(PAT_NUM_DEV_PUT.search(code_text))

        if has_timeout and not has_num_dev:
            # Find the line with CommissioningTimeout for context
            timeout_lineno = i + 1
            for ln, l in code_body:
                if PAT_TIMEOUT_PUT.search(l):
                    timeout_lineno = ln
                    break

            findings.append({
                "file"         : str(path),
                "lineno"       : i + 1,
                "timeout_line" : timeout_lineno,
                "line"         : line.strip(),
                "rule"         : "gap1195-armfailsafe-no-number-of-devices",
                "severity"     : "ERROR",
                "message"      : (
                    "kArmFailsafe case writes kTag_CommissioningTimeout\n"
                    "    but NEVER writes kTag_NumberOfDevices.\n"
                    "    Per CSA Matter Spec §5.1.5(g): when multiple Nodes\n"
                    "    are subjected to ECM, TLV SHALL contain\n"
                    "    kTag_NumberOfDevices with expected device count.\n"
                    "    An attacker can inject extra nodes undetected."
                ),
                "fix"          : (
                    "In kArmFailsafe case add:\n"
                    "  if (params.isJointCommissioning &&\n"
                    "      params.numberOfDevices > 1) {\n"
                    "    writer.Put(kTag_NumberOfDevices,\n"
                    "               params.numberOfDevices);\n"
                    "  }"
                ),
                "context"      : lines[max(0,i-1):i+8],
                "context_start": max(0,i-1)+1,
            })

    return findings


def print_findings(findings):
    if not findings:
        ok("No GAP-1195 patterns detected.")
        return
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    for filepath, flist in by_file.items():
        print(f"\n  {BOLD}File: {filepath}{NC}")
        print(f"  {'─'*60}")
        for f in flist:
            sc = RED if f["severity"] == "ERROR" else YELLOW
            print(f"\n  {sc}[{f['severity']}]{NC}  "
                  f"{BOLD}{f['rule']}{NC}")
            print(f"  Case at line {f['lineno']}: "
                  f"{f['line'][:65]}")
            print(f"  Timeout at  line {f['timeout_line']}")
            print()
            for ln in f["message"].split("\n"):
                print(f"    {ln}")
            print()
            print(f"  {GREEN}Fix:{NC}")
            for ln in f["fix"].split("\n"):
                print(f"    {ln}")
            print()
            print(f"  {BLUE}Context (lines "
                  f"{f['context_start']}+):{NC}")
            for j, ctx in enumerate(f["context"]):
                lno    = f["context_start"] + j
                marker = ">>>" if lno == f["lineno"] else "   "
                clr    = RED if lno == f["lineno"] else NC
                print(f"  {clr}{marker} {lno:4d}  {ctx}{NC}")


def run_semgrep(src: Path) -> bool:
    hdr("Semgrep Analysis")
    rule = Path(__file__).parent / \
           "static" / "semgrep_gap1195_final.yaml"
    if not rule.exists():
        warn("Semgrep rule not found")
        return False
    try:
        result = subprocess.run(
            ["semgrep", "--config", str(rule),
             "--no-git-ignore", str(src), "--text"],
            capture_output=False
        )
        return result.returncode == 0
    except FileNotFoundError:
        warn("semgrep not installed")
        return False


def run_pytest() -> bool:
    hdr("Python Pytest Suite")
    test_py = Path(__file__).parent / \
              "pytest" / "test_gap1195_number_of_devices.py"
    if not test_py.exists():
        warn("pytest file not found")
        return False
    result = subprocess.run(
        ["python3", "-m", "pytest", str(test_py),
         "-v", "--tb=short"],
        capture_output=False
    )
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="GAP-1195: NumberOfDevices TLV Detection"
    )
    parser.add_argument("--src", required=True,
        help="CHIPDeviceController.cpp or source dir")
    parser.add_argument("--run-semgrep", action="store_true")
    parser.add_argument("--run-pytest",  action="store_true")
    args = parser.parse_args()

    src = Path(args.src)
    print()
    print(f"{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  GAP-1195: kTag_NumberOfDevices Missing in ECM{NC}")
    print(f"{BOLD}  CommissioningStage::kArmFailsafe switch case{NC}")
    print(f"{BOLD}  CSA Matter Spec §5.1.5(g) SHALL enforcement{NC}")
    print(f"{BOLD}{'='*60}{NC}")

    files = ([src] if src.is_file()
             else list(src.rglob("*.cpp")) + list(src.rglob("*.c")))
    info(f"Scanning {len(files)} file(s)...")

    hdr("Static Source Analysis")
    all_findings = []
    for f in files:
        all_findings.extend(analyse_file(f))

    print_findings(all_findings)

    errors = [f for f in all_findings if f["severity"] == "ERROR"]
    print(f"\n{BOLD}{'─'*60}{NC}")
    print(f"  Findings: {RED}{len(errors)} errors{NC}")
    if errors:
        print(f"\n  {RED}{BOLD}GAP-1195 CONFIRMED:{NC}")
        for f in errors:
            print(f"    {f['file']}:{f['lineno']}")
    else:
        print(f"\n  {GREEN}No GAP-1195 patterns found.{NC}")
    print(f"{BOLD}{'─'*60}{NC}")

    if args.run_semgrep: run_semgrep(src)
    if args.run_pytest:  run_pytest()


if __name__ == "__main__":
    main()
