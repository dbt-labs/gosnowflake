#!/usr/bin/env python3
"""dbt fork test gate.

Runs the test suite without a Snowflake account (SKIP_SETUP=1) and compares the failing
tests to the recorded baseline for this OS (ci/dbt/baseline/<os>.json). Tests that need a
live account fail in the baseline too; only failures that are NOT in the baseline fail the
gate. See ci/dbt/README.md.

Standard library only.
"""

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DBT_DIR = Path(__file__).resolve().parent
ROOT_DIR = DBT_DIR.parent.parent
SCRIPTS_DIR = ROOT_DIR / "ci" / "scripts"
WIREMOCK_VERSION = "3.11.0"
OS_NAME = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "unknown")
MAX_PANIC_RERUNS = 30
RETRIES = 2


def log(msg):
    print(msg, flush=True)


def load_events(path):
    """Events of a `go test -json` run. Non-JSON lines (e.g. build output) are ignored."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return events


def panicked_tests(events):
    """(package, top-level test) of tests that panicked. A panic aborts the whole package."""
    return {
        (e["Package"], e["Test"].split("/")[0])
        for e in events
        if e.get("Action") == "output" and e.get("Test") and e.get("Output", "").startswith("panic: ")
    }


def failed(events):
    """({package: failed test names}, {packages that failed as a whole})."""
    tests, packages = {}, set()
    for e in events:
        if e.get("Action") != "fail":
            continue
        if e.get("Test"):
            tests.setdefault(e["Package"], set()).add(e["Test"])
        else:
            packages.add(e["Package"])
    return tests, packages


def go_test(result, race, run, skip, extra):
    cmd = ["go", "test", "-count=1", "-timeout", "30m", "-json"]
    if race:
        cmd.append("-race")
    if run:
        cmd += ["-run", "^(" + "|".join(run) + ")$"]
    if skip:
        cmd += ["-skip", "^(" + "|".join(sorted(skip)) + ")$"]
    cmd += extra
    with open(result, "w", encoding="utf-8") as f:
        return subprocess.run(cmd, cwd=ROOT_DIR, stdout=f).returncode


def run_pass(result, race, run, skip, extra):
    """Runs go test until a pass completes without any test panicking.

    A panic aborts its whole package and hides remaining tests in that package. On each
    panic, we record the panicking test(s) in `panicked` and re-run with them skipped so
    the rest of the suite executes. Returns (events, panicked), where `events` is from the
    final panic-free attempt (which re-ran all non-panicking tests) and `panicked` contains
    every test that panicked across attempts (still counted as failures against the baseline).
    """
    panicked = set()
    for attempt in range(1, MAX_PANIC_RERUNS + 1):
        attempt_result = result.with_stem(f"{result.stem}-attempt{attempt}")
        skip_all = set(skip) | {t for _, t in panicked}
        rc = go_test(attempt_result, race, run, skip_all, extra)
        log(f"go test attempt {attempt} ({attempt_result.name}) exit code: {rc} (ignored; compared against baseline)")
        events = load_events(attempt_result)
        # Previously panicked tests were skipped above; subtract `panicked` as a guard
        # against an infinite loop if `-skip` ever fails to match.
        new_panics = panicked_tests(events) - panicked
        if not new_panics:
            return events, panicked
        log("::warning::panicking tests, re-running without them:")
        for pkg, test in sorted(new_panics):
            log(f"{pkg} {test}")
        panicked |= new_panics
    log("::error::too many panicking tests")
    sys.exit(1)


def retry_failures(failed_tests, packages, retry_names, retried):
    """Retries failed network-dependent tests. One that passes on retry is not a failure but
    is reported so flakiness stays visible."""
    touched = set()
    for pkg, tests in failed_tests.items():
        for top in sorted({t.split("/")[0] for t in tests} & set(retry_names)):
            for attempt in range(1, RETRIES + 1):
                rc = subprocess.run(
                    ["go", "test", "-race", "-count=1", "-run", f"^{top}$", pkg],
                    cwd=ROOT_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ).returncode
                if rc == 0:
                    log(f"::warning::{top} failed but passed on retry {attempt} (network-dependent test)")
                    retried.append({"package": pkg, "test": top})
                    tests -= {t for t in tests if t == top or t.startswith(top + "/")}
                    touched.add(pkg)
                    break
    # A package whose only failures were retried tests no longer counts as failed.
    for pkg in touched:
        if not failed_tests[pkg]:
            packages.discard(pkg)


def build_result(failed_tests, packages, panicked):
    """Result in the same schema as a baseline file, so it can be committed as one."""
    result = {}
    for pkg in sorted(set(failed_tests) | packages | {p for p, _ in panicked}):
        result[pkg] = {
            "package_failed": pkg in packages,
            "panicked": sorted(t for p, t in panicked if p == pkg),
            "failed": sorted(failed_tests.get(pkg, ())),
        }
    return result


def write_json(path, data):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def failing_set(result):
    """(package, test) of every failed or panicked test in a result/baseline."""
    return {(pkg, t) for pkg, r in result.items() for t in r.get("failed", []) + r.get("panicked", [])}


def compare(baseline, current):
    new = sorted(failing_set(current) - failing_set(baseline))
    fixed = sorted(failing_set(baseline) - failing_set(current))
    new_packages = sorted(
        pkg for pkg, r in current.items()
        if r["package_failed"] and not baseline.get(pkg, {}).get("package_failed")
    )
    return new, fixed, new_packages


class Services:
    """wiremock (a fake Snowflake server, needs Java) and the hang web server the tests use."""

    def __init__(self, out_dir, http_port, https_port):
        self.procs, self.out_dir = [], out_dir
        self.http_port, self.https_port = http_port, https_port

    def start(self):
        self.procs.append(subprocess.Popen([sys.executable, str(SCRIPTS_DIR / "hang_webserver.py"), "12345"]))
        jar = SCRIPTS_DIR / f"wiremock-standalone-{WIREMOCK_VERSION}.jar"
        if not jar.exists():
            url = f"https://repo1.maven.org/maven2/org/wiremock/wiremock-standalone/{WIREMOCK_VERSION}/{jar.name}"
            urllib.request.urlretrieve(url, jar)
        self.wiremock_log = open(self.out_dir / "wiremock.log", "w")
        self.procs.append(subprocess.Popen(
            ["java", "-jar", str(jar), "--port", str(self.http_port), "--https-port", str(self.https_port),
             "--https-keystore", str(SCRIPTS_DIR / "wiremock.p12"), "--keystore-type", "PKCS12",
             "--keystore-password", "password"],
            cwd=SCRIPTS_DIR, stdout=self.wiremock_log, stderr=subprocess.STDOUT,
        ))
        url = f"http://127.0.0.1:{self.http_port}/__admin/mappings"
        for _ in range(60):
            try:
                urllib.request.urlopen(url, timeout=2).close()
                return
            except OSError:
                time.sleep(1)
        log("wiremock did not start:")
        log((self.out_dir / "wiremock.log").read_text())
        sys.exit(2)

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DBT_DIR / "out", help="output directory (default: ci/dbt/out)")
    ap.add_argument("--config", type=Path, default=DBT_DIR / "config.json")
    ap.add_argument("--baseline", type=Path, default=DBT_DIR / "baseline" / f"{OS_NAME}.json")
    ap.add_argument("--update-baseline", action="store_true", help="write the result as the new baseline and exit")
    ap.add_argument("--no-wiremock", action="store_true", help="do not start wiremock (it is already running)")
    ap.add_argument("--run", help="local debugging: only run tests matching this regexp in the main pass")
    ap.add_argument("--go-args", default="./...", help="packages and flags passed to go test (default: ./...)")
    args = ap.parse_args()

    if OS_NAME == "unknown":
        log(f"unsupported OS: {platform.system()}")
        return 2
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    config = json.loads(args.config.read_text())
    no_race = config["no_race"]["tests"]
    retry_names = config["retry"]["tests"]
    extra = shlex.split(args.go_args)

    http_port = os.environ.setdefault("WIREMOCK_PORT", "14335")
    https_port = os.environ.setdefault("WIREMOCK_HTTPS_PORT", "13567")
    os.environ.setdefault("WIREMOCK_PORT_HTTPS", https_port)
    os.environ.setdefault("GORACE", "history_size=7")
    os.environ["SKIP_SETUP"] = "1"

    services = Services(out, http_port, https_port)
    try:
        if not args.no_wiremock:
            services.start()

        # Timing-sensitive tests run in a second pass without -race (see config.json).
        events, panicked = run_pass(
            out / f"go-test-race-{OS_NAME}.jsonl", True,
            [args.run] if args.run else [], no_race, extra,
        )
        if no_race:
            no_race_events, no_race_panicked = run_pass(
                out / f"go-test-norace-{OS_NAME}.jsonl", False,
                no_race, [], extra,
            )
            events += no_race_events
            panicked |= no_race_panicked
    finally:
        services.stop()

    failed_tests, packages = failed(events)
    retried = []
    retry_failures(failed_tests, packages, retry_names, retried)
    write_json(out / f"retried-{OS_NAME}.json", retried)

    current = build_result(failed_tests, packages, panicked)
    write_json(out / f"failures-{OS_NAME}.json", current)

    if args.update_baseline:
        write_json(args.baseline, current)
        log(f"wrote baseline {args.baseline}")
        return 0
    if not args.baseline.exists():
        log(f"::error::No baseline for {OS_NAME} at {args.baseline}.")
        log(f"Record it: download failures-{OS_NAME}.json from this run's artifact and commit it there.")
        return 1

    baseline = json.loads(args.baseline.read_text())
    new, fixed, new_packages = compare(baseline, current)
    # Picked up by the "report" job in dbt-ci.yml, which comments on the PR.
    write_json(out / f"fixed-{OS_NAME}.json", [{"package": p, "test": t} for p, t in fixed])

    log(f"baseline failures: {len(failing_set(baseline))}, current failures: {len(failing_set(current))}")
    if fixed:
        log("::notice::tests in the baseline that now pass (consider shrinking the baseline):")
        for pkg, test in fixed:
            log(f"{pkg} {test}")
    if new or new_packages:
        log("::error::New test failures not in the baseline:")
        for pkg, test in new:
            log(f"{pkg} {test}")
        for pkg in new_packages:
            log(f"{pkg} [package failed as a whole]")
        return 1
    log("No new failures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
