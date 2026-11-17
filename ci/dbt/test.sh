#!/usr/bin/env bash
#
# dbt fork test gate.
#
# Runs the test suite without a Snowflake account (SKIP_SETUP=1) and compares the
# set of failing tests to the recorded baseline for this OS. Tests that need a live
# account fail in the baseline too; only failures that are NOT in the baseline fail
# the gate. See ci/dbt/README.md.
#
# Env:
#   DBT_CI_TEST_ARGS    override the `go test` package/flag args (default: ./...)
#   DBT_CI_NO_WIREMOCK  set to skip starting wiremock / the hang web server (local use)
#   DBT_CI_OUT          output directory (default: ci/dbt/out)
set -uo pipefail

DBT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DBT_DIR/../.." && pwd)"
OUT_DIR="${DBT_CI_OUT:-$DBT_DIR/out}"

case "$(uname -s)" in
  Linux) OS_NAME=linux ;;
  Darwin) OS_NAME=macos ;;
  MINGW* | MSYS* | CYGWIN*) OS_NAME=windows ;;
  *) echo "unsupported OS: $(uname -s)"; exit 2 ;;
esac

BASELINE="$DBT_DIR/baseline/$OS_NAME.txt"
mkdir -p "$OUT_DIR"
FAILURES="$OUT_DIR/failures-$OS_NAME.txt"

export SKIP_SETUP=1
export WIREMOCK_PORT="${WIREMOCK_PORT:-14335}"
export WIREMOCK_HTTPS_PORT="${WIREMOCK_HTTPS_PORT:-13567}"
export WIREMOCK_PORT_HTTPS="${WIREMOCK_PORT_HTTPS:-$WIREMOCK_HTTPS_PORT}"
export GORACE="${GORACE:-history_size=7}"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

if [[ -z "${DBT_CI_NO_WIREMOCK:-}" ]]; then
  python3 "$ROOT_DIR/ci/scripts/hang_webserver.py" 12345 &
  PIDS+=($!)
  "$ROOT_DIR/ci/scripts/run_wiremock.sh" > "$OUT_DIR/wiremock.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 60); do
    curl -fs "http://127.0.0.1:$WIREMOCK_PORT/__admin/mappings" > /dev/null && break
    sleep 1
  done
  curl -fs "http://127.0.0.1:$WIREMOCK_PORT/__admin/mappings" > /dev/null || {
    echo "wiremock did not start"; cat "$OUT_DIR/wiremock.log"; exit 2; }
fi

cd "$ROOT_DIR"
# shellcheck disable=SC2086
go test -race -count=1 -timeout 30m -json ${DBT_CI_TEST_ARGS:-./...} > "$OUT_DIR/test-$OS_NAME.json"
echo "go test exit code: $? (ignored; compared against baseline)"

# Failing tests (including subtests), plus packages that failed as a whole
# (build failure, panic, timeout) so a package-level break is never hidden.
jq -r 'select(.Action == "fail") |
       if .Test then "\(.Package) \(.Test)" else "\(.Package) [package]" end' \
  "$OUT_DIR/test-$OS_NAME.json" | LC_ALL=C sort -u > "$FAILURES"

if [[ ! -f "$BASELINE" ]]; then
  echo "::error::No baseline for $OS_NAME at ci/dbt/baseline/$OS_NAME.txt."
  echo "Record it: download the failures-$OS_NAME.txt artifact from this run and commit it there."
  exit 1
fi

NEW="$(LC_ALL=C comm -13 <(LC_ALL=C sort -u "$BASELINE") "$FAILURES")"
FIXED="$(LC_ALL=C comm -23 <(LC_ALL=C sort -u "$BASELINE") "$FAILURES")"

echo "baseline failures: $(wc -l < "$BASELINE" | tr -d ' '), current failures: $(wc -l < "$FAILURES" | tr -d ' ')"
if [[ -n "$FIXED" ]]; then
  echo "::notice::tests in the baseline that now pass (consider shrinking the baseline):"
  echo "$FIXED"
fi
if [[ -n "$NEW" ]]; then
  echo "::error::New test failures not in the baseline:"
  echo "$NEW"
  exit 1
fi
echo "No new failures."
