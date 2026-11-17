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
# A panicking test aborts its whole package and hides every test that has not run yet.
# So: record the panicking test as failed, re-run skipping it, and repeat until a run
# finishes without a panic. Failures come from the final run plus the panicked tests.
PANICKED="$OUT_DIR/panicked-$OS_NAME.txt"
: > "$PANICKED"
SKIP_RE=""
RESULT="$OUT_DIR/test-$OS_NAME.json"
for attempt in $(seq 1 30); do
  SKIP_ARGS=()
  [[ -n "$SKIP_RE" ]] && SKIP_ARGS=(-skip "^($SKIP_RE)\$")
  # shellcheck disable=SC2086
  go test -race -count=1 -timeout 30m -json ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"} ${DBT_CI_TEST_ARGS:-./...} > "$RESULT"
  echo "go test attempt $attempt exit code: $? (ignored; compared against baseline)"

  NEW_PANICS="$(jq -r 'select(.Action == "output" and .Test != null and (.Output | test("^panic: "))) |
                       "\(.Package) \(.Test | split("/")[0])"' "$RESULT" | tr -d '\r' | LC_ALL=C sort -u)"
  [[ -z "$NEW_PANICS" ]] && break
  echo "::warning::panicking tests, re-running without them:"
  echo "$NEW_PANICS"
  echo "$NEW_PANICS" >> "$PANICKED"
  SKIP_RE="$(awk '{print $2}' "$PANICKED" | LC_ALL=C sort -u | paste -sd'|' -)"
  if [[ "$attempt" == 30 ]]; then echo "::error::too many panicking tests"; exit 1; fi
done

# (jq on Windows emits CRLF, hence the tr.)
# Failing tests (including subtests), plus packages that failed as a whole
# (build failure, timeout, ...) so a package-level break is never hidden.
# Baseline/failure files may hold "# ..." comments: whole-line comments, and a trailing
# " # panic" on tests that crashed the test binary. Strip them before comparing. The
# delimiter is " #" (not a bare "#") because Go subtest names can contain "#01".
normalize() { tr -d '\r' | sed -E -e 's/[[:space:]]+#.*$//' -e '/^#/d' -e '/^[[:space:]]*$/d' | LC_ALL=C sort -u; }

{
  echo "# Failing tests recorded by ci/dbt/test.sh. '# panic' marks tests that crashed the"
  echo "# test binary (they are skipped and re-run, see ci/dbt/README.md)."
  {
    jq -r 'select(.Action == "fail") |
           if .Test then "\(.Package) \(.Test)" else "\(.Package) [package]" end' "$RESULT" | normalize
    sed 's/$/ # panic/' "$PANICKED" | tr -d '\r'
  } | LC_ALL=C sort -u
} > "$FAILURES"

if [[ ! -f "$BASELINE" ]]; then
  echo "::error::No baseline for $OS_NAME at ci/dbt/baseline/$OS_NAME.txt."
  echo "Record it: download the failures-$OS_NAME.txt artifact from this run and commit it there."
  exit 1
fi

normalize < "$BASELINE" > "$OUT_DIR/baseline-$OS_NAME.norm"
normalize < "$FAILURES" > "$OUT_DIR/failures-$OS_NAME.norm"
NEW="$(LC_ALL=C comm -13 "$OUT_DIR/baseline-$OS_NAME.norm" "$OUT_DIR/failures-$OS_NAME.norm")"
FIXED="$(LC_ALL=C comm -23 "$OUT_DIR/baseline-$OS_NAME.norm" "$OUT_DIR/failures-$OS_NAME.norm")"
# Picked up by the "report" job in dbt-ci.yml, which comments on the PR.
printf '%s\n' "$FIXED" | sed '/^$/d' > "$OUT_DIR/fixed-$OS_NAME.txt"

echo "baseline failures: $(wc -l < "$OUT_DIR/baseline-$OS_NAME.norm" | tr -d ' '), current failures: $(wc -l < "$OUT_DIR/failures-$OS_NAME.norm" | tr -d ' ')"
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
