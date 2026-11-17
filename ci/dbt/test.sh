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
#   DBT_CI_NO_RACE_FILE override ci/dbt/no-race-tests.txt (tests run without -race)
#   DBT_CI_RETRY_FILE   override ci/dbt/retry-tests.txt (network tests that get retried)
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

# Lists live next to this script: one test name per line, '#' comments allowed.
read_list() { [[ -f "$1" ]] && sed -E -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$1" | tr -d '\r'; }
join_re() { paste -sd'|' -; }
# Baseline/failure files may hold "# ..." comments: whole-line comments, and a trailing
# " # panic" on tests that crashed the test binary. Strip them before comparing. The
# delimiter is " #" (not a bare "#") because Go subtest names can contain "#01".
normalize() { tr -d '\r' | sed -E -e 's/[[:space:]]+#.*$//' -e '/^#/d' -e '/^[[:space:]]*$/d' | LC_ALL=C sort -u; }

# Tests that depend on wall-clock timing (lease TTLs of a few hundred ms) break under the
# race detector's slowdown, so they run in a second pass without -race.
NO_RACE_RE="$(read_list "${DBT_CI_NO_RACE_FILE:-$DBT_DIR/no-race-tests.txt}" | join_re)"
# Tests that depend on the external network are retried before counting as failed.
RETRY_FILE="${DBT_CI_RETRY_FILE:-$DBT_DIR/retry-tests.txt}"

# A panicking test aborts its whole package and hides every test that has not run yet.
# So: record the panicking test as failed, re-run skipping it, and repeat until a run
# finishes without a panic. Failures come from the final run plus the panicked tests.
PANICKED="$OUT_DIR/panicked-$OS_NAME.txt"
: > "$PANICKED"

# run_pass <result.json> <race flag or ""> <run regex or ""> <extra skip regex or "">
run_pass() {
  local result=$1 race=$2 run_re=$3 extra_skip=$4 attempt skip_re new_panics
  for attempt in $(seq 1 30); do
    skip_re="$(awk '{print $2}' "$PANICKED" | LC_ALL=C sort -u | paste -sd'|' -)"
    [[ -n "$extra_skip" ]] && skip_re="${skip_re:+$skip_re|}$extra_skip"
    local rc args=(-count=1 -timeout 30m -json)
    [[ -n "$race" ]] && args+=(-race)
    [[ -n "$run_re" ]] && args+=(-run "^($run_re)\$")
    [[ -n "$skip_re" ]] && args+=(-skip "^($skip_re)\$")
    # shellcheck disable=SC2086
    go test "${args[@]}" ${DBT_CI_TEST_ARGS:-./...} > "$result"
    rc=$?
    echo "go test attempt $attempt ($(basename "$result")) exit code: $rc (ignored; compared against baseline)"

    new_panics="$(jq -r 'select(.Action == "output" and .Test != null and (.Output | test("^panic: "))) |
                         "\(.Package) \(.Test | split("/")[0])"' "$result" | tr -d '\r' | LC_ALL=C sort -u)"
    [[ -z "$new_panics" ]] && return 0
    echo "::warning::panicking tests, re-running without them:"
    echo "$new_panics"
    echo "$new_panics" >> "$PANICKED"
  done
  echo "::error::too many panicking tests"
  exit 1
}

RESULTS=("$OUT_DIR/test-$OS_NAME-race.json")
run_pass "${RESULTS[0]}" -race "" "$NO_RACE_RE"
if [[ -n "$NO_RACE_RE" ]]; then
  RESULTS+=("$OUT_DIR/test-$OS_NAME-norace.json")
  run_pass "${RESULTS[1]}" "" "$NO_RACE_RE" ""
fi

# Failing tests (including subtests), plus packages that failed as a whole
# (build failure, timeout, ...) so a package-level break is never hidden.
# (jq on Windows emits CRLF, hence the tr in normalize.)
FAILED_TESTS="$OUT_DIR/failed-tests-$OS_NAME.txt"
jq -r 'select(.Action == "fail") |
       if .Test then "\(.Package) \(.Test)" else "\(.Package) [package]" end' "${RESULTS[@]}" | normalize > "$FAILED_TESTS"

# Retry network-dependent failures. A test that passes on retry is not a failure, but it
# is reported so flakiness stays visible.
RETRIED="$OUT_DIR/retried-$OS_NAME.txt"
: > "$RETRIED"
RETRY_NAMES="$(read_list "$RETRY_FILE")"
if [[ -n "$RETRY_NAMES" ]]; then
  CANDIDATES="$(printf '%s\n' "$RETRY_NAMES" | awk 'NR==FNR{r[$1]=1;next}
                  $2!="[package]"{split($2,a,"/"); if (a[1] in r) print $1" "a[1]}' - "$FAILED_TESTS" | LC_ALL=C sort -u)"
  while read -r pkg top; do
    [[ -z "$pkg" ]] && continue
    for try in 1 2; do
      if go test -race -count=1 -run "^$top\$" "$pkg" < /dev/null > /dev/null 2>&1; then
        echo "::warning::$top failed but passed on retry $try (network-dependent test)"
        echo "$pkg $top" >> "$RETRIED"
        awk -v p="$pkg" -v t="$top" '!($1==p && ($2==t || index($2, t"/")==1))' "$FAILED_TESTS" > "$FAILED_TESTS.tmp" \
          && mv "$FAILED_TESTS.tmp" "$FAILED_TESTS"
        break
      fi
    done
  done <<< "$CANDIDATES"
  # A package whose only failures were retried tests no longer counts as failed.
  while read -r pkg _; do
    [[ -z "$pkg" ]] && continue
    awk -v p="$pkg" '$1==p && $2!="[package]"{f=1} END{exit !f}' "$FAILED_TESTS" ||
      { awk -v p="$pkg" '!($1==p && $2=="[package]")' "$FAILED_TESTS" > "$FAILED_TESTS.tmp" && mv "$FAILED_TESTS.tmp" "$FAILED_TESTS"; }
  done < <(sort -u "$RETRIED")
fi

{
  echo "# Failing tests recorded by ci/dbt/test.sh. '# panic' marks tests that crashed the"
  echo "# test binary (they are skipped and re-run, see ci/dbt/README.md)."
  {
    cat "$FAILED_TESTS"
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
