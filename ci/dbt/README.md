# dbt fork CI

CI for the dbt fork lives only in new files so merging upstream never conflicts:
`.github/workflows/dbt-ci.yml` and this directory.

## Upstream workflows are disabled, not edited

The workflows inherited from upstream (`build-test.yml`, `changelog.yml`, `cla_bot.yml`,
`jira_*.yml`, `semgrep.yml`) need Snowflake-internal secrets and services. They are
disabled in the repo's Actions settings, which does not touch the files:

    gh workflow list --all
    gh workflow disable <file>.yml

This is keyed by file path. If a merge brings in a new upstream workflow it starts
enabled; disable it too. Only the `dbt-ci gate` check is required for merging.

## Test gate

Most tests need a live Snowflake account and fail without one. `test.py` (Python 3,
standard library only) runs the suite with `SKIP_SETUP=1` plus wiremock (needs Java) and
fails only on failures that are not in `baseline/<os>.json`.

    python ci/dbt/test.py                     # what CI runs
    python ci/dbt/test.py --no-wiremock       # wiremock is already running
    python ci/dbt/test.py --update-baseline   # write the result as this OS's baseline
    python ci/dbt/test.py --help

### Baseline files

Plain JSON, one file per OS, keyed by package:

```json
{
  "github.com/snowflakedb/gosnowflake": {
    "package_failed": true,
    "panicked": ["TestUrlDecodeIfNeededE2E"],
    "failed": ["TestShowServerVersion", "..."]
  }
}
```

- `failed`: tests that fail (subtests as `Test/subtest`).
- `panicked`: tests that crashed the test binary. A panic aborts its whole package and
  hides every test that has not run yet, so the gate records the test, re-runs without it,
  and repeats until a run completes. These are listed separately so they stand out.
- `package_failed`: the package failed as a whole (it always does when a test fails). A
  package that fails without being in the baseline is reported even if no single test
  failed, e.g. a build error or a timeout.

To record or update a baseline: run the workflow, download the `test-output-<os>` artifact
and commit its `failures-<os>.json` as `baseline/<os>.json` (or run `--update-baseline`).
Until a baseline exists for an OS, that OS's job fails and prints this. Review baseline
changes in PRs: a growing baseline means a regression was accepted.

When a test in the baseline starts passing, the `report` job in `dbt-ci.yml` posts (and
keeps updated) a single PR comment listing it per OS, so the baseline can be shrunk. It
only reports; it never fails the PR.

### Flaky and timing-sensitive tests: `config.json`

JSON has no comments, so each list carries a `reason` field.

- `no_race`: tests that depend on wall-clock timing (the file-lease tests use TTLs of a
  few hundred ms and a 12ms grace period). The race detector's slowdown breaks those
  assumptions, so they run in a second pass without `-race`. Locally, under full CPU load,
  `TestConcurrentLeaseAcquireWithRandomDurationProcesses` failed 16 of 25 runs with
  `-race` and 0 of 25 without it.
- `retry`: tests that depend on the external network (for example `expired.badssl.com`).
  A failing one is retried up to twice and only counts as failed if every attempt fails; a
  pass on retry is reported as a warning.

Add a test to either list only after finding why it is unstable, and update the `reason`.
Prefer fixing the test or the code (see the OAuth cache fix) over listing it.
