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

Most tests need a live Snowflake account and fail without one. `ci/dbt/test.sh` runs the
suite with `SKIP_SETUP=1` (plus wiremock) and fails only on failures that are not in
`ci/dbt/baseline/<os>.txt`. Package-level failures (build errors, panics, timeouts) are
recorded as `<package> [package]`, so they are never silently ignored.

Recording or updating a baseline: run the workflow, download the `test-output-<os>`
artifact, and commit its `failures-<os>.txt` as `ci/dbt/baseline/<os>.txt`. Until a
baseline exists for an OS, that OS's job fails and prints this instruction.

Review baseline changes in PRs: a growing baseline means a regression was accepted.
