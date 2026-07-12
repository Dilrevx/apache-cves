# Apache Dataset Pipeline Plan

## Current strategy

The dataset builder is still in the early stabilization phase.  Do not jump
directly to a single fully automatic all-repository run.  Stabilize the second
half of the pipeline through explicit per-repository tasks, then extract the
stable task contract into a safer automation driver.

## Stable second-half contract

Inputs:

- `data/derived/patch_candidates.jsonl`
- `data/derived/repositories.jsonl`
- `data/repos/<repo>.git`

Processing stages:

- `clone-repos`
- `discover-patches`
- `verify-patches`
- `extract-samples`
- `validate`
- `audit-harness` as an evaluation stage, not as a dataset-labeling stage

Outputs:

- `data/derived/clone_report.jsonl`
- `data/derived/verified_patches.jsonl`
- `data/derived/rejected_patch_candidates.jsonl`
- `data/derived/skipped_contexts.jsonl`
- `data/derived/repo_status.jsonl`
- `data/dataset/samples.jsonl`
- `data/dataset/validation.json`
- `data/audits/prompts/*.md`
- `data/audits/raw/*.json`
- `data/audits/results.jsonl`

## Task record shape

Each per-repository task should update `data/derived/repo_status.jsonl` with a
row shaped like:

```json
{
  "repo": "axis-axis1-java",
  "stage": "validated",
  "candidate_count": 2,
  "verified_count": 1,
  "sample_pairs": 1,
  "audit_count": 0,
  "status": "ok",
  "last_error": null,
  "updated_at": "2026-07-11T00:00:00+00:00"
}
```

Status values should stay small and stable:

- `ok`
- `no_candidates`
- `no_verified_patches`
- `no_samples`
- `clone_error`
- `verify_error`
- `extract_error`
- `validate_error`
- `audit_error`

`data/derived/clone_report.jsonl` is the transport-level companion record.  It
should preserve the clone mode, blob filtering, optional Git proxy, attempted
URLs, and each per-source error.  On `bobo5090`, the current working transport
for GitHub clone tasks is task-local proxying with
`--git-proxy http://127.0.0.1:7890`; do not rely on global Git proxy config.

## Manual task batches

First batch, chosen to stabilize Java and small-repo behavior:

- `axis-axis1-java` - passed; class/file-level Java fallback sample
- `cxf-fediz` - passed; method-level Java sample
- `incubator-openwhisk-runtime-docker`
- `unomi` - passed; multi-file application-level Java sample

Second batch, chosen to exercise larger or non-Java projects:

- `cxf` - clone_error; GitHub early EOF, GitBox timed out
- `httpd` - clone_error; GitHub HTTP/2 cancel, GitBox URL not found
- `mynewt-nimble` - passed; 12 verified pairs
- `hive` - clone_error; manually stopped after >21m in git index-pack

Large repositories such as `arrow`, `spark`, and `openoffice` should be left
until clone timeouts, partial cleanup, and resumable fetch behavior are stable.

## Near-term implementation

1. Add `clone-repos --repo <repo>` for targeted clone tasks.
2. Add `run-repo-task --repo <repo>` to run:
   `clone -> discover-patches -> verify-patches -> extract-samples -> validate`.
3. Add optional `--audit-dry-run` and `--audit-limit` to prepare prompts
   without making model calls by default.
4. Update `repo_status.jsonl` at the end of every repo task.
5. Add `run-task-batch --repo-list <file>` as a conservative sequential driver.
   It must reuse `run-repo-task`, write `task_batch_summary.json`, and continue
   to the next repo on failure.  It must not add fallback or automatic repo
   selection.

## Current observations

- `cxf-fediz` validates method-level Java extraction and task-local Git proxying.
- `axis-axis1-java` validates class/file-context fallback for security changes
  outside a method body.
- `unomi` validates broad application-level Java patches and triggers the
  large-context hint path.  Current policy is to include full context for
  samples under the threshold; above the threshold, prepend a hint with the
  full context size and ask the audit agent to inspect the patch/repo if it has
  access.  Programmatic context ranking is still a future improvement, not part
  of the current stabilization loop.
- `audit-harness --repo <repo>` is required for per-repo tasks so dry-run prompts
  are generated for the current repository instead of the first global sample.
- Large repositories need a transport strategy beyond plain blobless clone:
  shallow commit-neighborhood fetch, GitHub codeload archive fallback, or a
  resumable local mirror cache before running broad automation.
- Do not enable archive fallback in the current manual task loop.  For now,
  clone failure should fail the repo task, write `clone_error` and
  `clone_report.jsonl`, and let the caller continue to the next repository.
  Archive fallback is deliberately deferred because it would complicate
  verification, extraction, and provenance semantics.

## Automation gate

Only after the first two manual batches produce stable status rows and context
quality should the project grow a full `run-pipeline` driver.  That driver
should consume the same task contract instead of inventing a second interface.
