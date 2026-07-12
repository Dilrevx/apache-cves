# Claude Handoff Notes

## Workspace

Primary remote workspace:

```text
ssh bobo5090:/data/lhq/workspace/apache-vuln-dataset
```

Local working copy:

```text
/Users/bytedance/.amux/workspaces/cli/LD93HRV6QM/apache-builder
```

Prefer editing locally, running `python3 -m py_compile build_dataset.py`, then
syncing changed files to the remote workspace.

## Operating Mode

The project is in controlled batch-construction mode.

- Use `run-task-batch` for explicit repo lists.
- Use batches of up to 20 repos.
- Use `--continue-on-error`.
- Keep `--audit-dry-run` as the default audit mode.
- Use task-local Git proxying on `bobo5090`:

```bash
--git-proxy http://127.0.0.1:7890
```

Do not start a broad all-Apache automatic run without first generating and
reviewing the repo list.

## Standard Batch Command

```bash
python3 build_dataset.py run-task-batch \
  --output ./data \
  --repo-list data/config/batch_001.txt \
  --audit-dry-run \
  --audit-limit 1 \
  --git-proxy http://127.0.0.1:7890 \
  --clone-timeout 1200 \
  --continue-on-error
```

## Batch List Construction

Generate candidate repo lists from `data/derived/patch_candidates.jsonl`.

Rules:

- skip repos already marked `ok` in `data/derived/repo_status.jsonl`
- sort remaining repos by candidate count ascending
- put at most 20 repos in one `data/config/batch_*.txt`
- keep comments allowed with `#`

Current stabilization list:

```text
data/config/manual_batch_stabilization.txt
```

## Success Checks

After every batch, inspect:

```bash
cat data/derived/task_batch_summary.json
cat data/dataset/validation.json
tail -n 40 data/derived/repo_status.jsonl
cat data/derived/skipped_contexts.jsonl
df -h /data /
du -sh data/repos
```

Expected invariants:

- `validation.json.valid` is `true`
- every successful repo has `status=ok`
- clone failures are recorded as `clone_error`
- audit stage is `prompt_prepared` unless a real audit run was requested
- dataset labels remain paired `vulnerable` and `patched`

## Important Policy Decisions

- Do not implement archive fallback in the current task loop.
- On clone failure, log `clone_error` and continue to the next repo.
- Keep audit harness output separate from dataset labels.
- Do not treat model verdicts as ground truth.
- Do not use global Git proxy config; pass proxy through task args.
- Do not delete partial clone directories unless explicitly doing cleanup.

## Known Issues

- `discover-patches` and `verify-patches` currently operate globally, so each
  repo task can rescan previously cloned repos.  This is the next likely
  performance bottleneck as batch sizes grow.
- Large-context samples use a hint plus truncation.  Programmatic context
  ranking is intentionally deferred.
- Some verified patches can be skipped with `no_source_context`; this is
  acceptable when validation still passes, but inspect `skipped_contexts.jsonl`
  after each batch.

## Current Baseline

The monitored stabilization batch completed successfully:

- 8/8 configured repos were `ok`
- 108 samples
- 54 pairs
- validation passed

High-yield repos from the baseline:

- `httpd`: 22 pairs
- `mynewt-nimble`: 12 pairs
- `cxf`: 8 pairs
- `hive`: 4 pairs
