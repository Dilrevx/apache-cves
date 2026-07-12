# Apache Dataset Builder Architecture

## Goal

Build a provenance-preserving Apache CVE-to-patch dataset with paired
pre-patch and post-patch source contexts.  The dataset is designed for
security-audit evaluation, not for automatic label generation.

## Design Principles

- Keep every stage resumable and inspectable through JSON/JSONL artifacts.
- Treat Git commit evidence as the source of truth for verified samples.
- Keep audit harness output separate from dataset labels.
- Prefer explicit per-repository tasks and batch lists over broad automatic
  execution until repo acquisition and context quality are stable.
- On clone failure, write structured status and continue to the next repo.
  Do not use archive fallback in the current stabilization loop.

## Data Layout

```text
data/
  config/
    manual_batch_stabilization.txt
    batch_*.txt               explicit batch repo lists
  dataset/
    samples.jsonl             final paired vulnerable/patched contexts
    validation.json           schema/pair validation report
  derived/
    clone_report.jsonl        transport attempts and clone/update errors
    patch_candidates.jsonl    candidate CVE/repo/commit links
    rejected_patch_candidates.jsonl
    repo_status.jsonl         per-repository task state
    skipped_contexts.jsonl
    task_batch_summary.json   latest batch-level summary
    verified_patches.jsonl
  state/                      compact upstream sync checkpoints
```

The construction workspace may also contain `data/repos/`, `data/raw/`, and
`data/audits/`.  Those directories are high-volume or experiment-specific and
are intentionally excluded from this release repository.

## Pipeline

1. `index-cves`
   Select Apache CNA CVEs from a local CVEListV5 checkout.

2. `collect-evidence`
   Cache Apache advisory, mailing list, and JIRA reference documents.

3. `sync-osv` and `link-osv`
   Mirror OSV data and link records to selected CVEs.

4. `discover-asf-repos` and `resolve-repos`
   Build repository manifests from curated mappings, direct references, and
   Apache GitHub inventory.

5. `clone-repos`
   Clone or update a target repo.  The active remote transport on `bobo5090`
   uses task-local Git proxying:

   ```bash
   --git-proxy http://127.0.0.1:7890
   ```

6. `discover-patches`
   Build candidate patch records from direct CVE references, OSV ranges, and
   Git history mentions.

7. `verify-patches`
   Verify that candidate commits exist locally, resolve parent commits, and
   require source-file diffs before accepting a patch.

8. `extract-samples`
   Emit paired `vulnerable` and `patched` samples.  Small contexts are included
   directly.  When selected context exceeds `--large-context-hint-threshold`,
   the sample receives a `# large-context-hint` header and `selection` metadata
   rather than attempting complex ranking.

9. `validate`
   Check required fields, label pairs, commit pairing, and minimum pair counts.

10. `audit-harness`
    Prepare or run label-blind audit prompts.  Audit output is downstream
    evaluation data and must not mutate dataset labels.

## Task Contracts

### Per-Repo Task

`run-repo-task` runs one repo through:

```text
clone -> discover-patches -> verify-patches -> extract-samples -> validate -> optional audit-harness
```

It writes one row per repo to `data/derived/repo_status.jsonl`.

Stable status values:

- `ok`
- `no_candidates`
- `no_verified_patches`
- `no_samples`
- `clone_error`
- `verify_error`
- `extract_error`
- `validate_error`
- `audit_error`

### Batch Task

`run-task-batch` reads a text file with one repo slug per line, then invokes
`run-repo-task` sequentially.  Blank lines and `#` comments are ignored.

Batch behavior:

- preserve repo order from the file
- continue after per-repo failures when `--continue-on-error` is set
- write `data/derived/task_batch_summary.json`
- keep repo-level truth in `repo_status.jsonl`
- do not add archive fallback or automatic repo selection

## Current Stabilized Results

Validated release corpus:

- 1028 samples
- 514 pre/post pairs
- 514 vulnerable labels
- 514 patched labels
- 330 unique CVEs
- 61 repositories with samples

Current construction status is captured in:

- `data/dataset/validation.json`
- `data/derived/repo_status.jsonl`
- `data/derived/task_batch_summary.json`
- `data/derived/verify_diagnostics.json`

## Known Constraints

- `discover-patches` and `verify-patches` are currently global stages, so each
  repo task can rescan all cloned repositories.  This is acceptable for
  stabilization but should be optimized before very large batches.
- Large patches can exceed 24000 characters of selected context.  The current
  policy is to add a large-context hint; programmatic context ranking is a
  future improvement.
- Archive fallback is intentionally deferred.  It would complicate commit
  verification, source extraction, and provenance semantics.
- Disk should be checked between batches.  The current repo cache is modest,
  but broad Apache coverage can grow quickly.
