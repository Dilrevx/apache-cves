# apache-cves

Function-level Apache CVE patch dataset and its provenance-first builder.

This repository contains a validated paired dataset for Apache Foundation
CVE-to-patch examples. Each accepted patch emits a `vulnerable` pre-patch sample
and a `patched` post-patch sample with source context, commit provenance, and
verification metadata.

Downloaded source repositories, raw advisory HTML, and model/audit scratch data
are intentionally not included in this release repository.

## Benchmark roadmap

This checked-in release is the current `corpus-v1` baseline, not a Gold
benchmark.  The Dataset Schema 2.0 requirements and release criteria are
tracked in `docs/apache-cve-llm-audit-benchmark-requirements.md`.

## Dataset snapshot

The current checked-in corpus is valid according to
`data/dataset/validation.json`.

- Samples: 1028
- Pre/post pairs: 514
- Vulnerable labels: 514
- Patched labels: 514
- Unique CVEs: 330
- Repositories with samples: 61
- Schema version: 1.0.0

Primary files:

- `data/dataset/samples.jsonl` - final paired vulnerable/patched contexts
- `data/dataset/validation.json` - validation report
- `data/derived/verified_patches.jsonl` - verified patch records
- `data/derived/repositories.jsonl` - repository manifest
- `data/derived/repo_status.jsonl` - per-repository pipeline status
- `data/derived/verify_diagnostics.json` - diagnostics for rejected candidates
- `build_dataset.py` - standard-library-only dataset builder

## Data flow

1. `index-cves` parses the local `CVEListV5` clone and selects Apache records
   from CNA metadata (`shortName=apache`) with an explicit vendor fallback.
2. `collect-evidence` caches Apache security advisories, `lists.apache.org`
   announcements, and Apache JIRA pages with their CVE provenance.
3. `sync-osv` mirrors the official OSV export.  A full bootstrap uses
   `all.zip`; incremental refreshes use `modified_id.csv`.
4. `link-osv` connects selected CVEs to OSV aliases and extracts Git
   `introduced` / `fixed` range events.
5. `discover-asf-repos` and `resolve-repos` build a product-to-repository
   manifest from curated aliases, direct references, and the public Apache
   GitHub organisation inventory.
6. `clone-repos`, `discover-patches`, and `verify-patches` prove candidate
   patch commits, their parent commits, and containing branches/tags.
7. `extract-samples` emits paired `vulnerable` (pre-patch) and `patched`
   (post-patch) function-level contexts.  `validate` checks the resulting
   JSONL corpus.

The builder relies only on Python's standard library and Git.  It is safe to
interrupt: stage files are atomically replaced only after a successful stage.

## Included artifacts

This repository includes the compact artifacts needed to inspect, validate, and
extend the dataset:

```text
data/
  config/                  batch input lists used during construction
  dataset/
    samples.jsonl          validated paired dataset
    validation.json        validation summary
  derived/
    apache_cves.jsonl
    osv_links.jsonl
    repositories.jsonl
    patch_candidates.jsonl
    rejected_patch_candidates.jsonl
    verified_patches.jsonl
    repo_status.jsonl
    verify_diagnostics.json
    ...
  state/                   small source snapshots/checkpoints
```

The following high-volume or environment-specific directories are excluded:

- `data/repos/` - local Git worktree clones
- `data/raw/` - cached advisory/evidence HTML
- `data/audits/` - model prompts, raw responses, and audit experiments

## Validate

```bash
python3 build_dataset.py validate --output ./data
```

Expected summary:

```json
{
  "valid": true,
  "samples": 1028,
  "pairs": 514,
  "labels": {
    "patched": 514,
    "vulnerable": 514
  }
}
```

## Remote bootstrap

```bash
python3 build_dataset.py index-cves \
  --cvelist-repo /data/lhq/workspace/route-hacker/externals/vulndb-mirror/output/cvelistv5/cvelistv5_repo \
  --output ./data

python3 build_dataset.py collect-evidence --output ./data --limit 100
python3 build_dataset.py discover-asf-repos --output ./data
python3 build_dataset.py resolve-repos --output ./data

# Full OSV bootstrap is intentionally explicit; it can be large.
python3 build_dataset.py sync-osv --output ./data --full
python3 build_dataset.py link-osv --output ./data

# Start with the verified source-URL/curated mappings. Resume as needed.
python3 build_dataset.py clone-repos --output ./data --limit 20
python3 build_dataset.py discover-patches --output ./data
python3 build_dataset.py verify-patches --output ./data
python3 build_dataset.py extract-samples --output ./data
python3 build_dataset.py validate --output ./data
```

`data/derived/unresolved_products.jsonl` is intentional output, not a silent
failure: each ambiguous product-to-repository mapping must be reviewed before
it can produce a training/evaluation example.

## Per-repository task workflow

The project is currently stabilizing the second half of the pipeline through
explicit repository tasks before enabling broad automation.

Run one repository task:

```bash
python3 build_dataset.py run-repo-task \
  --output ./data \
  --repo axis-axis1-java \
  --min-pairs 1 \
  --audit-dry-run \
  --audit-limit 1 \
  --git-proxy http://127.0.0.1:7890
```

This command is intended to run:

1. targeted mirror clone / update for the requested repo;
2. patch discovery across cloned repos;
3. patch verification against commit parents and source diffs;
4. function-level pre/post sample extraction;
5. validation with a minimum-pair gate;
6. optional label-blind audit prompt preparation.

Every task updates `data/derived/repo_status.jsonl` so interrupted or failed
runs can be inspected and resumed without relying on terminal scrollback.
Clone attempts are written to `data/derived/clone_report.jsonl`, including the
transport URL, clone mode, blob filtering, proxy, and per-source errors.

Run an explicit repo list sequentially:

```bash
python3 build_dataset.py run-task-batch \
  --output ./data \
  --repo-list data/config/manual_batch_stabilization.txt \
  --audit-dry-run \
  --audit-limit 1 \
  --git-proxy http://127.0.0.1:7890 \
  --clone-timeout 1200 \
  --continue-on-error
```

The batch runner is intentionally conservative.  It only invokes
`run-repo-task` in file order, records `data/derived/task_batch_summary.json`,
and continues after per-repo failures.  It does not enable archive fallback or
automatic repository selection.

Example stabilization batch:

```text
axis-axis1-java
cxf-fediz
incubator-openwhisk-runtime-docker
unomi
```

Large repositories such as `arrow`, `spark`, `hive`, and `openoffice` should be
scheduled after single-repo status, partial clone cleanup, and context quality
are stable.

## Batch construction

Use batches of up to 20 repositories.  Start from repositories present in
`data/derived/patch_candidates.jsonl`, skip repos already marked `ok` in
`data/derived/repo_status.jsonl`, and sort by candidate count ascending so
small, lower-risk repos run first.

Example batch:

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

After each batch, inspect:

- `data/derived/task_batch_summary.json`
- `data/derived/repo_status.jsonl`
- `data/dataset/validation.json`
- `data/derived/skipped_contexts.jsonl`
- disk usage for `/data` and `data/repos`
