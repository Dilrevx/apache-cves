# LJL Java 30 Project-Level Migrated CVE Samples

This package contains 30 Java project-level migrated TP samples. Each sample starts from a verified third-party library-level CVE PoC and injects it into a real downstream Apache project that has build-file dependency evidence for the affected library.

These are migrated/injected project-level samples, not claims that the downstream project current HEAD is natively vulnerable.

Acceptance standard:

1. the downstream repository has build-file dependency evidence for the vulnerable library;
2. the patch applies cleanly to a clean downstream project copy;
3. the PoC harness is present under `.cve_poc_local/`;
4. the local runner executes successfully after patch application;
5. the validation marker is written as `actual=1`.

Summary:

- Samples: 30
- Unique downstream repositories: 30
- Apache downstream samples: 30
- Non-Apache fallback samples: 0
- Libraries covered: 11
- CVEs covered: 11
- Full patch-after-apply validation: 30/30 passed

Primary files:

- `patches/*.patch` - project-level patch files
- `meta/INDEX.tsv` - sample index
- `meta/SUMMARY.json` - aggregate summary
- `meta/*.json` - per-sample dependency and validation metadata
- `logs/validation.jsonl` - generation-time validation records
- `logs/apply_run_all.json` - full patch-after-apply runner validation evidence
- `candidate_hits.jsonl` - scanned downstream dependency evidence candidates
- `build_java30_project_patches.py` - generator used to produce these artifacts

Full verification performed on bobo5090:

- for each of the 30 rows in `meta/INDEX.tsv`, a clean copied downstream sparse repository was used;
- the corresponding patch was applied with `git apply`;
- the runner was executed as `python3 .cve_poc_local/run_local_cve_poc.py <CVE>`;
- each sample required `apply_rc=0`, `run_rc=0`, `pass=true`, `actual="1"`, and `exit_code=0`;
- result: `checked=30`, `passed=30`, `errors=[]`.

The canonical audit evidence is `logs/apply_run_all.json`.
