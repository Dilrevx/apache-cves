# LJL Java 20 Project-Level Migrated CVE Samples

This temporary dataset extension contains 20 Java project-level migrated TP samples.
Each sample starts from a verified third-party library-level CVE PoC and injects it
into a real downstream project that depends on the affected library.

These are migrated/injected project-level samples, not claims that the downstream
project current HEAD is natively vulnerable. A sample is accepted when:

1. the downstream repository has build-file dependency evidence for the library;
2. the PoC harness is copied under `.cve_poc_local/`;
3. the local runner compiles and executes the PoC;
4. the validation marker is written as `1`;
5. the generated patch applies cleanly.

Summary:

- Samples: 20
- Apache downstream samples: 18
- Non-Apache fallback samples: 2
- Distinct downstream repositories: 10
- Source archive: `cve_poc_dataset_v2.tar.gz`
- Reference runner format: `patch.zip`
- Out of scope: `patches.zip`

Primary files:

- `patches/*.patch` - project-level patch files
- `meta/INDEX.tsv` - sample index
- `meta/SUMMARY.json` - aggregate summary
- `meta/*.json` - per-sample dependency and validation metadata
- `logs/validation.jsonl` - validation records from generation
- `build_java20_project_patches.py` - generator used to produce these artifacts

Verification performed on `bobo5090`:

- all 20 samples were marker-validated with `actual == "1"` and `pass == true`;
- all 20 patch files are non-empty and contain runner, mapping, dependency evidence,
  source PoC, and metadata files;
- `git apply --check` passed for all 20 patch files against clean copied downstream repositories;
- three representative patches were applied and executed end to end after patch application.
