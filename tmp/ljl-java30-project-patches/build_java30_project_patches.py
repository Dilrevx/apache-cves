#!/usr/bin/env python3
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(os.environ.get("LJL_ROOT", "/data/lhq/workspace/ljl-patch-java20"))
INPUT = ROOT / "input"
DATASET = INPUT
PATCH_ZIP = INPUT / "patch_zip" / "patch"
REPOS = ROOT / "repos"
WORK = ROOT / "work"
PATCHES = ROOT / "patches"
LOGS = ROOT / "logs"
META = ROOT / "meta"

RUNNER = """#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POC_ROOT = ROOT / ".cve_poc_local"
CASES = {}


def marker_candidates(cve):
    return [Path("/tmp") / f"TRIGGER_{cve}", Path("/tmp") / f"TRIGGER_{cve.replace('-', '_')}"]


def clear_markers(cve):
    for marker in marker_candidates(cve):
        try:
            marker.unlink()
        except FileNotFoundError:
            pass


def read_marker(cve):
    for marker in marker_candidates(cve):
        if marker.exists():
            return marker.read_text().strip()
    return "MISSING"


def load_cases():
    mapping = POC_ROOT / "mapping.tsv"
    if not mapping.exists():
        return
    lines = mapping.read_text().splitlines()
    if not lines:
        return
    headers = lines[0].split("\\t")
    for line in lines[1:]:
        if not line.strip():
            continue
        row = dict(zip(headers, line.split("\\t")))
        CASES[row["cve"]] = row


def run_case(cve):
    row = CASES[cve]
    case_dir = POC_ROOT / row["library"] / cve / "v1"
    clear_markers(cve)

    if (case_dir / "pom.xml").exists():
        mvn = os.environ.get("CVE_POC_MVN", "mvn")
        local_repo = Path(os.environ.get("CVE_POC_MAVEN_REPO", str(POC_ROOT / ".m2-poc")))
        local_repo.mkdir(parents=True, exist_ok=True)
        cp_file = case_dir / "target" / "classpath.txt"
        prep_cmd = [
            mvn,
            f"-Dmaven.repo.local={local_repo}",
            "-q",
            "compile",
            "org.apache.maven.plugins:maven-dependency-plugin:3.6.1:build-classpath",
            f"-Dmdep.outputFile={cp_file}",
            "-Dmdep.includeScope=runtime",
        ]
        prep = subprocess.run(prep_cmd, cwd=str(case_dir), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=420)
        if prep.returncode != 0:
            actual = read_marker(cve)
            return {
                "project": ROOT.name,
                "library": row["library"],
                "cve": cve,
                "expected": "1",
                "actual": actual,
                "pass": False,
                "exit_code": prep.returncode,
                "command": prep_cmd,
                "output": prep.stdout[-4000:],
            }
        cp = str(case_dir / "target" / "classes")
        dep_jars = []
        if cp_file.exists() and cp_file.read_text().strip():
            dep_jars = cp_file.read_text().strip().split(os.pathsep)
        if dep_jars:
            cp = cp + os.pathsep + os.pathsep.join(dep_jars)
        java = os.environ.get("CVE_POC_JAVA", "java")
        cmd = [java, "-cp", cp, "com.example.App"]
    else:
        return {"cve": cve, "pass": False, "error": "no pom.xml", "case_dir": str(case_dir)}

    try:
        proc = subprocess.run(cmd, cwd=str(case_dir), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=420)
        actual = read_marker(cve)
        return {
            "project": ROOT.name,
            "library": row["library"],
            "cve": cve,
            "expected": "1",
            "actual": actual,
            "pass": proc.returncode == 0 and actual == "1",
            "exit_code": proc.returncode,
            "command": cmd,
            "output": proc.stdout[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "project": ROOT.name,
            "library": row["library"],
            "cve": cve,
            "expected": "1",
            "actual": read_marker(cve),
            "pass": False,
            "exit_code": "TIMEOUT",
            "command": cmd,
            "output": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
        }


def main():
    if os.environ.get("CVE_POC_ENABLE") != "1":
        print(json.dumps({"enabled": False, "error": "set CVE_POC_ENABLE=1"}))
        return 2
    load_cases()
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        print(json.dumps({"enabled": True, "available": sorted(CASES)}))
        return 2
    result = run_case(sys.argv[1])
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
"""


# More than 20 are listed so the script can skip candidates whose real build
# files do not prove the downstream dependency.
CANDIDATES = [
    # CVE, source library, preferred downstream repo, maven coordinates to prove.
    ("CVE-2016-1000031", "apache-commons-fileupload", "apache/struts", "commons-fileupload", "commons-fileupload"),
    ("CVE-2023-24998", "apache-commons-fileupload", "apache/struts", "commons-fileupload", "commons-fileupload"),
    ("CVE-2021-29425", "apache-commons-io", "apache/tika", "commons-io", "commons-io"),
    ("CVE-2024-47554", "apache-commons-io", "apache/tika", "commons-io", "commons-io"),
    ("CVE-2022-42889", "apache-commons-text", "apache/jmeter", "org.apache.commons", "commons-text"),
    ("CVE-2024-31141", "apache-kafka", "apache/flink", "org.apache.kafka", "kafka-clients"),
    ("CVE-2025-27817", "apache-kafka", "apache/flink", "org.apache.kafka", "kafka-clients"),
    ("CVE-2020-13933", "apache-shiro", "apache/zeppelin", "org.apache.shiro", "shiro-core"),
    ("CVE-2022-40664", "apache-shiro", "apache/zeppelin", "org.apache.shiro", "shiro-core"),
    ("CVE-2018-11776", "apache-struts2", "apache/struts-examples", "org.apache.struts", "struts2-core"),
    ("CVE-2023-50164", "apache-struts2", "apache/struts-examples", "org.apache.struts", "struts2-core"),
    ("CVE-2021-23926", "apache-xmlbeans", "apache/tika", "org.apache.xmlbeans", "xmlbeans"),
    ("CVE-2019-12086", "jackson", "apache/camel", "com.fasterxml.jackson.core", "jackson-databind"),
    ("CVE-2020-8840", "jackson", "apache/camel", "com.fasterxml.jackson.core", "jackson-databind"),
    ("CVE-2023-26049", "jetty", "apache/hadoop", "org.eclipse.jetty", "jetty-server"),
    ("CVE-2020-9488", "log4j", "apache/flink", "org.apache.logging.log4j", "log4j-core"),
    ("CVE-2021-44228", "log4j", "apache/flink", "org.apache.logging.log4j", "log4j-core"),
    ("CVE-2021-21409", "netty", "apache/pulsar", "io.netty", "netty-codec-http2"),
    ("CVE-2026-42584", "netty", "apache/pulsar", "io.netty", "netty-codec-http"),
    ("CVE-2021-41079", "apache-tomcat", "apache/skywalking", "org.apache.tomcat.embed", "tomcat-embed-core"),
    ("CVE-2018-1000632", "dom4j", "apache/hive", "dom4j", "dom4j"),
    ("CVE-2020-10683", "dom4j", "apache/hive", "dom4j", "dom4j"),
    ("CVE-2015-7501", "apache-commons-collections", "apache/hive", "org.apache.commons", "commons-collections4"),
    ("CVE-2020-26945", "mybatis", "apache/shardingsphere", "org.mybatis", "mybatis"),
    ("CVE-2018-1272", "spring-framework", "apache/skywalking", "org.springframework", "spring-web"),
    ("CVE-2021-22060", "spring-framework", "apache/skywalking", "org.springframework", "spring-core"),
    # Non-Apache fallback candidates.
    ("CVE-2014-0114", "apache-commons-beanutils", "jenkinsci/jenkins", "commons-beanutils", "commons-beanutils"),
    ("CVE-2019-10086", "apache-commons-beanutils", "jenkinsci/jenkins", "commons-beanutils", "commons-beanutils"),
    ("CVE-2017-18349", "fastjson", "yangzongzhuan/RuoYi", "com.alibaba", "fastjson"),
    ("CVE-2022-25845", "fastjson", "yangzongzhuan/RuoYi", "com.alibaba", "fastjson"),
    ("CVE-2020-26259", "xstream", "jenkinsci/jenkins", "com.thoughtworks.xstream", "xstream"),
    ("CVE-2021-21351", "xstream", "jenkinsci/jenkins", "com.thoughtworks.xstream", "xstream"),
]


def load_candidates():
    hits_path = os.environ.get("LJL_CANDIDATE_HITS")
    if not hits_path:
        return CANDIDATES

    hits = []
    with open(hits_path) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            hits.append((
                row["cve"],
                row["library"],
                row["repo"],
                row["group"],
                row["artifact"],
            ))

    if os.environ.get("LJL_ROTATE_LIBRARIES") != "1":
        return hits

    by_repo = {}
    for candidate in hits:
        by_repo.setdefault(candidate[2], []).append(candidate)

    library_order = [
        "apache-commons-io",
        "jackson",
        "log4j",
        "apache-commons-collections",
        "apache-commons-beanutils",
        "jetty",
        "dom4j",
        "apache-shiro",
        "apache-commons-fileupload",
        "netty",
        "apache-xmlbeans",
    ]
    selected = []
    used = set()
    made_progress = True
    while made_progress:
        made_progress = False
        for lib in library_order:
            for repo in sorted(by_repo):
                if repo in used:
                    continue
                match = next((c for c in by_repo[repo] if c[1] == lib), None)
                if match:
                    selected.append(match)
                    used.add(repo)
                    made_progress = True
                    break
    for repo in sorted(by_repo):
        if repo not in used:
            selected.append(by_repo[repo][0])
            used.add(repo)
    return selected


def run(cmd, cwd=None, timeout=900, check=True, env=None):
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout[-4000:]}")
    return proc


def repo_slug(repo):
    return repo.replace("/", "__")


def sparse_clone(repo):
    target = REPOS / repo_slug(repo)
    if (target / ".git").exists():
        return target
    if target.exists():
        shutil.rmtree(target)
    url = f"https://github.com/{repo}.git"
    run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", url, str(target)], timeout=900)
    run(["git", "sparse-checkout", "set", "--no-cone", "**/pom.xml", "**/*.gradle", "**/*.gradle.kts", "**/build.gradle", "**/build.gradle.kts"], cwd=target)
    return target


def build_files(repo_dir):
    names = []
    for pattern in ("**/pom.xml", "**/*.gradle", "**/*.gradle.kts"):
        names.extend(repo_dir.glob(pattern))
    return [p for p in names if ".git" not in p.parts]


def find_dependency_evidence(repo_dir, group, artifact):
    evidence = []
    needles = [artifact]
    if group:
        needles.append(group)
    for file in build_files(repo_dir):
        try:
            lines = file.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if artifact in line or (group and group in line):
                window = "\n".join(lines[max(0, i - 4): min(len(lines), i + 4)])
                if artifact in window and (not group or group in window):
                    evidence.append({
                        "file": str(file.relative_to(repo_dir)),
                        "line": i,
                        "snippet": window.strip()[:1200],
                    })
                    if len(evidence) >= 3:
                        return evidence
    return evidence


def read_manifest(cve_lib, cve):
    path = DATASET / cve_lib / cve / "manifest.json"
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text())


def copy_case(dest_root, library, cve):
    src = DATASET / library / cve
    if not (src / "v1" / "pom.xml").exists():
        raise FileNotFoundError(src / "v1" / "pom.xml")
    case_root = dest_root / ".cve_poc_local" / library / cve
    if case_root.exists():
        shutil.rmtree(case_root)
    ignore = shutil.ignore_patterns("target", "*.class", ".DS_Store", "._*")
    shutil.copytree(src / "v1", case_root / "v1", ignore=ignore)
    for name in ("manifest.json", "vuln_description.json", "_brief.md", "_build_summary.json"):
        if (src / name).exists():
            shutil.copy2(src / name, case_root / name)


def write_local_files(work_dir, row):
    local = work_dir / ".cve_poc_local"
    local.mkdir(parents=True, exist_ok=True)
    (local / "run_local_cve_poc.py").write_text(RUNNER)
    os.chmod(local / "run_local_cve_poc.py", 0o755)
    with (local / "mapping.tsv").open("w") as f:
        f.write("project\trepo\tcve\tlanguage\tlibrary\tsource_case\n")
        f.write("\t".join([row["project"], row["repo"], row["cve"], "java", row["library"], row["source_case"]]) + "\n")
    (local / "downstream_evidence.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")


def make_patch(work_dir, patch_path):
    files = [
        str(path.relative_to(work_dir))
        for path in sorted((work_dir / ".cve_poc_local").rglob("*"))
        if path.is_file() and "target" not in path.parts and ".m2-poc" not in path.parts
    ]
    if files:
        proc = subprocess.run(
            ["git", "add", "--sparse", "-N", "-f", "--pathspec-from-file=-", "--pathspec-file-nul"],
            cwd=str(work_dir),
            input=("\0".join(files) + "\0").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git add intent failed ({proc.returncode}): {proc.stdout[-4000:]}")
    proc = subprocess.run(
        ["git", "diff", "--binary", "--", ".cve_poc_local"],
        cwd=str(work_dir),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    patch_path.write_text(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed ({proc.returncode}): {proc.stderr[-4000:]}")
    if not proc.stdout.strip():
        raise RuntimeError(f"empty patch: {patch_path}")


def validate(work_dir, cve):
    env = os.environ.copy()
    env["CVE_POC_ENABLE"] = "1"
    env.setdefault("CVE_POC_MAVEN_REPO", str(ROOT / ".m2-poc"))
    return run(["python3", ".cve_poc_local/run_local_cve_poc.py", cve], cwd=work_dir, timeout=520, check=False, env=env)


def main():
    for d in (REPOS, WORK, PATCHES, LOGS, META):
        d.mkdir(parents=True, exist_ok=True)
    for pattern_root, pattern in ((PATCHES, "*.patch"), (META, "*.json"), (LOGS, "*.failed.log")):
        for path in pattern_root.glob(pattern):
            path.unlink()

    selected = []
    selected_repos = set()
    limit = int(os.environ.get("LJL_LIMIT", "20"))
    validation_path = LOGS / "validation.jsonl"
    index_path = META / "INDEX.tsv"
    if validation_path.exists():
        validation_path.unlink()
    if index_path.exists():
        index_path.unlink()

    for cve, library, repo, group, artifact in load_candidates():
        if len(selected) >= limit:
            break
        if os.environ.get("LJL_UNIQUE_REPOS") == "1" and repo in selected_repos:
            continue
        try:
            manifest = read_manifest(library, cve)
            if manifest.get("language") != "java":
                continue
            repo_dir = sparse_clone(repo)
            evidence = find_dependency_evidence(repo_dir, group, artifact)
            if not evidence:
                print(f"SKIP no dependency evidence: {cve} {library} -> {repo} {group}:{artifact}")
                continue

            sample_id = f"{cve}__{repo_slug(repo)}"
            work_dir = WORK / sample_id
            if work_dir.exists():
                shutil.rmtree(work_dir)
            shutil.copytree(repo_dir, work_dir, ignore=shutil.ignore_patterns(".git/objects/pack/*.pack"))
            if not (work_dir / ".git").exists():
                shutil.rmtree(work_dir)
                run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", f"https://github.com/{repo}.git", str(work_dir)], timeout=900)
                run(["git", "sparse-checkout", "set", "--no-cone", "**/pom.xml", "**/*.gradle", "**/*.gradle.kts"], cwd=work_dir)

            row = {
                "sample_id": sample_id,
                "project": repo.split("/")[-1],
                "repo": repo,
                "repo_url": f"https://github.com/{repo}",
                "cve": cve,
                "library": library,
                "source_case": f"{library}/{cve}",
                "dependency_group": group,
                "dependency_artifact": artifact,
                "dependency_evidence": evidence,
                "carrier_kind": "apache_downstream" if repo.startswith("apache/") else "non_apache_downstream",
            }
            copy_case(work_dir, library, cve)
            write_local_files(work_dir, row)

            validation = validate(work_dir, cve)
            try:
                parsed = json.loads(validation.stdout.strip().splitlines()[-1])
            except Exception:
                parsed = {"pass": False, "parse_error": True, "raw": validation.stdout[-4000:]}
            row["validation"] = parsed
            row["validation_exit"] = validation.returncode
            with validation_path.open("a") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
            if not parsed.get("pass"):
                print(f"SKIP validation failed: {sample_id} exit={validation.returncode}")
                (LOGS / f"{sample_id}.failed.log").write_text(validation.stdout)
                continue

            patch_path = PATCHES / f"{sample_id}.patch"
            make_patch(work_dir, patch_path)
            row["patch_file"] = str(patch_path.relative_to(ROOT))
            (META / f"{sample_id}.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
            selected.append(row)
            selected_repos.add(repo)
            print(f"OK {len(selected):02d}: {sample_id} -> {patch_path.name}")
        except Exception as exc:
            print(f"ERROR {cve} {library} -> {repo}: {exc}")
            continue

    with index_path.open("w") as f:
        headers = ["sample_id", "patch_file", "cve", "library", "repo", "carrier_kind", "dependency_group", "dependency_artifact", "source_case", "validated"]
        f.write("\t".join(headers) + "\n")
        for row in selected:
            f.write("\t".join([
                row["sample_id"],
                row.get("patch_file", ""),
                row["cve"],
                row["library"],
                row["repo"],
                row["carrier_kind"],
                row["dependency_group"],
                row["dependency_artifact"],
                row["source_case"],
                str(bool(row.get("validation", {}).get("pass"))),
            ]) + "\n")

    summary = {
        "requested": limit,
        "selected": len(selected),
        "unique_repositories": len({r["repo"] for r in selected}),
        "apache_downstream": sum(1 for r in selected if r["carrier_kind"] == "apache_downstream"),
        "non_apache_downstream": sum(1 for r in selected if r["carrier_kind"] != "apache_downstream"),
        "index": str(index_path),
        "patches": str(PATCHES),
        "validation_log": str(validation_path),
    }
    (META / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if len(selected) >= limit else 1


if __name__ == "__main__":
    raise SystemExit(main())
