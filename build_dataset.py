#!/usr/bin/env python3
"""Build a provenance-preserving Apache CVE-to-patch dataset.

The program is purposefully dependency-free so it can run on the remote host
without changing the existing vulndb-mirror environment.  Every command is
resumable and produces JSONL that can be inspected independently.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import html
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional


SCHEMA_VERSION = "1.0.0"
USER_AGENT = "apache-vuln-dataset/1.0 (research dataset builder)"
OSV_BUCKET = "https://storage.googleapis.com/osv-vulnerabilities"
SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".java", ".kt", ".kts", ".py", ".go", ".rs", ".js", ".jsx",
    ".ts", ".tsx", ".rb", ".php", ".cs", ".scala", ".groovy",
    ".sh", ".pl", ".pm", ".swift", ".m", ".mm",
}
NON_SOURCE_PREFIXES = ("docs/", "site/", ".github/", ".gitignore")
GITHUB_APACHE_RE = re.compile(
    r"https?://github\.com/apache/([^/\s?#]+)(?:/(commit|pull|issues)/([^/?#\s]+))?",
    re.IGNORECASE,
)
GITBOX_RE = re.compile(
    r"https?://gitbox\.apache\.org/repos/asf/([^/\s?#]+?)(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"\b[0-9a-f]{7,64}\b", re.IGNORECASE)


# Curated aliases use Apache GitBox repository names.  Entries are treated as
# high-confidence mappings, but patches are not marked verified until Git
# proves the commit and parent relationship.
CURATED_REPO_MAP = {
    "ats": "trafficserver",
    "age": "age",
    "accumulo": "accumulo",
    "http server": "httpd",
    "httpd": "httpd",
    "tomcat": "tomcat",
    "airflow": "airflow",
    "superset": "superset",
    "traffic server": "trafficserver",
    "ofbiz": "ofbiz-framework",
    "camel": "camel",
    "nifi": "nifi",
    "cxf": "cxf",
    "activemq": "activemq",
    "activemq all": "activemq",
    "activemq broker": "activemq",
    "activemq artemis": "activemq-artemis",
    "cloudstack": "cloudstack",
    "dolphinscheduler": "dolphinscheduler",
    "inlong": "inlong",
    "openoffice": "openoffice",
    "solr": "solr",
    "struts": "struts",
    "apisix": "apisix",
    "apisix dashboard": "apisix-dashboard",
    "apisix java plugin runner": "apisix-java-plugin-runner",
    "openmeetings": "openmeetings",
    "zeppelin": "zeppelin",
    "answer": "answer",
    "hadoop": "hadoop",
    "dubbo": "dubbo",
    "kylin": "kylin",
    "pulsar": "pulsar",
    "shiro": "shiro",
    "hive": "hive",
    "spark": "spark",
    "thrift": "thrift",
    "ranger": "ranger",
    "tika": "tika",
    "syncope": "syncope",
    "atlas": "atlas",
    "druid": "druid",
    "kafka": "kafka",
    "ozone": "ozone",
    "cassandra": "cassandra",
    "couchdb": "couchdb",
    "wicket": "wicket",
    "kvrocks": "kvrocks",
    "zookeeper": "zookeeper",
    "archiva": "archiva",
    "guacamole client": "guacamole-client",
    "karaf": "karaf",
    "linkis": "linkis",
    "mina": "mina",
    "subversion": "subversion",
    "james": "james-project",
    "sling": "sling-org-apache-sling-engine",
    "storm": "storm",
    "streampipes": "streampipes",
    "impala": "impala",
    "jena": "jena",
    "pdfbox": "pdfbox",
    "qpid broker j": "qpid-broker-j",
    "roller": "roller",
    "spamassassin": "spamassassin",
    "traffic control": "trafficcontrol",
    "allura": "allura",
    "ignite": "ignite",
    "mesos": "mesos",
    "nimble": "nimble",
    "tapestry": "tapestry-5",
    "commons compress": "commons-compress",
    "commons configuration": "commons-configuration",
    "commons fileupload": "commons-fileupload",
    "commons collections": "commons-collections",
    "commons io": "commons-io",
    "commons text": "commons-text",
    "commons lang": "commons-lang",
    "commons beanutils": "commons-beanutils",
    "commons codec": "commons-codec",
    "commons jexl": "commons-jexl",
    "commons dbcp": "commons-dbcp",
    "commons net": "commons-net",
    "commons validator": "commons-validator",
    "maven": "maven",
    "ant": "ant",
    "flink": "flink",
    "iotdb": "iotdb",
    "seatunnel": "seatunnel",
    "rocketmq": "rocketmq",
    "hertzbeat": "hertzbeat",
    "streampark": "incubator-streampark",
    "seatunnel": "seatunnel",
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalise_product(name: str) -> str:
    value = re.sub(r"\bapache\b", "", name, flags=re.IGNORECASE)
    value = re.sub(r"\([^)]*\)", " ", value)
    value = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return " ".join(value.split())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temp.replace(path)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    count = 0
    with temp.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    temp.replace(path)
    return count


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required stage output is missing: {path}")
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at {path}:{line_no}") from exc


def git_env(proxy: Optional[str] = None) -> Optional[dict[str, str]]:
    if not proxy:
        return None
    env = os.environ.copy()
    env.update({
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "http_proxy": proxy,
        "https_proxy": proxy,
    })
    return env


def git_command(args: list[str], *, proxy: Optional[str] = None, connect_timeout: Optional[int] = None) -> list[str]:
    command = ["git"]
    if proxy:
        command.extend(["-c", f"http.proxy={proxy}", "-c", f"https.proxy={proxy}"])
    if connect_timeout:
        command.extend(["-c", f"http.connectTimeout={connect_timeout}"])
    command.extend(args)
    return command


def run_git(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = True,
    proxy: Optional[str] = None,
    connect_timeout: Optional[int] = None,
) -> str:
    result = subprocess.run(
        git_command(args, proxy=proxy, connect_timeout=connect_timeout),
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_env(proxy),
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def run_git_with_timeout(
    args: list[str],
    *,
    timeout: Optional[int] = None,
    cwd: Optional[Path] = None,
    proxy: Optional[str] = None,
    connect_timeout: Optional[int] = None,
) -> str:
    try:
        result = subprocess.run(
            git_command(args, proxy=proxy, connect_timeout=connect_timeout),
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=git_env(proxy),
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git {' '.join(args)} timed out after {timeout}s") from exc
    if result.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def is_source_path(path: str) -> bool:
    low = path.lower()
    return (
        not low.startswith(NON_SOURCE_PREFIXES)
        and Path(low).suffix in SOURCE_EXTENSIONS
    )


def classify_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host == "lists.apache.org":
        return "apache_list"
    if host == "issues.apache.org" and "/jira" in path:
        return "apache_jira"
    if host.endswith(".apache.org") and ("security" in path or "vulnerab" in path):
        return "apache_security"
    if host == "github.com" and path.lower().startswith("/apache/"):
        return "github_apache"
    if host == "gitbox.apache.org":
        return "apache_gitbox"
    return "other"


def cna_records(data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    meta = data.get("cveMetadata") or {}
    return cna, meta


def apache_selection_reasons(data: dict[str, Any]) -> list[str]:
    cna, meta = cna_records(data)
    reasons: list[str] = []
    provider = (cna.get("providerMetadata") or {}).get("shortName", "")
    assigner = meta.get("assignerShortName", "")
    if str(provider).lower() == "apache":
        reasons.append("cna_provider_short_name")
    if str(assigner).lower() == "apache":
        reasons.append("cve_assigner_short_name")
    for affected in cna.get("affected") or []:
        vendor = str(affected.get("vendor", "")).strip().lower()
        if vendor == "apache software foundation":
            reasons.append("affected_vendor")
            break
    return reasons


def extract_description(cna: dict[str, Any]) -> str:
    for item in cna.get("descriptions") or []:
        if item.get("lang") in ("en", None) and item.get("value"):
            return str(item["value"]).strip()
    return ""


def extract_cwes(cna: dict[str, Any]) -> list[str]:
    result = []
    for block in cna.get("problemTypes") or []:
        for entry in block.get("descriptions") or []:
            cwe = entry.get("cweId")
            if cwe:
                result.append(str(cwe))
    return sorted(set(result))


def extract_affected(cna: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in cna.get("affected") or []:
        result.append({
            "vendor": str(item.get("vendor") or ""),
            "product": str(item.get("product") or ""),
            "default_status": item.get("defaultStatus"),
            "versions": item.get("versions") or [],
        })
    return result


def extract_references(cna: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for item in cna.get("references") or []:
        url = str(item.get("url") or "").strip()
        if url:
            refs.append({
                "url": url,
                "name": str(item.get("name") or ""),
                "tags": sorted(str(tag) for tag in (item.get("tags") or [])),
                "kind": classify_url(url),
            })
    return refs


def cmd_index_cves(args: argparse.Namespace) -> None:
    source = Path(args.cvelist_repo).expanduser().resolve()
    root = Path(args.output).expanduser().resolve()
    cves_dir = source / "cves"
    if not cves_dir.is_dir():
        raise FileNotFoundError(f"CVEListV5 cves directory not found: {cves_dir}")
    source_commit = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    selected: list[dict[str, Any]] = []
    rejected = 0
    for path in sorted(cves_dir.rglob("CVE-*.json")):
        try:
            raw = read_json(path)
        except (OSError, json.JSONDecodeError):
            rejected += 1
            continue
        reasons = apache_selection_reasons(raw)
        if not reasons:
            continue
        cna, meta = cna_records(raw)
        cve_id = str(meta.get("cveId") or path.stem)
        if meta.get("state") != "PUBLISHED":
            continue
        selected.append({
            "schema_version": SCHEMA_VERSION,
            "cve_id": cve_id,
            "title": str(cna.get("title") or cve_id),
            "description": extract_description(cna),
            "cwe_ids": extract_cwes(cna),
            "published": meta.get("datePublished"),
            "modified": meta.get("dateUpdated"),
            "selection_reasons": reasons,
            "cna": {
                "provider_metadata": cna.get("providerMetadata") or {},
                "assigner_short_name": meta.get("assignerShortName"),
            },
            "affected": extract_affected(cna),
            "references": extract_references(cna),
            "source": {
                "cvelist_commit": source_commit,
                "record_path": str(path.relative_to(source)),
                "record_sha256": sha256_file(path),
            },
        })
    selected.sort(key=lambda row: row["cve_id"])
    count = write_jsonl(root / "derived" / "apache_cves.jsonl", selected)
    products = Counter(
        affected["product"]
        for row in selected for affected in row["affected"]
        if affected.get("product")
    )
    write_json(root / "derived" / "apache_cve_index_stats.json", {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "source_repo": str(source),
        "source_commit": source_commit,
        "apache_published_cves": count,
        "unreadable_source_records": rejected,
        "top_products": products.most_common(),
    })
    print(json.dumps({"apache_published_cves": count, "source_commit": source_commit}))


class EvidenceTextExtractor(HTMLParser):
    """Minimal, dependency-free HTML-to-text extraction for evidence pages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
        elif tag in {"p", "br", "li", "tr", "div", "h1", "h2", "h3", "h4", "pre"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)

    def text(self) -> str:
        value = html.unescape("".join(self.parts))
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()


def evidence_file_stem(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def html_to_text(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    parser = EvidenceTextExtractor()
    try:
        parser.feed(decoded)
        parser.close()
        return parser.text()
    except Exception:
        return decoded


def cmd_collect_evidence(args: argparse.Namespace) -> None:
    """Cache official Apache advisory, list, and JIRA documents with provenance."""
    root = Path(args.output).expanduser().resolve()
    selected_kinds = set(args.kinds)
    urls: dict[str, dict[str, Any]] = {}
    for cve in read_jsonl(root / "derived" / "apache_cves.jsonl"):
        for reference in cve.get("references") or []:
            if reference.get("kind") not in selected_kinds:
                continue
            row = urls.setdefault(reference["url"], {
                "url": reference["url"],
                "kind": reference["kind"],
                "cves": set(),
                "reference_names": set(),
            })
            row["cves"].add(cve["cve_id"])
            if reference.get("name"):
                row["reference_names"].add(reference["name"])

    evidence_path = root / "derived" / "evidence.jsonl"
    existing = {row["url"]: row for row in read_jsonl(evidence_path)} if evidence_path.exists() else {}
    raw_dir = root / "raw" / "evidence"
    text_dir = raw_dir / "text"
    rows = list(existing.values())
    pending = [item for _, item in sorted(urls.items()) if item["url"] not in existing or existing[item["url"]].get("status") != "ok"]
    if args.limit:
        pending = pending[:args.limit]
    for index, item in enumerate(pending, 1):
        url = item["url"]
        record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "url": url,
            "kind": item["kind"],
            "cves": sorted(item["cves"]),
            "reference_names": sorted(item["reference_names"]),
            "fetched_at": now_iso(),
        }
        stem = evidence_file_stem(url)
        try:
            raw = fetch_bytes(url, retries=args.retries)
            raw_dir.mkdir(parents=True, exist_ok=True)
            text_dir.mkdir(parents=True, exist_ok=True)
            raw_path = raw_dir / f"{stem}.html"
            text_path = text_dir / f"{stem}.txt"
            raw_path.write_bytes(raw)
            text = html_to_text(raw)
            text_path.write_text(text + "\n", encoding="utf-8")
            record.update({
                "status": "ok",
                "raw_path": str(raw_path.relative_to(root)),
                "text_path": str(text_path.relative_to(root)),
                "content_sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            })
        except Exception as exc:
            record.update({"status": "error", "error": str(exc)})
        existing[url] = record
        print(f"[{index}/{len(pending)}] {item['kind']} {record['status']} {url}", file=sys.stderr)
    # Refresh CVE associations for previously fetched shared documents.
    for url, item in urls.items():
        if url in existing:
            existing[url]["cves"] = sorted(item["cves"])
            existing[url]["reference_names"] = sorted(item["reference_names"])
    rows = sorted(existing.values(), key=lambda row: row["url"])
    write_jsonl(evidence_path, rows)
    print(json.dumps({
        "documents": len(rows), "fetched_this_run": len(pending),
        "ok": sum(row.get("status") == "ok" for row in rows),
        "errors": sum(row.get("status") == "error" for row in rows),
    }))


def http_open(url: str, *, timeout: int = 60) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=timeout)


RETRYABLE_NETWORK_ERRORS = (
    urllib.error.URLError,
    http.client.IncompleteRead,
    TimeoutError,
    OSError,
)


def fetch_bytes(url: str, *, retries: int = 4) -> bytes:
    """Read a small HTTP response with retry/backoff for flaky connections."""
    for attempt in range(retries):
        try:
            with http_open(url) as response:
                return response.read()
        except RETRYABLE_NETWORK_ERRORS as exc:
            if attempt + 1 == retries:
                raise RuntimeError(f"request failed for {url}: {exc}") from exc
            time.sleep(2 ** attempt)
    raise AssertionError("network retry loop unexpectedly exhausted")


def download(url: str, destination: Path, *, retries: int = 4) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    for attempt in range(retries):
        try:
            with http_open(url) as response, partial.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            partial.replace(destination)
            return
        except RETRYABLE_NETWORK_ERRORS as exc:
            if attempt + 1 == retries:
                raise RuntimeError(f"download failed for {url}: {exc}") from exc
            time.sleep(2 ** attempt)


def safe_extract_json(zip_path: Path, destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            member = Path(info.filename)
            if info.is_dir() or member.suffix.lower() != ".json":
                continue
            target = (destination / member).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError(f"unsafe zip member: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            count += 1
    return count


def cmd_sync_osv(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    raw = root / "raw" / "osv"
    records = raw / "records"
    state_path = root / "state" / "osv_state.json"
    if args.full:
        zip_path = raw / "all.zip"
        print(f"downloading {OSV_BUCKET}/all.zip")
        download(f"{OSV_BUCKET}/all.zip", zip_path)
        count = safe_extract_json(zip_path, records)
        write_json(state_path, {
            "schema_version": SCHEMA_VERSION,
            "mode": "full",
            "synced_at": now_iso(),
            "archive": str(zip_path),
            "archive_sha256": sha256_file(zip_path),
            "extracted_records": count,
        })
        print(json.dumps({"mode": "full", "extracted_records": count}))
        return

    previous = read_json(state_path) if state_path.exists() else {}
    since = args.since or previous.get("synced_at")
    if not since:
        raise ValueError("incremental OSV sync needs --since or an existing full/incremental state")
    changed = 0
    downloaded = 0
    text = fetch_bytes(f"{OSV_BUCKET}/modified_id.csv").decode("utf-8")
    for modified, item_path in csv.reader(text.splitlines()):
        if modified <= since:
            break
        changed += 1
        relative = Path(item_path)
        if relative.suffix.lower() != ".json":
            relative = relative.with_suffix(".json")
        destination = records / relative
        url = f"{OSV_BUCKET}/{urllib.parse.quote(relative.as_posix(), safe='/')}"
        download(url, destination)
        downloaded += 1
        if args.limit and downloaded >= args.limit:
            break
    write_json(state_path, {
        "schema_version": SCHEMA_VERSION,
        "mode": "incremental",
        "synced_at": now_iso(),
        "previous_sync": since,
        "listed_changes": changed,
        "downloaded_records": downloaded,
    })
    print(json.dumps({"mode": "incremental", "downloaded_records": downloaded}))


def git_events(affected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    extracted = []
    for entry in affected:
        package = entry.get("package") or {}
        for range_data in entry.get("ranges") or []:
            if str(range_data.get("type", "")).upper() != "GIT":
                continue
            repo_url = str(range_data.get("repo") or "")
            events = range_data.get("events") or []
            last_introduced: Optional[str] = None
            for event in events:
                if event.get("introduced"):
                    last_introduced = str(event["introduced"])
                if event.get("fixed"):
                    extracted.append({
                        "repo_url": repo_url,
                        "introduced": last_introduced,
                        "fixed": str(event["fixed"]),
                        "package": package,
                    })
                    last_introduced = None
    return extracted


def cmd_link_osv(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    selected = {row["cve_id"]: row for row in read_jsonl(root / "derived" / "apache_cves.jsonl")}
    records = root / "raw" / "osv" / "records"
    if not records.is_dir():
        raise FileNotFoundError("OSV records missing; run sync-osv --full first")
    links: list[dict[str, Any]] = []
    processed = 0
    for path in sorted(records.rglob("*.json")):
        try:
            raw = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        processed += 1
        aliases = {str(value).upper() for value in (raw.get("aliases") or [])}
        record_id = str(raw.get("id") or "")
        if record_id.upper().startswith("CVE-"):
            aliases.add(record_id.upper())
        matching = sorted(aliases.intersection(selected))
        if not matching:
            continue
        ranges = git_events(raw.get("affected") or [])
        for cve_id in matching:
            links.append({
                "schema_version": SCHEMA_VERSION,
                "cve_id": cve_id,
                "osv_id": record_id,
                "aliases": sorted(aliases),
                "summary": raw.get("summary") or "",
                "modified": raw.get("modified"),
                "references": raw.get("references") or [],
                "git_ranges": ranges,
                "source": {
                    "record_path": str(path.relative_to(root)),
                    "record_sha256": sha256_file(path),
                },
            })
    links.sort(key=lambda row: (row["cve_id"], row["osv_id"]))
    count = write_jsonl(root / "derived" / "osv_links.jsonl", links)
    write_json(root / "derived" / "osv_link_stats.json", {
        "generated_at": now_iso(),
        "osv_records_processed": processed,
        "linked_records": count,
        "linked_cves": len({row["cve_id"] for row in links}),
        "git_range_events": sum(len(row["git_ranges"]) for row in links),
    })
    print(json.dumps({"linked_records": count, "git_range_events": sum(len(row["git_ranges"]) for row in links)}))


def github_api_repos() -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    page = 1
    # This deliberately stays below the response size that has proven stable
    # on the remote link.  Apache has only a few hundred repositories, so the
    # extra requests remain well below GitHub's unauthenticated API limit.
    page_size = 20
    while True:
        url = f"https://api.github.com/orgs/apache/repos?type=all&per_page={page_size}&page={page}"
        rows = json.loads(fetch_bytes(url).decode("utf-8"))
        if not isinstance(rows, list):
            raise RuntimeError("unexpected GitHub Apache org API response")
        repos.extend(rows)
        if len(rows) < page_size:
            break
        page += 1
    return repos


def cmd_discover_asf_repos(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    rows = github_api_repos()
    repos = []
    for item in rows:
        name = str(item.get("name") or "")
        if not name:
            continue
        repos.append({
            "name": name,
            "normalised_name": normalise_product(name),
            "github_url": str(item.get("clone_url") or f"https://github.com/apache/{name}.git"),
            "gitbox_url": f"https://gitbox.apache.org/repos/asf/{name}.git",
            "archived": bool(item.get("archived")),
            "default_branch": item.get("default_branch"),
        })
    repos.sort(key=lambda row: row["name"])
    write_json(root / "state" / "apache_github_repos.json", {
        "generated_at": now_iso(), "repos": repos,
    })
    print(json.dumps({"apache_github_repos": len(repos)}))


def slug_from_url(url: str) -> Optional[str]:
    match = GITHUB_APACHE_RE.search(url)
    if match:
        return match.group(1).removesuffix(".git")
    match = GITBOX_RE.search(url)
    if match:
        return match.group(1).removesuffix(".git")
    return None


def cve_direct_repo_refs(cve: dict[str, Any]) -> list[dict[str, Any]]:
    return direct_repo_refs_from_urls(
        [str(ref["url"]) for ref in (cve.get("references") or [])],
        source_method="cve_direct_reference",
    )


def direct_repo_refs_from_urls(urls: Iterable[str], *, source_method: str) -> list[dict[str, Any]]:
    refs = []
    for url in urls:
        match = GITHUB_APACHE_RE.search(url)
        if match:
            refs.append({
                "repo": match.group(1).removesuffix(".git"),
                "commit": match.group(3) if match.group(2) == "commit" else None,
                "url": url,
                "method": source_method,
            })
        else:
            slug = slug_from_url(url)
            if slug:
                refs.append({"repo": slug, "commit": None, "url": url, "method": source_method})
    return refs


def evidence_repo_refs(root: Path) -> dict[str, list[dict[str, Any]]]:
    """Extract Apache repo and commit links embedded in cached source pages."""
    evidence_path = root / "derived" / "evidence.jsonl"
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not evidence_path.exists():
        return by_cve
    for document in read_jsonl(evidence_path):
        if document.get("status") != "ok" or not document.get("raw_path"):
            continue
        raw_path = root / document["raw_path"]
        try:
            content = raw_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        urls = [document["url"], *[match.group(0) for match in GITHUB_APACHE_RE.finditer(content)]]
        refs = direct_repo_refs_from_urls(urls, source_method="apache_evidence_reference")
        for cve_id in document.get("cves") or []:
            by_cve[cve_id].extend(refs)
    return by_cve


def best_fuzzy_repo(product: str, inventory: list[dict[str, Any]]) -> tuple[Optional[str], float]:
    target = normalise_product(product)
    if not target:
        return None, 0.0
    best_name: Optional[str] = None
    best_score = 0.0
    for repo in inventory:
        score = SequenceMatcher(None, target, repo["normalised_name"]).ratio()
        if target in repo["normalised_name"] or repo["normalised_name"] in target:
            score = max(score, 0.86)
        if score > best_score:
            best_name, best_score = repo["name"], score
    return best_name, best_score


def curated_repo_for_product(product: str) -> Optional[str]:
    """Resolve an exact product, then a known parent-project subcomponent.

    Apache advisories frequently name a module (for example, an Airflow
    provider) while the security fix lives in the project's monorepo.  Match
    the most specific alias first so dedicated repositories such as
    ``apisix-dashboard`` remain distinct from their parent project.
    """
    target = normalise_product(product)
    for alias in sorted(CURATED_REPO_MAP, key=len, reverse=True):
        if target == alias or target.startswith(alias + " "):
            return CURATED_REPO_MAP[alias]
    return None


def is_asf_affected_vendor(vendor: Any) -> bool:
    return "apache" in str(vendor or "").lower()


def cmd_resolve_repos(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    cves = list(read_jsonl(root / "derived" / "apache_cves.jsonl"))
    state_path = root / "state" / "apache_github_repos.json"
    inventory = (read_json(state_path).get("repos", []) if state_path.exists() else [])
    evidence_refs = evidence_repo_refs(root)
    by_slug: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []
    for cve in cves:
        candidate_sources: list[dict[str, Any]] = []
        for direct in cve_direct_repo_refs(cve):
            candidate_sources.append({
                "repo": direct["repo"], "confidence": "high", "method": direct["method"],
                "source_url": direct["url"], "commit": direct.get("commit"),
            })
        for direct in evidence_refs.get(cve["cve_id"], []):
            candidate_sources.append({
                "repo": direct["repo"], "confidence": "high", "method": direct["method"],
                "source_url": direct["url"], "commit": direct.get("commit"),
            })
        for affected in cve["affected"]:
            product = affected.get("product", "")
            normalised = normalise_product(product)
            # CVEs assigned by Apache can list a non-ASF downstream dependency.
            # Those components must not cause unrelated repositories to be
            # cloned merely because the CNA happens to be Apache.
            if not is_asf_affected_vendor(affected.get("vendor")):
                continue
            curated = curated_repo_for_product(product)
            if curated:
                candidate_sources.append({
                    "repo": curated, "confidence": "high", "method": "curated_product_map",
                    "source_url": None, "product": product,
                })
                continue
            best, score = best_fuzzy_repo(product, inventory)
            if best and score >= args.fuzzy_threshold:
                candidate_sources.append({
                    "repo": best, "confidence": "candidate", "method": "github_org_fuzzy_match",
                    "source_url": None, "product": product, "score": round(score, 4),
                })
            elif product:
                unresolved.append({
                    "cve_id": cve["cve_id"], "product": product, "vendor": affected.get("vendor"),
                    "normalised_product": normalised,
                })
        for item in candidate_sources:
            slug = item["repo"]
            row = by_slug.setdefault(slug, {
                "schema_version": SCHEMA_VERSION,
                "repo": slug,
                "gitbox_url": f"https://gitbox.apache.org/repos/asf/{slug}.git",
                "github_url": f"https://github.com/apache/{slug}.git",
                "confidence": item["confidence"],
                "mapping_evidence": [],
                "cves": set(),
                "direct_commit_refs": [],
            })
            if item["confidence"] == "high":
                row["confidence"] = "high"
            row["cves"].add(cve["cve_id"])
            row["mapping_evidence"].append({key: value for key, value in item.items() if key != "commit"})
            if item.get("commit"):
                row["direct_commit_refs"].append({
                    "cve_id": cve["cve_id"], "commit": item["commit"], "url": item.get("source_url"),
                })
    manifests = []
    for slug, row in by_slug.items():
        row["cves"] = sorted(row["cves"])
        deduplicated_evidence = {json.dumps(item, sort_keys=True): item for item in row["mapping_evidence"]}
        row["mapping_evidence"] = [deduplicated_evidence[key] for key in sorted(deduplicated_evidence)]
        deduplicated_commits = {(item["cve_id"], item["commit"], item.get("url")): item for item in row["direct_commit_refs"]}
        row["direct_commit_refs"] = [deduplicated_commits[key] for key in sorted(deduplicated_commits)]
        manifests.append(row)
    manifests.sort(key=lambda row: row["repo"])
    write_jsonl(root / "derived" / "repositories.jsonl", manifests)
    unique_unresolved = {(r["product"], r.get("vendor")): r for r in unresolved}
    write_jsonl(root / "derived" / "unresolved_products.jsonl", sorted(unique_unresolved.values(), key=lambda r: (r["product"], r["cve_id"])))
    print(json.dumps({"repositories": len(manifests), "unresolved_products": len(unique_unresolved)}))


def manifest_row(slug: str, *, confidence: str = "candidate") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": slug,
        "gitbox_url": f"https://gitbox.apache.org/repos/asf/{slug}.git",
        "github_url": f"https://github.com/apache/{slug}.git",
        "confidence": confidence,
        "mapping_evidence": [],
        "cves": [],
        "direct_commit_refs": [],
    }


def dedupe_manifest_rows(rows_by_repo: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    manifests = []
    for row in rows_by_repo.values():
        row["cves"] = sorted(set(row.get("cves") or []))
        evidence = {json.dumps(item, sort_keys=True): item for item in row.get("mapping_evidence") or []}
        row["mapping_evidence"] = [evidence[key] for key in sorted(evidence)]
        commits = {(item["cve_id"], item["commit"], item.get("url")): item for item in row.get("direct_commit_refs") or []}
        row["direct_commit_refs"] = [commits[key] for key in sorted(commits)]
        manifests.append(row)
    return sorted(manifests, key=lambda row: row["repo"])


def upsert_manifest_repo(
    rows_by_repo: dict[str, dict[str, Any]],
    slug: str,
    *,
    confidence: str,
    evidence: dict[str, Any],
    cve_id: Optional[str] = None,
) -> bool:
    row = rows_by_repo.get(slug)
    added = row is None
    if row is None:
        row = manifest_row(slug, confidence=confidence)
        rows_by_repo[slug] = row
    if confidence == "high":
        row["confidence"] = "high"
    if cve_id and cve_id not in row["cves"]:
        row["cves"].append(cve_id)
    row["mapping_evidence"].append(evidence)
    return added


def cmd_merge_osv_repos(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    repo_path_jsonl = root / "derived" / "repositories.jsonl"
    rows_by_repo = {row["repo"]: row for row in read_jsonl(repo_path_jsonl)}
    added = 0
    updated = 0
    skipped_urls = 0
    for link in read_jsonl(root / "derived" / "osv_links.jsonl"):
        cve_id = link["cve_id"]
        source_path = (link.get("source") or {}).get("record_path")
        for event in link.get("git_ranges") or []:
            repo_url = str(event.get("repo_url") or "")
            slug = slug_from_url(repo_url)
            if not slug:
                skipped_urls += 1
                continue
            if upsert_manifest_repo(
                rows_by_repo,
                slug,
                confidence="candidate",
                cve_id=cve_id,
                evidence={
                    "repo": slug,
                    "confidence": "candidate",
                    "method": "osv_git_range_repo_url",
                    "source_url": repo_url,
                    "record_path": source_path,
                    "cve_id": cve_id,
                },
            ):
                added += 1
            else:
                updated += 1
    manifests = dedupe_manifest_rows(rows_by_repo)
    write_jsonl(repo_path_jsonl, manifests)
    print(json.dumps({
        "repositories": len(manifests),
        "added_from_osv": added,
        "updated_from_osv": updated,
        "skipped_urls": skipped_urls,
    }))


ASF_PROJECTS_URL = "https://projects.apache.org/json/foundation/projects.json"


def project_repository_urls(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def cmd_sync_asf_projects(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    raw = fetch_bytes(ASF_PROJECTS_URL)
    projects = json.loads(raw.decode("utf-8"))
    rows = []
    for key, project in sorted(projects.items()):
        repos = project_repository_urls(project.get("repository"))
        rows.append({
            "schema_version": SCHEMA_VERSION,
            "project_key": key,
            "name": project.get("name"),
            "pmc": project.get("pmc"),
            "programming_language": project.get("programming-language"),
            "homepage": project.get("homepage"),
            "repository_urls": repos,
        })
    write_json(root / "state" / "asf_projects_snapshot.json", {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "source_url": ASF_PROJECTS_URL,
        "project_count": len(rows),
        "projects_with_repository": sum(1 for row in rows if row["repository_urls"]),
        "projects_without_repository": sum(1 for row in rows if not row["repository_urls"]),
    })
    write_jsonl(root / "derived" / "asf_project_repos.jsonl", rows)
    print(json.dumps({
        "projects": len(rows),
        "with_repository": sum(1 for row in rows if row["repository_urls"]),
        "without_repository": sum(1 for row in rows if not row["repository_urls"]),
    }))


def cmd_merge_asf_project_repos(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    repo_path_jsonl = root / "derived" / "repositories.jsonl"
    rows_by_repo = {row["repo"]: row for row in read_jsonl(repo_path_jsonl)}
    added = 0
    updated = 0
    skipped_urls = 0
    projects = list(read_jsonl(root / "derived" / "asf_project_repos.jsonl"))
    for project in projects:
        urls = list(project.get("repository_urls") or [])
        if args.infer_missing and not urls:
            key = project["project_key"].replace("_", "-")
            urls = [f"https://gitbox.apache.org/repos/asf/{key}.git"]
        for repo_url in urls:
            slug = slug_from_url(repo_url)
            if not slug:
                skipped_urls += 1
                continue
            if upsert_manifest_repo(
                rows_by_repo,
                slug,
                confidence="candidate",
                evidence={
                    "repo": slug,
                    "confidence": "candidate",
                    "method": "asf_project_repository",
                    "source_url": repo_url,
                    "project_key": project["project_key"],
                    "project_name": project.get("name"),
                    "pmc": project.get("pmc"),
                    "inferred": repo_url not in (project.get("repository_urls") or []),
                },
            ):
                added += 1
            else:
                updated += 1
    manifests = dedupe_manifest_rows(rows_by_repo)
    write_jsonl(repo_path_jsonl, manifests)
    print(json.dumps({
        "projects": len(projects),
        "repositories": len(manifests),
        "added_from_asf_projects": added,
        "updated_from_asf_projects": updated,
        "skipped_urls": skipped_urls,
        "infer_missing": args.infer_missing,
    }))


def repo_path(root: Path, slug: str) -> Path:
    mirror = root / "repos" / f"{slug}.git"
    worktree = root / "repos" / slug
    if mirror.exists():
        return mirror
    if worktree.exists():
        return worktree
    return mirror


def is_complete_mirror(path: Path) -> bool:
    if not path.is_dir():
        return False
    probe = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-bare-repository"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    if probe.returncode or probe.stdout.strip() != "true":
        return False
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def is_complete_worktree(path: Path) -> bool:
    if not path.is_dir():
        return False
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def is_complete_repo(path: Path) -> bool:
    return is_complete_mirror(path) or is_complete_worktree(path)


def destination_for_clone(root: Path, slug: str, clone_mode: str) -> Path:
    if clone_mode == "worktree":
        return root / "repos" / slug
    return root / "repos" / f"{slug}.git"


def preserve_interrupted_path(path: Path) -> None:
    """Keep a broken/interrupted clone for forensics instead of deleting it."""
    if not path.exists():
        return
    suffix = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(path.name + f".interrupted-{suffix}")
    path.rename(target)


def clone_urls_for_manifest(item: dict[str, Any]) -> list[str]:
    urls = [item.get("github_url"), item.get("gitbox_url")]
    seen = set()
    result = []
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            result.append(url)
    return result


def clone_args_for_url(url: str, destination: Path, clone_mode: str, filter_blobs: bool) -> list[str]:
    if clone_mode == "mirror":
        return ["clone", "--mirror", url, str(destination)]
    if filter_blobs:
        return ["clone", "--filter=blob:none", url, str(destination)]
    return ["clone", url, str(destination)]


def configure_repo_transport(path: Path, proxy: Optional[str], connect_timeout: Optional[int]) -> None:
    if not path.exists():
        return
    if proxy:
        run_git(["-C", str(path), "config", "http.proxy", proxy], check=False)
        run_git(["-C", str(path), "config", "https.proxy", proxy], check=False)
    if connect_timeout:
        run_git(["-C", str(path), "config", "http.connectTimeout", str(connect_timeout)], check=False)


def cmd_clone_repos(args: argparse.Namespace) -> None:
    # Current policy is intentionally simple: try the manifest clone URLs,
    # record every transport failure in clone_report.jsonl, and let
    # run-repo-task mark clone_error so the caller can move to the next repo.
    # Archive/commit-neighborhood fallback is a known future direction, but it
    # changes verification and extraction semantics enough that it should not
    # be mixed into this stabilization pass.
    root = Path(args.output).expanduser().resolve()
    manifests = list(read_jsonl(root / "derived" / "repositories.jsonl"))
    selected = [row for row in manifests if args.include_candidates or row["confidence"] == "high"]
    if args.repo:
        wanted = set(args.repo)
        selected = [row for row in selected if row["repo"] in wanted]
    if args.only_patch_candidates:
        candidate_repos = {
            row["repo"]
            for row in read_jsonl(root / "derived" / "patch_candidates.jsonl")
        }
        selected = [row for row in selected if row["repo"] in candidate_repos]
    if args.limit:
        selected = selected[:args.limit]
    report = []
    for index, item in enumerate(selected, 1):
        destination = destination_for_clone(root, item["repo"], args.clone_mode)
        partial = destination.with_name(destination.name + ".partial")
        attempts = []
        try:
            if destination.exists() and is_complete_repo(destination):
                configure_repo_transport(destination, args.git_proxy, args.connect_timeout)
                run_git(
                    ["-C", str(destination), "remote", "update", "--prune"],
                    proxy=args.git_proxy,
                    connect_timeout=args.connect_timeout,
                )
                action = "updated"
            else:
                if destination.exists():
                    preserve_interrupted_path(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if partial.exists() and not is_complete_repo(partial):
                    preserve_interrupted_path(partial)
                if partial.exists() and is_complete_repo(partial):
                    configure_repo_transport(partial, args.git_proxy, args.connect_timeout)
                    run_git(
                        ["-C", str(partial), "remote", "update", "--prune"],
                        proxy=args.git_proxy,
                        connect_timeout=args.connect_timeout,
                    )
                else:
                    for url in clone_urls_for_manifest(item):
                        if partial.exists():
                            preserve_interrupted_path(partial)
                        clone_args = clone_args_for_url(url, partial, args.clone_mode, args.filter_blobs)
                        try:
                            run_git_with_timeout(
                                clone_args,
                                timeout=args.clone_timeout,
                                proxy=args.git_proxy,
                                connect_timeout=args.connect_timeout,
                            )
                            configure_repo_transport(partial, args.git_proxy, args.connect_timeout)
                            attempts.append({"url": url, "status": "ok"})
                            break
                        except RuntimeError as exc:
                            attempts.append({"url": url, "status": "error", "error": str(exc)})
                    if not partial.exists() or not is_complete_repo(partial):
                        errors = "; ".join(f"{row['url']}: {row.get('error')}" for row in attempts)
                        raise RuntimeError(errors or f"no clone URL available for {item['repo']}")
                partial.replace(destination)
                action = "cloned"
            head = run_git(
                ["-C", str(destination), "rev-parse", "HEAD"],
                proxy=args.git_proxy,
                connect_timeout=args.connect_timeout,
            ).strip()
            report.append({
                "repo": item["repo"],
                "status": action,
                "head": head,
                "path": str(destination),
                "clone_mode": args.clone_mode,
                "filter_blobs": args.filter_blobs,
                "git_proxy": args.git_proxy,
                "attempts": attempts,
            })
        except RuntimeError as exc:
            report.append({
                "repo": item["repo"],
                "status": "error",
                "error": str(exc),
                "clone_mode": args.clone_mode,
                "filter_blobs": args.filter_blobs,
                "git_proxy": args.git_proxy,
                "attempts": attempts,
            })
        print(f"[{index}/{len(selected)}] {item['repo']}: {report[-1]['status']}", file=sys.stderr)
    write_jsonl(root / "derived" / "clone_report.jsonl", report)
    print(json.dumps(Counter(row["status"] for row in report)))


def upsert_repo_status(root: Path, row: dict[str, Any]) -> None:
    path = root / "derived" / "repo_status.jsonl"
    existing = {}
    if path.exists():
        existing = {item["repo"]: item for item in read_jsonl(path)}
    row = {**row, "schema_version": SCHEMA_VERSION, "updated_at": now_iso()}
    existing[row["repo"]] = row
    write_jsonl(path, [existing[key] for key in sorted(existing)])


def repo_task_counts(root: Path, repo: str) -> dict[str, int]:
    candidates = [row for row in read_jsonl(root / "derived" / "patch_candidates.jsonl") if row["repo"] == repo]
    verified = [
        row for row in read_jsonl(root / "derived" / "verified_patches.jsonl")
        if row["repo"] == repo
    ] if (root / "derived" / "verified_patches.jsonl").exists() else []
    samples = [
        row for row in read_jsonl(root / "dataset" / "samples.jsonl")
        if row.get("repo_id") == repo
    ] if (root / "dataset" / "samples.jsonl").exists() else []
    audits = [
        row for row in read_jsonl(root / "audits" / "results.jsonl")
        if any(sample["sample_id"] == row.get("sample_id") for sample in samples)
    ] if (root / "audits" / "results.jsonl").exists() else []
    return {
        "candidate_count": len(candidates),
        "verified_count": len(verified),
        "sample_pairs": len(samples) // 2,
        "audit_count": len(audits),
    }


def repo_verify_diagnostics(root: Path, repo: str) -> dict[str, Any]:
    path = root / "derived" / "verify_diagnostics.json"
    if not path.exists():
        return {}
    report = read_json(path)
    return (report.get("by_repo") or {}).get(repo, {})


def write_repo_task_status(root: Path, repo: str, *, stage: str, status: str, last_error: Optional[str] = None) -> None:
    upsert_repo_status(root, {
        "repo": repo,
        "stage": stage,
        "status": status,
        "last_error": last_error,
        **repo_task_counts(root, repo),
    })


def cmd_run_repo_task(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    repo = args.repo
    try:
        cmd_clone_repos(argparse.Namespace(
            output=args.output,
            limit=None,
            include_candidates=True,
            only_patch_candidates=False,
            repo=[repo],
            clone_timeout=args.clone_timeout,
            clone_mode=args.clone_mode,
            filter_blobs=args.filter_blobs,
            git_proxy=args.git_proxy,
            connect_timeout=args.connect_timeout,
        ))
        clone_rows = [row for row in read_jsonl(root / "derived" / "clone_report.jsonl") if row["repo"] == repo]
        if not clone_rows:
            write_repo_task_status(root, repo, stage="clone", status="clone_error", last_error="repo not found in repositories manifest")
            raise SystemExit(1)
        if clone_rows[-1]["status"] == "error":
            write_repo_task_status(root, repo, stage="clone", status="clone_error", last_error=clone_rows[-1].get("error"))
            raise SystemExit(1)

        cmd_discover_patches(argparse.Namespace(output=args.output, repo=[repo]))
        counts = repo_task_counts(root, repo)
        if not counts["candidate_count"]:
            write_repo_task_status(root, repo, stage="discover", status="no_candidates")
            print(json.dumps({"repo": repo, "status": "no_candidates", **counts}))
            return

        cmd_verify_patches(argparse.Namespace(output=args.output, repo=[repo]))
        counts = repo_task_counts(root, repo)
        if not counts["verified_count"]:
            write_repo_task_status(root, repo, stage="verify", status="no_verified_patches")
            print(json.dumps({"repo": repo, "status": "no_verified_patches", **counts, "verify_diagnostics": repo_verify_diagnostics(root, repo)}))
            return

        cmd_extract_samples(argparse.Namespace(
            output=args.output,
            repo=[repo],
            max_context_chars=args.max_context_chars,
            large_context_hint_threshold=args.large_context_hint_threshold,
        ))
        counts = repo_task_counts(root, repo)
        if counts["sample_pairs"] < args.min_pairs:
            write_repo_task_status(root, repo, stage="extract", status="no_samples")
            print(json.dumps({"repo": repo, "status": "no_samples", **counts}))
            return

        cmd_validate(argparse.Namespace(output=args.output, min_pairs=args.min_pairs))
        if args.audit_dry_run or args.audit:
            cmd_audit_harness(argparse.Namespace(
                output=args.output,
                sample_id=None,
                repo=repo,
                label=args.audit_label,
                limit=args.audit_limit,
                claude_command=args.claude_command,
                claude_arg=args.claude_arg,
                timeout=args.audit_timeout,
                dry_run=args.audit_dry_run,
            ))
        write_repo_task_status(root, repo, stage="validated", status="ok")
        print(json.dumps({"repo": repo, "status": "ok", **repo_task_counts(root, repo)}))
    except Exception as exc:
        write_repo_task_status(root, repo, stage="task", status="task_error", last_error=str(exc))
        raise


def read_repo_list(path: Path) -> list[str]:
    repos = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            repos.append(value.split()[0])
    return repos


def latest_repo_status(root: Path, repo: str) -> Optional[dict[str, Any]]:
    path = root / "derived" / "repo_status.jsonl"
    if not path.exists():
        return None
    rows = [row for row in read_jsonl(path) if row.get("repo") == repo]
    return rows[-1] if rows else None


def cmd_run_task_batch(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    repo_list = Path(args.repo_list).expanduser()
    repos = read_repo_list(repo_list)
    started_at = now_iso()
    results = []
    for index, repo in enumerate(repos, 1):
        print(f"[{index}/{len(repos)}] batch repo: {repo}", file=sys.stderr)
        exit_code = 0
        error = None
        try:
            cmd_run_repo_task(argparse.Namespace(
                output=args.output,
                repo=repo,
                min_pairs=args.min_pairs,
                max_context_chars=args.max_context_chars,
                large_context_hint_threshold=args.large_context_hint_threshold,
                audit=args.audit,
                audit_dry_run=args.audit_dry_run,
                audit_label=args.audit_label,
                audit_limit=args.audit_limit,
                claude_command=args.claude_command,
                claude_arg=args.claude_arg,
                audit_timeout=args.audit_timeout,
                clone_timeout=args.clone_timeout,
                clone_mode=args.clone_mode,
                filter_blobs=args.filter_blobs,
                git_proxy=args.git_proxy,
                connect_timeout=args.connect_timeout,
            ))
        except SystemExit as exc:
            exit_code = int(exc.code or 0) if isinstance(exc.code, int) else 1
            if exit_code and not args.continue_on_error:
                raise
        except Exception as exc:
            exit_code = 1
            error = str(exc)
            if not args.continue_on_error:
                raise
        status = latest_repo_status(root, repo) or {
            "repo": repo,
            "stage": "batch",
            "status": "missing_status",
            "last_error": error or "repo task did not write repo_status.jsonl",
            "candidate_count": 0,
            "verified_count": 0,
            "sample_pairs": 0,
            "audit_count": 0,
        }
        result = {
            "index": index,
            "repo": repo,
            "exit_code": exit_code,
            "status": status.get("status"),
            "stage": status.get("stage"),
            "candidate_count": status.get("candidate_count", 0),
            "verified_count": status.get("verified_count", 0),
            "sample_pairs": status.get("sample_pairs", 0),
            "audit_count": status.get("audit_count", 0),
            "last_error": status.get("last_error") or error,
        }
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "finished_at": now_iso(),
        "repo_list": str(repo_list),
        "total_repos": len(repos),
        "status_counts": Counter(row["status"] for row in results),
        "exit_code_counts": Counter(str(row["exit_code"]) for row in results),
        "sample_pairs": sum(int(row.get("sample_pairs") or 0) for row in results),
        "verified_count": sum(int(row.get("verified_count") or 0) for row in results),
        "results": results,
    }
    write_json(root / "derived" / "task_batch_summary.json", summary)
    print(json.dumps({
        "total_repos": summary["total_repos"],
        "status_counts": summary["status_counts"],
        "exit_code_counts": summary["exit_code_counts"],
        "sample_pairs": summary["sample_pairs"],
        "verified_count": summary["verified_count"],
        "summary_path": "derived/task_batch_summary.json",
    }, ensure_ascii=False))


def cvemap(root: Path) -> dict[str, dict[str, Any]]:
    return {row["cve_id"]: row for row in read_jsonl(root / "derived" / "apache_cves.jsonl")}


def repo_cve_map(root: Path) -> dict[str, set[str]]:
    return {row["repo"]: set(row["cves"]) for row in read_jsonl(root / "derived" / "repositories.jsonl")}


def normalise_commit(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    return value if re.fullmatch(r"[0-9a-fA-F]{7,64}", value) else None


def cmd_discover_patches(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    cves = cvemap(root)
    repo_cves = repo_cve_map(root)
    target_repos = set(args.repo or [])
    candidates: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(cve_id: str, repo: str, commit: Optional[str], method: str, sources: list[str], *, introduced: Optional[str] = None) -> None:
        if target_repos and repo not in target_repos:
            return
        commit = normalise_commit(commit)
        if not commit or cve_id not in cves:
            return
        key = (cve_id, repo, commit.lower())
        row = candidates.setdefault(key, {
            "schema_version": SCHEMA_VERSION, "cve_id": cve_id, "repo": repo,
            "patch_commit": commit.lower(), "methods": [], "sources": [], "introduced": [],
        })
        if method not in row["methods"]:
            row["methods"].append(method)
        row["sources"] = sorted(set(row["sources"]).union(sources))
        if introduced and introduced not in row["introduced"]:
            row["introduced"].append(introduced)

    for link in read_jsonl(root / "derived" / "osv_links.jsonl") if (root / "derived" / "osv_links.jsonl").exists() else []:
        cve_id = link["cve_id"]
        for event in link.get("git_ranges") or []:
            slug = slug_from_url(str(event.get("repo_url") or ""))
            if slug:
                add(cve_id, slug, event.get("fixed"), "osv_git_range", [link["source"]["record_path"]], introduced=event.get("introduced"))

    for manifest in read_jsonl(root / "derived" / "repositories.jsonl"):
        if target_repos and manifest["repo"] not in target_repos:
            continue
        for direct in manifest.get("direct_commit_refs") or []:
            add(direct["cve_id"], manifest["repo"], direct["commit"], "cve_direct_commit", [direct.get("url") or ""])

    # Git history is lower-confidence discovery only.  A sample is emitted
    # only after verify-patches has checked parent/diff evidence.
    for repo, cve_ids in repo_cves.items():
        if target_repos and repo not in target_repos:
            continue
        mirror = repo_path(root, repo)
        if not mirror.is_dir():
            continue
        for cve_id in sorted(cve_ids):
            output = run_git([
                "-C", str(mirror), "log", "--all", "--regexp-ignore-case",
                f"--grep={cve_id}", "--format=%H%x1f%s",
            ], check=False)
            for line in output.splitlines():
                if "\x1f" not in line:
                    continue
                commit, subject = line.split("\x1f", 1)
                add(cve_id, repo, commit, "git_history_cve_mention", [f"git:{commit}:{subject}"])
    rows = list(candidates.values())
    if target_repos and (root / "derived" / "patch_candidates.jsonl").exists():
        rows.extend(
            row for row in read_jsonl(root / "derived" / "patch_candidates.jsonl")
            if row["repo"] not in target_repos
        )
    rows = sorted(rows, key=lambda row: (row["repo"], row["patch_commit"], row["cve_id"]))
    write_jsonl(root / "derived" / "patch_candidates.jsonl", rows)
    print(json.dumps({"patch_candidates": len(rows), "by_method": Counter(method for row in rows for method in row["methods"])}))


def git_commit_exists(mirror: Path, commit: str) -> bool:
    return subprocess.run(["git", "-C", str(mirror), "cat-file", "-e", f"{commit}^{{commit}}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def commit_branches_and_tags(mirror: Path, commit: str) -> dict[str, list[str]]:
    refs = run_git(["-C", str(mirror), "for-each-ref", "--contains", commit, "--format=%(refname)"]).splitlines()
    branches = sorted(ref.removeprefix("refs/heads/").removeprefix("refs/remotes/") for ref in refs if ref.startswith(("refs/heads/", "refs/remotes/")))
    tags = sorted(ref.removeprefix("refs/tags/") for ref in refs if ref.startswith("refs/tags/"))
    return {"branches": branches, "tags": tags}


def write_verify_diagnostics(root: Path, verified: list[dict[str, Any]], rejected: list[dict[str, Any]]) -> None:
    by_repo: dict[str, dict[str, Any]] = {}

    def repo_entry(repo: str) -> dict[str, Any]:
        return by_repo.setdefault(repo, {
            "candidate_commits": 0,
            "verified_commits": 0,
            "rejected_commits": 0,
            "reject_reasons": Counter(),
            "sample_rejections": [],
        })

    for row in verified:
        entry = repo_entry(row["repo"])
        entry["candidate_commits"] += 1
        entry["verified_commits"] += 1
    for row in rejected:
        entry = repo_entry(row["repo"])
        reason = row.get("reject_reason") or row.get("status") or "unknown"
        entry["candidate_commits"] += 1
        entry["rejected_commits"] += 1
        entry["reject_reasons"][reason] += 1
        if len(entry["sample_rejections"]) < 5:
            entry["sample_rejections"].append({
                "patch_commit": row["patch_commit"],
                "status": row.get("status"),
                "reject_reason": reason,
                "cves": row.get("cves") or [],
                "methods": row.get("methods") or [],
                "source_count": len(row.get("source_paths") or []),
                "changed_count": len(row.get("changed_paths") or []),
            })

    normalized = {}
    for repo, entry in sorted(by_repo.items()):
        entry["reject_reasons"] = dict(sorted(entry["reject_reasons"].items()))
        normalized[repo] = entry
    totals = {
        "candidate_commits": sum(entry["candidate_commits"] for entry in normalized.values()),
        "verified_commits": sum(entry["verified_commits"] for entry in normalized.values()),
        "rejected_commits": sum(entry["rejected_commits"] for entry in normalized.values()),
        "reject_reasons": dict(sorted(Counter(
            reason
            for entry in normalized.values()
            for reason, count in entry["reject_reasons"].items()
            for _ in range(count)
        ).items())),
    }
    write_json(root / "derived" / "verify_diagnostics.json", {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "totals": totals,
        "by_repo": normalized,
    })


def cmd_verify_patches(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    target_repos = set(args.repo or [])
    include_containment = getattr(args, "include_containment", False)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in read_jsonl(root / "derived" / "patch_candidates.jsonl"):
        if target_repos and candidate["repo"] not in target_repos:
            continue
        key = (candidate["repo"], candidate["patch_commit"])
        row = grouped.setdefault(key, {
            "schema_version": SCHEMA_VERSION, "repo": candidate["repo"], "patch_commit": candidate["patch_commit"],
            "cves": [], "methods": [], "sources": [], "introduced": [],
        })
        row["cves"].append(candidate["cve_id"])
        row["methods"] = sorted(set(row["methods"]).union(candidate["methods"]))
        row["sources"] = sorted(set(row["sources"]).union(candidate["sources"]))
        row["introduced"] = sorted(set(row["introduced"]).union(candidate.get("introduced") or []))
    verified = []
    rejected = []
    for row in grouped.values():
        mirror = repo_path(root, row["repo"])
        if not mirror.is_dir():
            row["status"] = "unavailable"
            row["reject_reason"] = "repo_not_cloned"
            rejected.append(row)
            continue
        if not git_commit_exists(mirror, row["patch_commit"]):
            row["status"] = "unavailable"
            row["reject_reason"] = "commit_missing"
            rejected.append(row)
            continue
        try:
            parent = run_git(["-C", str(mirror), "rev-parse", f"{row['patch_commit']}^"]).strip()
        except RuntimeError:
            row["status"] = "root_commit"
            row["reject_reason"] = "root_commit"
            rejected.append(row)
            continue
        changed = [path for path in run_git(["-C", str(mirror), "diff-tree", "--no-commit-id", "--name-only", "-r", row["patch_commit"]]).splitlines() if path]
        source_paths = [path for path in changed if is_source_path(path)]
        # `git for-each-ref --contains` is expensive on large Apache histories
        # such as tomcat.  Keep online batch verification focused on commit,
        # parent and source-diff evidence; containment can be backfilled later.
        containment = commit_branches_and_tags(mirror, row["patch_commit"]) if include_containment else {"branches": [], "tags": []}
        row.update({
            "pre_patch_commit": parent,
            "changed_paths": changed,
            "source_paths": source_paths,
            "containment": containment,
            "status": "verified" if source_paths else "non_source_change",
            "confidence": "verified" if "osv_git_range" in row["methods"] else "supported",
        })
        if source_paths:
            verified.append(row)
        else:
            row["reject_reason"] = "non_source_change"
            rejected.append(row)
    if target_repos:
        verified.extend(
            row for row in read_jsonl(root / "derived" / "verified_patches.jsonl")
            if row["repo"] not in target_repos
        ) if (root / "derived" / "verified_patches.jsonl").exists() else None
        rejected.extend(
            row for row in read_jsonl(root / "derived" / "rejected_patch_candidates.jsonl")
            if row["repo"] not in target_repos
        ) if (root / "derived" / "rejected_patch_candidates.jsonl").exists() else None
    verified.sort(key=lambda row: (row["repo"], row["patch_commit"]))
    rejected.sort(key=lambda row: (row["repo"], row["patch_commit"]))
    write_jsonl(root / "derived" / "verified_patches.jsonl", verified)
    write_jsonl(root / "derived" / "rejected_patch_candidates.jsonl", rejected)
    write_verify_diagnostics(root, verified, rejected)
    print(json.dumps({"verified_patches": len(verified), "rejected_or_unavailable": len(rejected)}))


@dataclasses.dataclass(frozen=True)
class FunctionSpan:
    name: str
    start: int
    end: int


PY_DEF_RE = re.compile(r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>[A-Za-z_][\w.]*)\s*\(")
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "return", "sizeof", "do"}
JAVA_NON_METHOD_PREFIXES = ("return ", "throw ", "new ", "super.", "this.")


def python_functions(lines: list[str]) -> list[FunctionSpan]:
    spans = []
    for index, line in enumerate(lines):
        match = PY_DEF_RE.match(line)
        if not match:
            continue
        indent = len(match.group("indent").expandtabs(4))
        end = len(lines)
        for cursor in range(index + 1, len(lines)):
            candidate = lines[cursor]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            candidate_indent = len(candidate) - len(candidate.lstrip(" \t"))
            if candidate_indent <= indent:
                end = cursor
                break
        spans.append(FunctionSpan(match.group("name"), index + 1, end))
    return spans


def brace_delta(line: str) -> int:
    # Good-enough lexical masking for function extent discovery.  Context is
    # still taken from Git; this only identifies a useful enclosing span.
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line.count("{") - line.count("}")


def brace_functions(lines: list[str]) -> list[FunctionSpan]:
    spans: list[FunctionSpan] = []
    for start in range(len(lines)):
        window = " ".join(lines[start:min(len(lines), start + 8)])
        brace_at = window.find("{")
        paren_at = window.find("(")
        if brace_at < 0 or paren_at < 0 or paren_at > brace_at or ";" in window[:brace_at]:
            continue
        before = window[:paren_at]
        names = re.findall(r"([A-Za-z_~][\w:~]*)\s*$", before)
        if not names or names[-1] in CONTROL_WORDS:
            continue
        depth = 0
        seen = False
        for end in range(start, len(lines)):
            depth += brace_delta(lines[end])
            seen = seen or "{" in lines[end]
            if seen and depth <= 0:
                spans.append(FunctionSpan(names[-1], start + 1, end + 1))
                break
    unique: dict[tuple[str, int], FunctionSpan] = {}
    for span in spans:
        key = (span.name, span.end)
        current = unique.get(key)
        if current is None or span.start > current.start:
            unique[key] = span
    return sorted(unique.values(), key=lambda item: (item.start, item.end, item.name))


def looks_like_java_method_prefix(prefix: str, name: str) -> bool:
    compact = " ".join(prefix.strip().split())
    if not compact or name in CONTROL_WORDS:
        return False
    if compact.endswith("@" + name):
        return False
    if re.search(rf"\.\s*{re.escape(name)}$", compact):
        return False
    if any(token in compact for token in ("=", "->", "::")):
        return False
    if compact.startswith(JAVA_NON_METHOD_PREFIXES):
        return False
    tokens = re.findall(r"[A-Za-z_][\w$]*|[<>?,\[\].]+", compact)
    return len([token for token in tokens if re.match(r"[A-Za-z_]", token)]) >= 2


def java_functions(lines: list[str]) -> list[FunctionSpan]:
    spans: list[FunctionSpan] = []
    for anchor, line in enumerate(lines):
        if "{" not in line:
            continue
        start = anchor
        while start > 0:
            previous = lines[start - 1].strip()
            if not previous or previous.startswith(("//", "/*", "*", "@")):
                start -= 1
                continue
            if previous.endswith((",", "throws", "<", "&", "|")):
                start -= 1
                continue
            break
        window = " ".join(lines[start:anchor + 1])
        brace_at = window.rfind("{")
        if brace_at < 0 or ";" in window[:brace_at]:
            continue
        paren_at = -1
        name = ""
        for match in re.finditer(r"([A-Za-z_$][\w$]*)\s*\(", window[:brace_at]):
            candidate_name = match.group(1)
            candidate_paren = match.start(0) + len(candidate_name)
            if looks_like_java_method_prefix(window[:candidate_paren], candidate_name):
                name = candidate_name
                paren_at = candidate_paren
                break
        if paren_at < 0 or paren_at > brace_at:
            continue
        before = window[:paren_at]
        depth = 0
        seen = False
        for end in range(start, len(lines)):
            depth += brace_delta(lines[end])
            seen = seen or "{" in lines[end]
            if seen and depth <= 0:
                spans.append(FunctionSpan(name, start + 1, end + 1))
                break
    filtered: list[FunctionSpan] = []
    for span in sorted(spans, key=lambda item: (item.start, item.end - item.start, item.name)):
        if any(existing.start <= span.start and span.end <= existing.end and existing.name == span.name for existing in filtered):
            continue
        filtered.append(span)
    return sorted(filtered, key=lambda item: (item.start, item.end, item.name))


def functions_for_path(path: str, text: str) -> list[FunctionSpan]:
    lines = text.splitlines()
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return python_functions(lines)
    if suffix == ".java":
        return java_functions(lines)
    return brace_functions(lines)


def parse_diff_hunks(diff: str) -> dict[str, list[tuple[int, int, int, int]]]:
    current: Optional[str] = None
    result: dict[str, list[tuple[int, int, int, int]]] = defaultdict(list)
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("@@") and current:
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                old_start, old_count, new_start, new_count = match.groups()
                result[current].append((int(old_start), int(old_count or 1), int(new_start), int(new_count or 1)))
    return result


def git_blob(mirror: Path, commit: str, path: str) -> Optional[str]:
    result = subprocess.run(["git", "-C", str(mirror), "show", f"{commit}:{path}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def selected_context(path: str, text: str, changed_lines: list[int], *, maximum_chars: int) -> tuple[str, list[dict[str, Any]]]:
    lines = text.splitlines()
    spans = functions_for_path(path, text)
    selected = []
    for span in spans:
        if any(span.start <= line <= span.end for line in changed_lines):
            selected.append(span)
    if not selected:
        center = changed_lines[0] if changed_lines else 1
        start, end = max(1, center - 40), min(len(lines), center + 40)
        selected = [FunctionSpan("<file_context>", start, end)]
    # Preserve deterministic, non-overlapping blocks.
    blocks = []
    metadata = []
    consumed = 0
    for span in sorted(selected, key=lambda item: (item.start, item.end, item.name))[:8]:
        chunk = "\n".join(lines[span.start - 1:span.end])
        header = f"# path: {path}\n# function: {span.name} (lines {span.start}-{span.end})\n"
        if consumed and consumed + len(header) + len(chunk) > maximum_chars:
            break
        blocks.append(header + chunk)
        metadata.append({"name": span.name, "path": path, "range": [span.start, span.end]})
        consumed += len(header) + len(chunk)
    return "\n\n".join(blocks), metadata


def context_with_large_patch_hint(chunks: list[str], funcs: list[dict[str, Any]], *, maximum_chars: int, hint_threshold: int) -> tuple[str, dict[str, Any]]:
    full_text = "\n\n".join(chunks)
    selection = {
        "strategy": "direct_changed_context_v1",
        "max_context_chars": maximum_chars,
        "hint_threshold": hint_threshold,
        "candidate_chars": len(full_text),
        "candidate_functions": len(funcs),
        "truncated": len(full_text) > maximum_chars,
        "large_context_hint": len(full_text) > hint_threshold,
    }
    if len(full_text) <= hint_threshold:
        return full_text[:maximum_chars], selection

    # Keep large-patch handling explicit and conservative in this pass.  A
    # later iteration should rank changed functions programmatically instead of
    # relying on source path order before truncation.
    hint = (
        "# large-context-hint\n"
        f"# Full changed context is {len(full_text)} characters across {len(funcs)} selected function/file blocks, "
        f"which exceeds threshold {hint_threshold}.\n"
        "# The context below is a truncated excerpt. If this sample is audited by an agent with repository access, "
        "inspect the patch diff and referenced files around the changed lines before making a final judgment.\n\n"
    )
    budget = max(0, maximum_chars - len(hint))
    return hint + full_text[:budget], selection


def cmd_extract_samples(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    cves = cvemap(root)
    target_repos = set(args.repo or [])
    samples = []
    skipped = []
    for patch in read_jsonl(root / "derived" / "verified_patches.jsonl"):
        if target_repos and patch["repo"] not in target_repos:
            continue
        mirror = repo_path(root, patch["repo"])
        diff = run_git(["-C", str(mirror), "diff", "--unified=0", patch["pre_patch_commit"], patch["patch_commit"]])
        hunks = parse_diff_hunks(diff)
        if not hunks:
            skipped.append({"repo": patch["repo"], "patch_commit": patch["patch_commit"], "reason": "empty_diff"})
            continue
        pre_chunks, post_chunks, pre_functions, post_functions = [], [], [], []
        for path, ranges in hunks.items():
            if not is_source_path(path):
                continue
            old_lines = [line for old_start, old_count, _, _ in ranges for line in range(old_start, old_start + max(old_count, 1))]
            new_lines = [line for _, _, new_start, new_count in ranges for line in range(new_start, new_start + max(new_count, 1))]
            before = git_blob(mirror, patch["pre_patch_commit"], path)
            after = git_blob(mirror, patch["patch_commit"], path)
            if before is not None:
                text, funcs = selected_context(path, before, old_lines, maximum_chars=args.max_context_chars)
                if text:
                    pre_chunks.append(text)
                    pre_functions.extend(funcs)
            if after is not None:
                text, funcs = selected_context(path, after, new_lines, maximum_chars=args.max_context_chars)
                if text:
                    post_chunks.append(text)
                    post_functions.extend(funcs)
        if not pre_chunks or not post_chunks:
            skipped.append({"repo": patch["repo"], "patch_commit": patch["patch_commit"], "reason": "no_source_context"})
            continue
        pre_text, pre_selection = context_with_large_patch_hint(
            pre_chunks,
            pre_functions,
            maximum_chars=args.max_context_chars,
            hint_threshold=args.large_context_hint_threshold,
        )
        post_text, post_selection = context_with_large_patch_hint(
            post_chunks,
            post_functions,
            maximum_chars=args.max_context_chars,
            hint_threshold=args.large_context_hint_threshold,
        )
        for cve_id in sorted(set(patch["cves"])):
            if cve_id not in cves:
                continue
            evidence = {
                "method": "osv_git_range" if "osv_git_range" in patch["methods"] else "advisory_link | git_history",
                "confidence": patch["confidence"],
                "sources": patch["sources"],
                "containment": patch["containment"],
                "introduced": patch.get("introduced") or [],
            }
            prefix = f"{cve_id}:{patch['repo']}:{patch['patch_commit'][:12]}"
            shared = {
                "schema_version": SCHEMA_VERSION,
                "repo": patch["gitbox_url"] if "gitbox_url" in patch else f"https://gitbox.apache.org/repos/asf/{patch['repo']}.git",
                "repo_id": patch["repo"],
                "cves": [cve_id],
                "evidence": evidence,
            }
            samples.append({
                **shared,
                "sample_id": prefix + ":pre",
                "label": "vulnerable",
                "commit": patch["pre_patch_commit"],
                "paired_commit": patch["patch_commit"],
                "vuln_context": {"txt": pre_text, "funcs": pre_functions, "selection": pre_selection},
            })
            samples.append({
                **shared,
                "sample_id": prefix + ":post",
                "label": "patched",
                "commit": patch["patch_commit"],
                "paired_commit": patch["pre_patch_commit"],
                "vuln_context": {"txt": post_text, "funcs": post_functions, "selection": post_selection},
            })
    if target_repos:
        sample_path = root / "dataset" / "samples.jsonl"
        skipped_path = root / "derived" / "skipped_contexts.jsonl"
        if sample_path.exists():
            samples.extend(
                row for row in read_jsonl(sample_path)
                if row.get("repo_id") not in target_repos
            )
        if skipped_path.exists():
            skipped.extend(
                row for row in read_jsonl(skipped_path)
                if row.get("repo") not in target_repos
            )
    samples.sort(key=lambda row: row["sample_id"])
    write_jsonl(root / "dataset" / "samples.jsonl", samples)
    write_jsonl(root / "derived" / "skipped_contexts.jsonl", skipped)
    print(json.dumps({"samples": len(samples), "pairs": len(samples) // 2, "skipped": len(skipped)}))


def cmd_validate(args: argparse.Namespace) -> None:
    root = Path(args.output).expanduser().resolve()
    samples = list(read_jsonl(root / "dataset" / "samples.jsonl"))
    required = {"sample_id", "label", "commit", "paired_commit", "repo", "cves", "evidence", "vuln_context"}
    errors = []
    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in samples:
        missing = required.difference(row)
        if missing:
            errors.append({"sample_id": row.get("sample_id"), "error": f"missing {sorted(missing)}"})
            continue
        if row["label"] not in {"vulnerable", "patched"}:
            errors.append({"sample_id": row["sample_id"], "error": "invalid label"})
        if not row["vuln_context"].get("txt") or not row["vuln_context"].get("funcs"):
            errors.append({"sample_id": row["sample_id"], "error": "empty context/functions"})
        pairs[row["sample_id"].rsplit(":", 1)[0]].append(row)
    for pair_id, rows in pairs.items():
        labels = {row["label"] for row in rows}
        if len(rows) != 2 or labels != {"vulnerable", "patched"}:
            errors.append({"pair": pair_id, "error": "incomplete or invalid pair"})
        elif rows[0]["commit"] != rows[1]["paired_commit"] or rows[1]["commit"] != rows[0]["paired_commit"]:
            errors.append({"pair": pair_id, "error": "commit pairing mismatch"})
    if len(pairs) < args.min_pairs:
        errors.append({"error": f"expected at least {args.min_pairs} pair(s), found {len(pairs)}"})
    report = {
        "schema_version": SCHEMA_VERSION,
        "validated_at": now_iso(),
        "samples": len(samples),
        "pairs": len(pairs),
        "labels": Counter(row.get("label") for row in samples),
        "errors": errors,
        "valid": not errors,
    }
    write_json(root / "dataset" / "validation.json", report)
    print(json.dumps({"valid": not errors, "samples": len(samples), "errors": len(errors)}))
    if errors:
        raise SystemExit(1)


def audit_prompt(sample: dict[str, Any]) -> str:
    """Create a label-blind prompt for an external audit harness."""
    function_names = ", ".join(function["name"] for function in sample["vuln_context"]["funcs"])
    return f"""You are performing an independent source-code security audit.

Review the code context below. Do not assume that a vulnerability exists and
do not infer facts from external issue trackers. Identify concrete input flows,
security boundaries, and any defect that could cause a security impact.

Return exactly one JSON object with these keys:
- verdict: one of "vulnerable", "not_vulnerable", or "uncertain"
- rationale: concise evidence-based explanation
- locations: list of function names or file:line references
- vulnerability_class: CWE or plain-language class, if applicable
- confidence: number from 0 to 1

The context contains functions: {function_names}

--- code context ---
{sample["vuln_context"]["txt"]}
--- end code context ---
"""


def cmd_audit_harness(args: argparse.Namespace) -> None:
    """Run label-blind sample audits through a configured Claude CLI harness.

    This command is downstream of dataset construction. It records prompts and
    raw model output without mutating evidence, labels, commits, or contexts.
    """
    root = Path(args.output).expanduser().resolve()
    samples = list(read_jsonl(root / "dataset" / "samples.jsonl"))
    if args.sample_id:
        samples = [row for row in samples if row["sample_id"] == args.sample_id]
        if not samples:
            raise ValueError(f"sample not found: {args.sample_id}")
    else:
        samples = [row for row in samples if row["label"] == args.label]
        if args.repo:
            samples = [row for row in samples if row.get("repo_id") == args.repo]
    if args.limit:
        samples = samples[:args.limit]
    prompts_dir = root / "audits" / "prompts"
    raw_dir = root / "audits" / "raw"
    results_path = root / "audits" / "results.jsonl"
    existing = {row["sample_id"]: row for row in read_jsonl(results_path)} if results_path.exists() else {}
    for sample in samples:
        prompt = audit_prompt(sample)
        stem = hashlib.sha256(sample["sample_id"].encode("utf-8")).hexdigest()
        prompts_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = prompts_dir / f"{stem}.md"
        prompt_path.write_text(prompt, encoding="utf-8")
        record = {
            "schema_version": SCHEMA_VERSION,
            "sample_id": sample["sample_id"],
            "expected_label": sample["label"],
            "commit": sample["commit"],
            "prompt_path": str(prompt_path.relative_to(root)),
            "audited_at": now_iso(),
        }
        if args.dry_run:
            record.update({"status": "prompt_prepared"})
            existing[sample["sample_id"]] = record
            continue
        command = [args.claude_command, "-p", prompt, "--output-format", "json", *args.claude_arg]
        try:
            completed = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
                check=False,
            )
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_path = raw_dir / f"{stem}.json"
            raw_path.write_text(completed.stdout, encoding="utf-8")
            status = "ok" if completed.returncode == 0 else "command_error"
            if completed.returncode == 0:
                try:
                    payload = json.loads(completed.stdout)
                    if isinstance(payload, dict) and not str(payload.get("result") or "").strip():
                        status = "empty_result"
                except json.JSONDecodeError:
                    pass
            record.update({
                "status": status,
                "returncode": completed.returncode,
                "raw_response_path": str(raw_path.relative_to(root)),
                "stderr": completed.stderr[-4000:],
            })
        except (OSError, subprocess.TimeoutExpired) as exc:
            record.update({"status": "command_error", "error": str(exc)})
        existing[sample["sample_id"]] = record
    write_jsonl(results_path, sorted(existing.values(), key=lambda row: row["sample_id"]))
    statuses = Counter(row.get("status") for row in existing.values())
    print(json.dumps({"audited_or_prepared": len(samples), "statuses": statuses}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    index = sub.add_parser("index-cves", help="select published Apache CNA CVEs from CVEListV5")
    index.add_argument("--cvelist-repo", required=True)
    index.add_argument("--output", required=True)
    index.set_defaults(func=cmd_index_cves)
    evidence = sub.add_parser("collect-evidence", help="cache Apache security, list, and JIRA reference documents")
    evidence.add_argument("--output", required=True)
    evidence.add_argument("--kinds", nargs="+", default=["apache_security", "apache_list", "apache_jira"], choices=["apache_security", "apache_list", "apache_jira"])
    evidence.add_argument("--limit", type=int, help="cap new/retried documents for a batch")
    evidence.add_argument("--retries", type=int, default=4)
    evidence.set_defaults(func=cmd_collect_evidence)
    osv = sub.add_parser("sync-osv", help="mirror official OSV data export")
    osv.add_argument("--output", required=True)
    osv.add_argument("--full", action="store_true", help="download and extract all.zip")
    osv.add_argument("--since", help="ISO timestamp for modified_id.csv incremental refresh")
    osv.add_argument("--limit", type=int, help="cap records during a test incremental run")
    osv.set_defaults(func=cmd_sync_osv)
    link = sub.add_parser("link-osv", help="link mirrored OSV records to selected CVEs")
    link.add_argument("--output", required=True)
    link.set_defaults(func=cmd_link_osv)
    discover = sub.add_parser("discover-asf-repos", help="cache Apache GitHub organisation repo inventory")
    discover.add_argument("--output", required=True)
    discover.set_defaults(func=cmd_discover_asf_repos)
    resolve = sub.add_parser("resolve-repos", help="resolve products and references to Apache repos")
    resolve.add_argument("--output", required=True)
    resolve.add_argument("--fuzzy-threshold", type=float, default=0.90)
    resolve.set_defaults(func=cmd_resolve_repos)
    merge_osv = sub.add_parser("merge-osv-repos", help="merge Apache repo URLs found in OSV git ranges into repositories.jsonl")
    merge_osv.add_argument("--output", required=True)
    merge_osv.set_defaults(func=cmd_merge_osv_repos)
    asf_projects = sub.add_parser("sync-asf-projects", help="cache official Apache projects metadata")
    asf_projects.add_argument("--output", required=True)
    asf_projects.set_defaults(func=cmd_sync_asf_projects)
    merge_projects = sub.add_parser("merge-asf-project-repos", help="merge official Apache project repository URLs into repositories.jsonl")
    merge_projects.add_argument("--output", required=True)
    merge_projects.add_argument("--infer-missing", action="store_true", help="infer gitbox URLs from project keys when official metadata has no repository field")
    merge_projects.set_defaults(func=cmd_merge_asf_project_repos)
    clone = sub.add_parser("clone-repos", help="mirror clone resolved Apache repos")
    clone.add_argument("--output", required=True)
    clone.add_argument("--limit", type=int)
    clone.add_argument("--include-candidates", action="store_true")
    clone.add_argument("--only-patch-candidates", action="store_true", help="clone only repos present in patch_candidates.jsonl")
    clone.add_argument("--repo", action="append", default=[], help="clone only this repo slug; repeatable")
    clone.add_argument("--clone-timeout", type=int, default=600, help="per-repo clone timeout in seconds")
    clone.add_argument("--clone-mode", choices=["mirror", "worktree"], default="mirror")
    clone.add_argument("--filter-blobs", action=argparse.BooleanOptionalAction, default=False, help="use blobless clone in worktree mode")
    clone.add_argument("--git-proxy", help="HTTP(S) proxy used only for git network commands")
    clone.add_argument("--connect-timeout", type=int, default=30, help="git http.connectTimeout in seconds")
    clone.set_defaults(func=cmd_clone_repos)
    patches = sub.add_parser("discover-patches", help="find patch commits from OSV, references and history")
    patches.add_argument("--output", required=True)
    patches.add_argument("--repo", action="append", default=[], help="discover only this repo slug; repeatable")
    patches.set_defaults(func=cmd_discover_patches)
    verify = sub.add_parser("verify-patches", help="verify candidate commits and parent/backport evidence")
    verify.add_argument("--output", required=True)
    verify.add_argument("--repo", action="append", default=[], help="verify only this repo slug; repeatable")
    verify.add_argument("--include-containment", action="store_true", help="compute branch/tag containment with git for-each-ref --contains")
    verify.set_defaults(func=cmd_verify_patches)
    samples = sub.add_parser("extract-samples", help="emit paired function-level pre/post contexts")
    samples.add_argument("--output", required=True)
    samples.add_argument("--repo", action="append", default=[], help="extract only this repo slug; repeatable")
    samples.add_argument("--max-context-chars", type=int, default=24000)
    samples.add_argument("--large-context-hint-threshold", type=int, default=24000, help="prepend an audit hint when full selected context exceeds this many characters")
    samples.set_defaults(func=cmd_extract_samples)
    validate = sub.add_parser("validate", help="validate final JSONL schema and pair integrity")
    validate.add_argument("--output", required=True)
    validate.add_argument("--min-pairs", type=int, default=0)
    validate.set_defaults(func=cmd_validate)
    audit = sub.add_parser("audit-harness", help="run label-blind samples through a configured Claude CLI harness")
    audit.add_argument("--output", required=True)
    audit.add_argument("--sample-id")
    audit.add_argument("--repo", help="audit only samples from this repo_id when --sample-id is not set")
    audit.add_argument("--label", choices=["vulnerable", "patched"], default="vulnerable")
    audit.add_argument("--limit", type=int, default=1)
    audit.add_argument("--claude-command", default="claude")
    audit.add_argument("--claude-arg", action="append", default=[], help="extra argument passed to Claude (repeatable)")
    audit.add_argument("--timeout", type=int, default=600)
    audit.add_argument("--dry-run", action="store_true", help="write prompt(s) without invoking the model")
    audit.set_defaults(func=cmd_audit_harness)
    task = sub.add_parser("run-repo-task", help="run clone/verify/extract/validate for one repository and update repo_status.jsonl")
    task.add_argument("--output", required=True)
    task.add_argument("--repo", required=True)
    task.add_argument("--min-pairs", type=int, default=1)
    task.add_argument("--max-context-chars", type=int, default=24000)
    task.add_argument("--large-context-hint-threshold", type=int, default=24000, help="prepend an audit hint when full selected context exceeds this many characters")
    task.add_argument("--audit", action="store_true", help="run a real audit-harness call after validation")
    task.add_argument("--audit-dry-run", action="store_true", help="prepare audit prompt(s) after validation")
    task.add_argument("--audit-label", choices=["vulnerable", "patched"], default="vulnerable")
    task.add_argument("--audit-limit", type=int, default=1)
    task.add_argument("--claude-command", default="claude")
    task.add_argument("--claude-arg", action="append", default=[])
    task.add_argument("--audit-timeout", type=int, default=600)
    task.add_argument("--clone-timeout", type=int, default=600, help="per-repo clone timeout in seconds")
    task.add_argument("--clone-mode", choices=["mirror", "worktree"], default="worktree")
    task.add_argument("--filter-blobs", action=argparse.BooleanOptionalAction, default=True, help="use blobless clone in worktree mode")
    task.add_argument("--git-proxy", help="HTTP(S) proxy used only for git network commands")
    task.add_argument("--connect-timeout", type=int, default=30, help="git http.connectTimeout in seconds")
    task.set_defaults(func=cmd_run_repo_task)
    batch = sub.add_parser("run-task-batch", help="run run-repo-task sequentially for repos listed in a text file")
    batch.add_argument("--output", required=True)
    batch.add_argument("--repo-list", required=True, help="text file with one repo slug per line; blank lines and # comments are ignored")
    batch.add_argument("--continue-on-error", action=argparse.BooleanOptionalAction, default=True, help="continue to the next repo when a task exits non-zero")
    batch.add_argument("--min-pairs", type=int, default=1)
    batch.add_argument("--max-context-chars", type=int, default=24000)
    batch.add_argument("--large-context-hint-threshold", type=int, default=24000, help="prepend an audit hint when full selected context exceeds this many characters")
    batch.add_argument("--audit", action="store_true", help="run a real audit-harness call after validation")
    batch.add_argument("--audit-dry-run", action="store_true", help="prepare audit prompt(s) after validation")
    batch.add_argument("--audit-label", choices=["vulnerable", "patched"], default="vulnerable")
    batch.add_argument("--audit-limit", type=int, default=1)
    batch.add_argument("--claude-command", default="claude")
    batch.add_argument("--claude-arg", action="append", default=[])
    batch.add_argument("--audit-timeout", type=int, default=600)
    batch.add_argument("--clone-timeout", type=int, default=600, help="per-repo clone timeout in seconds")
    batch.add_argument("--clone-mode", choices=["mirror", "worktree"], default="worktree")
    batch.add_argument("--filter-blobs", action=argparse.BooleanOptionalAction, default=True, help="use blobless clone in worktree mode")
    batch.add_argument("--git-proxy", help="HTTP(S) proxy used only for git network commands")
    batch.add_argument("--connect-timeout", type=int, default=30, help="git http.connectTimeout in seconds")
    batch.set_defaults(func=cmd_run_task_batch)
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
