#!/usr/bin/env python3
"""Offline, disposable nuclei benchmark. The same file orchestrates and measures."""

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid

SCHEMA = 2
SAMPLES = 3
RATE = 500
CELL_TIMEOUT = 120
SUITE_TIMEOUT = 1200
LIMITS = {"cpus": 2, "memory_bytes": 1073741824, "pids": 128}
MATRIX = [
    {"templates": n, "targets": t, "concurrency": c, "rate": RATE}
    for n in (200, 1000, 3000) for t in (1, 4) for c in (10, 20, 50)
]
FLAGS = [
    "-silent", "-no-color", "-jsonl", "-omit-raw", "-omit-template",
    "-disable-clustering", "-disable-update-check", "-no-interactsh",
    "-disable-redirects", "-retries", "0", "-timeout", "5",
    "-no-httpx", "-no-stdin", "-bulk-size", "4",
    "-scan-strategy", "template-spray", "-rate-limit", str(RATE),
    "-auth=false", "-dashboard=false", "-cloud-upload=false",
]
COMMAND_FLAGS = FLAGS + [
    "-config", "{private_config}", "-templates", "{templates}",
    "-list", "{targets}", "-concurrency", "{concurrency}",
]


class BenchError(Exception):
    def __init__(self, message, **details):
        super().__init__(message)
        self.details = details


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def template_id(index):
    return "bench-%06d" % index


def request_path(index):
    return "/bench/%06d" % index


def marker(index):
    return "scan-bench-v2:%06d" % index


def template(index):
    return (
        f"id: {template_id(index)}\n"
        "info:\n"
        f"  name: {template_id(index)}\n"
        "  author: scan-bench\n  severity: info\n"
        "http:\n  - method: GET\n    redirects: false\n    path:\n"
        f'      - "{{{{BaseURL}}}}{request_path(index)}"\n'
        "    matchers-condition: and\n    matchers:\n"
        "      - type: status\n        status: [200]\n"
        "      - type: word\n        part: body\n        words:\n"
        f'          - "{marker(index)}"\n'
    )


def cell_key(cell):
    return "n{templates}-t{targets}-c{concurrency}".format(**cell)


def positive_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def validate_baseline(baseline, metadata):
    if not isinstance(baseline, dict) or baseline.get("schema_version") != SCHEMA:
        raise BenchError("Missing or incompatible baseline schema; use --update-baseline")
    if baseline.get("metadata") != metadata:
        old = baseline.get("metadata")
        old = old if isinstance(old, dict) else {}
        changed = sorted(k for k in set(metadata) | set(old)
                         if old.get(k) != metadata.get(k))
        raise BenchError("Incompatible baseline metadata; use --update-baseline",
                         mismatched_fields=changed)
    cells = baseline.get("cells")
    if not isinstance(cells, dict) or set(cells) != {cell_key(c) for c in MATRIX}:
        raise BenchError("Baseline matrix is incomplete or incompatible")
    for cell in MATRIX:
        key = cell_key(cell)
        entry = cells[key]
        if not isinstance(entry, dict) or entry.get("workload") != cell:
            raise BenchError("Invalid baseline workload", cell=key)
        samples = entry.get("samples")
        if not isinstance(samples, list) or len(samples) != SAMPLES:
            raise BenchError("Baseline must contain three validated samples", cell=key)
        for sample in samples:
            if not isinstance(sample, dict) or not positive_number(sample.get("seconds")):
                raise BenchError("Invalid baseline timing", cell=key)
            expected = cell["templates"] * cell["targets"]
            if (sample.get("returncode") != 0 or sample.get("validated") is not True
                    or sample.get("request_count") != expected
                    or sample.get("unique_pairs") != expected):
                raise BenchError("Baseline contains an unvalidated sample", cell=key)
        median = entry.get("median_seconds")
        if not positive_number(median) or median != statistics.median(s["seconds"] for s in samples):
            raise BenchError("Invalid baseline median", cell=key)
    return cells


def compare_cells(cells, baseline_cells, tolerance):
    comparisons = {}
    for key, entry in cells.items():
        previous = baseline_cells[key]["median_seconds"]
        delta = entry["median_seconds"] / previous - 1
        comparisons[key] = {"baseline_seconds": previous, "change_fraction": delta,
                            "regression": entry["median_seconds"] > previous * (1 + tolerance)}
    return comparisons


def validate_requests(counts, n, targets):
    expected = Counter({(t, "GET", request_path(i)): 1 for t in range(targets) for i in range(n)})
    if counts != expected:
        raise BenchError("Fixture request mismatch", expected_count=n * targets,
                         actual_count=sum(counts.values()),
                         missing=list((expected - counts).items())[:10],
                         extra=list((counts - expected).items())[:10])
    return sum(counts.values())


def validate_jsonl(path, n, origins):
    expected = {(template_id(i), origin + request_path(i))
                for origin in origins for i in range(n)}
    seen = set()
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                finding = json.loads(line)
                if not isinstance(finding, dict) or finding.get("type") != "http":
                    raise ValueError("not an HTTP finding")
                pair = (finding["template-id"], finding["matched-at"])
                if not all(isinstance(v, str) for v in pair):
                    raise ValueError("invalid pair types")
                if finding.get("matcher-status", True) is not True:
                    raise ValueError("unsuccessful matcher")
            except (ValueError, KeyError, TypeError) as exc:
                raise BenchError("Invalid nuclei JSONL", line=number, reason=str(exc)) from exc
            if pair not in expected or pair in seen:
                raise BenchError("Unexpected or duplicate nuclei pair", line=number, pair=pair)
            seen.add(pair)
    if seen != expected:
        raise BenchError("Missing nuclei pairs", expected_count=len(expected),
                         actual_count=len(seen), missing=sorted(expected - seen)[:10])
    return len(seen)


class Fixture:
    """One distinct OS-assigned loopback port per target; never probe over HTTP."""
    def __init__(self, n, targets):
        self.paths = {request_path(i): (marker(i) + "\n").encode() for i in range(n)}
        self.counts = Counter()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(32)
        self.servers = []
        self.threads = []
        self.origins = []
        fixture = self

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 256

            def process_request(self, request, address):
                fixture.slots.acquire()
                try:
                    super().process_request(request, address)
                except BaseException:
                    fixture.slots.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    fixture.slots.release()

            def get_request(self):
                request, address = super().get_request()
                request.settimeout(5)
                return request, address

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def parse_request(self):
                valid = super().parse_request()
                with fixture.lock:
                    fixture.counts[(self.server.target, self.command or "INVALID", self.path)] += 1
                return valid

            def do_GET(self):
                body = fixture.paths.get(self.path)
                self.send_response(200 if body is not None else 404)
                body = body if body is not None else b"not a benchmark path\n"
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        self.server_type = Server
        self.handler_type = Handler
        self.targets = targets

    def __enter__(self):
        try:
            for target in range(self.targets):
                server = self.server_type(("127.0.0.1", 0), self.handler_type)
                server.target = target
                self.servers.append(server)
                thread = threading.Thread(target=server.serve_forever,
                                          kwargs={"poll_interval": 0.05}, daemon=True)
                self.threads.append(thread)
                thread.start()
                self.origins.append("http://127.0.0.1:%d" % server.server_port)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def snapshot(self):
        with self.lock:
            return self.counts.copy()

    def __exit__(self, *args):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=1)


def clean_env(home):
    home.mkdir(mode=0o700)
    for name in ("cache", "config", "data"):
        (home / name).mkdir(mode=0o700)
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
            "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"), "TMPDIR": "/tmp", "LANG": "C.UTF-8",
            "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true"}


def collect_metadata(nuclei, work):
    env = clean_env(work / "version-home")
    version = subprocess.run([nuclei, "-version"], env=env, capture_output=True, text=True, timeout=15)
    match = re.search(r"Nuclei Engine Version:\s*(v[^\s]+)", version.stdout + version.stderr)
    if version.returncode or not match:
        raise BenchError("Cannot identify nuclei", returncode=version.returncode, stderr=version.stderr)
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    observed = {"cpus": int(quota) / int(period),
                "memory_bytes": int(Path("/sys/fs/cgroup/memory.max").read_text()),
                "pids": int(Path("/sys/fs/cgroup/pids.max").read_text())}
    if observed != LIMITS:
        raise BenchError("Container hardware limits do not match", observed=observed)
    cpu_models = sorted({line.split(":", 1)[1].strip()
                         for line in Path("/proc/cpuinfo").read_text().splitlines()
                         if line.startswith(("model name", "Hardware"))})
    workload = {"matrix": MATRIX, "samples": SAMPLES, "fixture_version": 2,
                "fixture_threads": 32, "http_version": "1.0", "connection": "close",
                "timing": "monotonic end-to-end nuclei process; fresh HOME per sample; no warmup",
                "cell_timeout_seconds": CELL_TIMEOUT, "suite_timeout_seconds": SUITE_TIMEOUT}
    digest = hashlib.sha256(canonical(workload).encode())
    for index in range(3000):
        digest.update(template(index).encode())
    return {"image_id": os.environ["SCAN_BENCH_IMAGE_ID"],
            "nuclei": {"version": match.group(1), "sha256": file_hash(Path(nuclei))},
            "harness_sha256": file_hash(Path(__file__)), "workload": workload,
            "workload_sha256": digest.hexdigest(), "flags": COMMAND_FLAGS,
            "hardware": {"limits": LIMITS, "architecture": platform.machine(),
                         "cpu_models": cpu_models, "host_logical_cpus": os.cpu_count(),
                         "kernel": platform.release()},
            "python_version": platform.python_version()}


def run_sample(nuclei, templates, cell, sample_index, output, work, deadline):
    key = cell_key(cell)
    name = "%s-s%d" % (key, sample_index + 1)
    sample_work = work / name
    sample_work.mkdir()
    env = clean_env(sample_work / "home")
    config = sample_work / "nuclei.yaml"
    config.write_text("{}\n")
    stdout_path = output / (name + ".jsonl")
    stderr_path = output / (name + ".stderr")
    counts_path = output / (name + ".requests.json")
    returncode = None
    timed_out = False
    with Fixture(cell["templates"], cell["targets"]) as fixture:
        targets = sample_work / "targets.txt"
        targets.write_text("\n".join(fixture.origins) + "\n")
        command = [nuclei] + FLAGS + ["-config", str(config), "-templates", str(templates),
                                     "-list", str(targets), "-concurrency", str(cell["concurrency"])]
        remaining = min(CELL_TIMEOUT, deadline - time.monotonic())
        if remaining <= 0:
            raise BenchError("Suite deadline exceeded", cell=key)
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            started = time.monotonic()
            try:
                result = subprocess.run(command, stdout=stdout, stderr=stderr, env=env,
                                        cwd=sample_work, timeout=remaining)
                returncode = result.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            elapsed = time.monotonic() - started
        counts = fixture.snapshot()
        origins = list(fixture.origins)
    write_json(counts_path, {"origins": origins, "requests": [
        {"target": t, "method": method, "path": path, "count": count}
        for (t, method, path), count in sorted(counts.items())]})
    details = {"cell": key, "sample": sample_index + 1, "returncode": returncode,
               "timed_out": timed_out, "stdout_file": stdout_path.name,
               "stderr_file": stderr_path.name, "requests_file": counts_path.name}
    try:
        if timed_out or returncode != 0:
            raise BenchError("Nuclei timed out" if timed_out else "Nuclei exited unsuccessfully")
        request_count = validate_requests(counts, cell["templates"], cell["targets"])
        unique_pairs = validate_jsonl(stdout_path, cell["templates"], origins)
    except BenchError as exc:
        raise BenchError(str(exc), **dict(details, **exc.details),
                         stderr=stderr_path.read_text(errors="replace")) from exc
    # Timings are exposed only after BOTH independent completeness checks pass.
    return {"seconds": elapsed, "returncode": returncode, "validated": True,
            "request_count": request_count, "unique_pairs": unique_pairs,
            "stdout_file": stdout_path.name, "stderr_file": stderr_path.name,
            "requests_file": counts_path.name}


def worker(args):
    output = Path("/output")
    report = {"schema_version": SCHEMA, "mode": args.mode, "status": "error", "cells": {}}
    started = time.monotonic()
    deadline = started + SUITE_TIMEOUT
    try:
        with tempfile.TemporaryDirectory(prefix="scan-bench-", dir="/tmp") as temporary:
            work = Path(temporary)
            nuclei = shutil.which("nuclei")
            if not nuclei:
                raise BenchError("Installed image has no nuclei executable")
            metadata = collect_metadata(nuclei, work)
            report["metadata"] = metadata
            baseline_cells = None
            if args.mode == "compare":
                baseline_cells = validate_baseline(json.loads(Path("/baseline.json").read_text()), metadata)
            matrix = MATRIX if args.mode != "validate" else [
                {"templates": 200, "targets": 1, "concurrency": 10, "rate": RATE},
                {"templates": 1000, "targets": 4, "concurrency": 50, "rate": RATE}]
            template_dirs = {}
            for n in sorted({c["templates"] for c in matrix}):
                directory = work / ("templates-%d" % n)
                directory.mkdir()
                for index in range(n):
                    (directory / (template_id(index) + ".yaml")).write_text(template(index))
                template_dirs[n] = directory
            for cell in matrix:
                report["cells"][cell_key(cell)] = {"workload": cell, "samples": []}
            for sample_index in range(1 if args.mode == "validate" else SAMPLES):
                for cell in matrix:
                    sample = run_sample(nuclei, template_dirs[cell["templates"]], cell,
                                        sample_index, output, work, deadline)
                    report["cells"][cell_key(cell)]["samples"].append(sample)
                    write_json(output / "progress.json", {"cell": cell_key(cell),
                               "sample": sample_index + 1, "validated": True})
            if args.mode != "validate":
                for entry in report["cells"].values():
                    entry["median_seconds"] = statistics.median(s["seconds"] for s in entry["samples"])
                # Also validate the entire candidate baseline before permitting an update.
                validate_baseline(report, metadata)
            report["status"] = "validated" if args.mode == "validate" else "passed"
            if baseline_cells is not None:
                comparisons = compare_cells(report["cells"], baseline_cells, args.tolerance)
                report["comparisons"] = comparisons
                report["tolerance"] = args.tolerance
                if any(c["regression"] for c in comparisons.values()):
                    report["status"] = "regression"
    except (BenchError, OSError, ValueError, subprocess.SubprocessError) as exc:
        report["error"] = {"message": str(exc), **getattr(exc, "details", {})}
    finally:
        report["suite_seconds"] = time.monotonic() - started
        write_json(output / "result.json", report)
    return 0 if report["status"] in ("passed", "validated") else 1


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="jingwei:1.5.0", help="already installed image; never pulled")
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp"),
                        help="existing parent outside the repository for a unique artifact directory")
    parser.add_argument("--baseline", type=Path,
                        default=Path(__file__).resolve().with_name("scan-bench-baseline.json"))
    parser.add_argument("--tolerance", type=float, default=0.6)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--update-baseline", action="store_true")
    modes.add_argument("--validate-only", action="store_true", help="assertion preflight; never writes a baseline")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=("compare", "update", "validate"), default="compare", help=argparse.SUPPRESS)
    return parser


def atomic_baseline(path, report):
    baseline = copy.deepcopy({key: report[key] for key in ("schema_version", "metadata", "cells")})
    baseline["created_at"] = datetime.now(timezone.utc).isoformat()
    for entry in baseline["cells"].values():
        entry["samples"] = [{k: v for k, v in sample.items() if not k.endswith("_file")}
                            for sample in entry["samples"]]
    validate_baseline(baseline, report["metadata"])
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=path.name + ".",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(baseline, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def host(args):
    harness = Path(__file__).resolve()
    repository = harness.parents[2]
    output = None
    report = {"schema_version": SCHEMA, "status": "error"}
    docker_rc = None
    try:
        if not math.isfinite(args.tolerance) or args.tolerance < 0:
            raise BenchError("Tolerance must be finite and nonnegative")
        parent = args.output_dir.resolve(strict=True)
        if not parent.is_dir() or parent == repository or repository in parent.parents:
            raise BenchError("Output directory must be outside the repository")
        output = Path(tempfile.mkdtemp(prefix="scan-bench-", dir=parent))
        baseline = args.baseline.resolve()
        mode = "update" if args.update_baseline else "validate" if args.validate_only else "compare"
        if not baseline.parent.is_dir():
            raise BenchError("Baseline parent directory must already exist")
        if mode == "compare" and not baseline.is_file():
            raise BenchError("Missing baseline; explicitly run --update-baseline")
        if any("," in str(path) for path in (harness, output, baseline)):
            raise BenchError("Docker bind mount paths cannot contain commas")
        inspected = subprocess.run(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
                                   capture_output=True, text=True, timeout=15)
        image_id = inspected.stdout.strip()
        if inspected.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise BenchError("Image must already be installed; pulling is prohibited",
                             returncode=inspected.returncode, stderr=inspected.stderr)
        name = "scan-bench-" + uuid.uuid4().hex
        cidfile = output / "container.cid"
        command = ["docker", "run", "--rm", "--pull=never", "--network=none", "--cpus=2",
                   "--memory=1g", "--memory-swap=1g", "--pids-limit=128", "--init", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--workdir", "/tmp",
                   "--name", name, "--cidfile", str(cidfile),
                   "--mount", f"type=bind,src={harness},dst=/scan-bench.py,readonly",
                   "--mount", f"type=bind,src={output},dst=/output"]
        if mode == "compare":
            command += ["--mount", f"type=bind,src={baseline},dst=/baseline.json,readonly"]
        # Clear even image-provided environment; never forward host keys, proxies or credentials.
        command += ["--entrypoint", "/usr/bin/env", image_id, "-i",
                    "PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
                    "SCAN_BENCH_IMAGE_ID=" + image_id, "python3", "-B", "/scan-bench.py",
                    "--worker", "--mode", mode, "--tolerance", str(args.tolerance)]
        try:
            with (output / "container.stdout").open("w") as stdout, (output / "container.stderr").open("w") as stderr:
                completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=SUITE_TIMEOUT + 60)
                docker_rc = completed.returncode
        finally:
            # Only our recorded disposable container can be stopped; no exec, pkill or live-container lookup.
            if cidfile.exists() and re.fullmatch(r"[0-9a-f]{64}", cidfile.read_text().strip()):
                subprocess.run(["docker", "stop", "--time", "5", cidfile.read_text().strip()],
                               capture_output=True, timeout=15)
        result_path = output / "result.json"
        if not result_path.is_file():
            raise BenchError("Container did not produce a result", returncode=docker_rc,
                             stderr=(output / "container.stderr").read_text(errors="replace"))
        report = json.loads(result_path.read_text())
        report["docker_returncode"] = docker_rc
        report["image_reference"] = args.image
        if docker_rc != 0 and report.get("status") in ("passed", "validated"):
            raise BenchError("Container exited unsuccessfully", returncode=docker_rc)
        if docker_rc == 0 and report.get("status") == "passed" and mode == "update":
            atomic_baseline(baseline, report)
            report["baseline_updated"] = str(baseline)
    except (BenchError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["status"] = "error"
        report["error"] = {"message": str(exc) or "Interrupted", **getattr(exc, "details", {})}
    report["artifact_dir"] = str(output) if output else None
    if output:
        write_json(output / "result.json", report)
    summary = {k: report[k] for k in ("status", "artifact_dir", "baseline_updated", "error") if k in report}
    print(json.dumps(summary, sort_keys=True))
    return 0 if docker_rc == 0 and report["status"] in ("passed", "validated") else 1


def interrupted(signum, frame):
    raise KeyboardInterrupt("Interrupted by signal %d" % signum)


if __name__ == "__main__":
    args = argument_parser().parse_args()
    if args.worker:
        sys.exit(worker(args))
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(host(args))
