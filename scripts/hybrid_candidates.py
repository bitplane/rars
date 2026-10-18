#!/usr/bin/env python3
"""Freeze, run and resume the finite experimental hybrid encoder matrix.

Standard library only. No builds, source changes, AI calls or network discovery
occur during a run. See scripts/hybrid/README.md for the manifest contract.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import random
import re
import shutil
import shlex
import signal
import socket
import stat
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

BITS = ("deeper_search", "multiple_states", "full_partitions", "automatic_filters",
        "optimize_member_order", "adaptive_dictionary")
PROFILES = ("desktop", "server")
SCHEMA = 1
BUDGETS = {"screen": 4 * 3600, "confirm": 12 * 3600}
REPETITIONS = 15
ROOT = Path(__file__).resolve().parents[1]


class RunError(Exception):
    pass


class SampleError(RunError):
    def __init__(self, message, control_failure=False):
        super().__init__(message)
        self.control_failure = control_failure


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise RunError("task wall-clock reservation exhausted")


def sha(path, deadline=None):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            check_deadline(deadline)
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    check_deadline(deadline)
    return h.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def relative_name(name):
    p = PurePosixPath(name)
    if (not name or not p.parts or p.is_absolute() or ".." in p.parts or str(p) != name
            or "\\" in name or "\n" in name or "\r" in name
            or p.parts[0].startswith(("-", "@"))):
        raise RunError(f"unsafe or non-canonical corpus path: {name!r}")
    return p


def choices(variant):
    if isinstance(variant, bool) or not isinstance(variant, int) or not 0 <= variant < 64:
        raise RunError("hybrid variant must be an integer in 0..63")
    return {name: bool(variant & (1 << bit)) for bit, name in enumerate(BITS)}


def configs(profiles):
    if not profiles or len(set(profiles)) != len(profiles) or set(profiles) - set(PROFILES):
        raise RunError("profiles must be distinct desktop/server values")
    return [{"id": f"{profile}-{variant:02d}", "profile": profile,
             "variant": variant, "choices": choices(variant)}
            for profile in profiles for variant in range(64)]


def inventory(value=None):
    hosts = value or [{"id": "local", "kind": "local", "hostname": socket.gethostname()}]
    if not hosts or len({h.get("id") for h in hosts}) != len(hosts):
        raise RunError("host inventory must have unique IDs")
    for host in hosts:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", host.get("id", "")):
            raise RunError("host IDs may contain letters, digits, underscore and dash")
        if host.get("kind") not in ("local", "export", "ssh") or not host.get("hostname"):
            raise RunError("hosts require explicit hostname and kind local/export/ssh; no discovery")
        if host["kind"] == "ssh":
            if not re.fullmatch(r"[A-Za-z0-9_.@-]+", host.get("ssh_target", "")) or host["ssh_target"].startswith("-"):
                raise RunError("SSH hosts require an explicit safe ssh_target")
            remote = host.get("remote_directory", "")
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", remote) or ".." in PurePosixPath(remote).parts:
                raise RunError("SSH remote_directory must be an absolute dedicated safe path")
            if not isinstance(host.get("port", 22), int) or not 1 <= host.get("port", 22) <= 65535:
                raise RunError("invalid SSH port")
    if len({h["hostname"] for h in hosts}) != len(hosts):
        raise RunError("a physical hostname may appear only once")
    return hosts


def snapshot_tree(directory, deadline=None):
    """Paths/content and the supported portable metadata, without following links."""
    result = {}
    for base, directories, files in os.walk(directory, followlinks=False):
        check_deadline(deadline)
        for name in list(directories):
            p = Path(base) / name
            if p.is_symlink():
                files.append(name)
                directories.remove(name)
            else:
                s = p.stat()
                result[p.relative_to(directory).as_posix()] = {
                    "type": "directory", "mode": stat.S_IMODE(s.st_mode), "mtime": int(s.st_mtime)}
        for name in files:
            check_deadline(deadline)
            p = Path(base) / name
            key = p.relative_to(directory).as_posix()
            s = p.lstat()
            if stat.S_ISLNK(s.st_mode):
                result[key] = {"type": "symlink", "target": os.readlink(p)}
            elif stat.S_ISREG(s.st_mode):
                result[key] = {"type": "file", "bytes": s.st_size, "sha256": sha(p, deadline),
                               "mode": stat.S_IMODE(s.st_mode), "mtime": int(s.st_mtime)}
            else:
                raise RunError(f"unsupported extracted object: {key}")
    return result


def validate_tree(actual, expected):
    normalized = dict(actual)
    for name, spec in expected.items():
        if spec.get("implicit_parent") and name in normalized:
            normalized[name] = {"type": normalized[name]["type"], "implicit_parent": True}
    if normalized != expected:
        keys = sorted(set(actual) | set(expected))
        wrong = [key for key in keys if normalized.get(key) != expected.get(key)]
        raise RunError("extracted path/content/supported-metadata mismatch: " + ", ".join(wrong[:8]))


def git_identity(repository):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()
    try:
        if git("status", "--porcelain", "--untracked-files=all"):
            raise RunError("freeze requires a clean committed source tree, including untracked files")
        return {"revision": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
                "dirty_diff_sha256": hashlib.sha256(git("diff", "HEAD", "--").encode()).hexdigest()}
    except (OSError, subprocess.CalledProcessError) as e:
        raise RunError("cannot freeze source revision; use a Git checkout") from e


def freeze(args):
    destination = args.output.resolve()
    if destination.exists():
        raise RunError("run directory already exists; resume it instead of replacing evidence")
    source = args.corpus.resolve()
    corpus = read_json(source)
    plan = read_json(args.plan) if args.plan else {}
    profiles = args.profile or ["desktop"]
    hosts = inventory(read_json(args.inventory) if args.inventory else None)
    budgets = {name: float(plan.get("budgets", {}).get(name, default)) for name, default in BUDGETS.items()}
    if any(not math.isfinite(v) or v <= 0 or v > BUDGETS[k] for k, v in budgets.items()):
        raise RunError("budgets must be positive and at most four screen/twelve confirmation host-hours")
    timeout = float(plan.get("task_timeout_seconds", 300))
    if not math.isfinite(timeout) or timeout <= 0:
        raise RunError("task timeout must be finite and positive")
    cold = plan.get("cold_prepare")
    if cold is not None:
        if (not isinstance(cold, list) or not cold
                or not all(isinstance(arg, str) and "\0" not in arg for arg in cold)):
            raise RunError("cold_prepare must be a nonempty executable argv array")
        executable = Path(cold[0])
        if (not executable.is_absolute() or not executable.is_file()
                or not os.access(executable, os.X_OK)):
            raise RunError("cold_prepare requires an absolute executable file")
        if executable.name in {"sh", "bash", "zsh", "dash", "fish", "csh", "tcsh", "env", "sudo", "doas", "cmd.exe", "powershell", "pwsh"}:
            raise RunError("cold_prepare must be a direct helper executable, not a shell/privilege/command wrapper")
    options = plan.get("worker_options", {})
    allowed = {"rars_add", "native_add", "rars_read", "native_read"}
    if set(options) - allowed or any(not isinstance(v, list) or not all(isinstance(x, str) for x in v)
                                     for v in options.values()):
        raise RunError("worker_options must contain documented arrays of argument strings")
    # The matrix owns these switches, to prevent silently relabelled bit choices.
    for channel, flags in options.items():
        for flag in flags:
            name = flag.split("=", 1)[0]
            owned = name in {"--dict-size", "--hybrid-dictionary-ceiling", "--threads", "--memory-limit", "--max-memory"}
            if channel == "rars_add":
                owned |= name in {"--experimental-hybrid", "--hybrid-variant", "--hybrid-architecture", "--analyze-relationships", "--optimize-member-order", "--auto-filter", "--no-filter"}
            if channel.startswith("native"):
                owned = flag.lower().startswith(("-md", "-mt"))
            if owned:
                raise RunError(f"matrix-owned switch in worker options: {flag}")
    entries = {item["path"]: item for item in corpus["files"] if item.get("measured", True)}
    if len(entries) != sum(item.get("measured", True) for item in corpus["files"]):
        raise RunError("duplicate measured corpus paths")
    source_identity = git_identity(args.repository)
    workloads = corpus.get("workloads") or [{"id": "corpus", "files": sorted(entries)}]
    if not workloads or len({w["id"] for w in workloads}) != len(workloads):
        raise RunError("corpus workloads must have unique IDs")
    destination.mkdir(parents=True)
    try:
        (destination / "frozen/bin").mkdir(parents=True)
        (destination / "frozen/input").mkdir()
        binaries = {}
        for role, path in (("candidate", args.rars), ("baseline", args.baseline or args.rars), ("native", args.native_rar)):
            path = path.resolve()
            target = destination / "frozen/bin" / role
            shutil.copy2(path, target)
            target.chmod(target.stat().st_mode | stat.S_IXUSR)
            binaries[role] = {"path": target.relative_to(destination).as_posix(), "sha256": sha(target),
                              "source": str(path), "bytes": target.stat().st_size}
        if cold is not None:
            target = destination / "frozen/bin/cold_prepare"
            shutil.copy2(Path(cold[0]).resolve(), target)
            target.chmod((target.stat().st_mode & 0o777) | stat.S_IXUSR)
            binaries["cold_prepare"] = {"path": target.relative_to(destination).as_posix(),
                "sha256": sha(target), "source": str(Path(cold[0]).resolve()), "bytes": target.stat().st_size}
        for name, item in entries.items():
            relative_name(name)
            original = source.parent / name
            if original.is_symlink() or not (original.is_file() or original.is_dir()):
                raise RunError(f"corpus hash/type mismatch: {name}")
            target = destination / "frozen/input" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if original.is_dir():
                target.mkdir(exist_ok=True)
            else:
                if sha(original) != item["sha256"]:
                    raise RunError(f"corpus hash/type mismatch: {name}")
                shutil.copy2(original, target)
                if sha(target) != item["sha256"]:
                    raise RunError(f"corpus changed while freezing: {name}")
        cases = []
        for work in workloads:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", work["id"]):
                raise RunError("case IDs must be safe directory names")
            staged = destination / "frozen/cases" / work["id"]
            staged.mkdir(parents=True)
            for name in work["files"]:
                if name not in entries:
                    raise RunError(f"workload references absent measured member: {name}")
                original = source.parent / name
                target = staged / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if original.is_dir():
                    target.mkdir(exist_ok=True)
                else:
                    shutil.copy2(destination / "frozen/input" / name, target)
            # Explicit directory arguments would otherwise recursively introduce
            # members outside a workload. Stage the exact subset, then pass
            # only requested paths, including explicit directory headers.
            directories = [p for p in staged.rglob("*") if p.is_dir()]
            for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
                shutil.copystat(source.parent / directory.relative_to(staged), directory)
            members = snapshot_tree(staged)
            explicit = set(work["files"])
            explicit_directories = {name for name in explicit if members[name]["type"] == "directory"}
            for name, record in list(members.items()):
                if record["type"] == "directory" and name not in explicit:
                    members[name] = {"type": "directory", "implicit_parent": True}
            arguments = [name for name in work["files"] if not any(
                parent.as_posix() in explicit_directories for parent in PurePosixPath(name).parents)]
            header_members = [name for name in members if name in explicit or any(
                parent.as_posix() in explicit_directories for parent in PurePosixPath(name).parents)]
            if not members:
                raise RunError("empty workloads are not benchmark samples")
            cases.append({"id": work["id"], "members": members,
                          "input_path": staged.relative_to(destination).as_posix(),
                          "archive_members": arguments, "header_members": header_members,
                          "solid": bool(work.get("solid", False))})
        for case in cases:
            case["control_settings"] = {profile: control_settings(profile, case) for profile in profiles}
        runner = destination / "frozen/hybrid_candidates.py"
        shutil.copy2(Path(__file__), runner)
        matrix = configs(profiles)
        invalid = [{"configuration": c["id"], "case": case["id"],
                    "code": "solid-filter-unsupported", "reason": "solid output does not support requested automatic/mandatory filters; excluded before child launch"}
                   for c in matrix for case in cases if case["solid"] and (mandatory_filter(options) or c["choices"]["automatic_filters"])]
        manifest = {"schema": SCHEMA, "source": source_identity,
                    "invalid_combinations": invalid,
                    "seed": int(args.seed), "profiles": profiles,
                    "host_platform": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version(), "logical_cpus": os.cpu_count()}, "configurations": matrix,
                    "cases": cases, "hosts": hosts, "budgets": budgets,
                    "cold_prepare": {"binary": "cold_prepare", "arguments": cold[1:]} if cold is not None else None,
                    "task_timeout_seconds": timeout, "worker_options": options,
                    "confirmation_repetitions": REPETITIONS, "max_finalists_per_profile": 3,
                    "promotion_control": "native; all four ranking metrics are within-task candidate/native ratios",
                    "control_roles": ["native", "baseline", "relationships", "streams", "native_ordered"],
                    "native_ordered_scope": "ordering-assisted native compression using the verified candidate member order and -ds; distinct from ordinary native control",
                    "screen_repetitions": 1, "binaries": binaries,
                    "corpus_manifest_sha256": sha(source), "corpus_source": str(source),
                    "runner_sha256": sha(runner), "metadata_scope": "all file/directory paths and types; regular bytes/SHA256 and explicitly requested member POSIX permissions/whole-second mtime; implicit parent directories path/type only; owner/group/xattrs/ACLs unmeasured",
                    "cold_scope": "operator-supplied cache preparation; system/global cache eviction is not verified" if cold is not None else "unavailable: no cache eviction performed; extraction measurements have uncontrolled cache state",
                    "budget_scope": "aggregate wall-clock task reservations including correctness work; fixed equal per-host shares; interrupted tasks charge their entire reserved timeout",
                    "rules": "No source mutation, build, AI invocation, auto-discovered SSH, byte-identity guard or size threshold. Only verified samples enter Pareto selection."}
        write_json(destination / "manifest.json", manifest)
        (destination / "manifest.sha256").write_text(sha(destination / "manifest.json") + "\n")
        (destination / "journal.jsonl").touch()
        return manifest
    except BaseException:
        # Keep the incomplete freeze so a failure never looks like a runnable run.
        (destination / "INIT_FAILED").write_text("Initialization failed; evidence retained. Use a new directory.\n")
        raise


def load(run):
    if (run / "INIT_FAILED").exists():
        raise RunError("incomplete failed initialization")
    if sha(run / "manifest.json") != (run / "manifest.sha256").read_text().strip():
        raise RunError("immutable manifest hash changed")
    m = read_json(run / "manifest.json")
    if m["schema"] != SCHEMA or m["configurations"] != configs(m["profiles"]):
        raise RunError("configuration matrix is not the frozen six-bit 64-way matrix")
    if m["confirmation_repetitions"] != 15 or m["max_finalists_per_profile"] != 3:
        raise RunError("confirmation contract changed")
    for b in m["binaries"].values():
        if sha(run / b["path"]) != b["sha256"]:
            raise RunError("frozen executable changed")
    if sha(run / "frozen/hybrid_candidates.py") != m["runner_sha256"]:
        raise RunError("frozen worker source changed")
    if sha(Path(__file__)) != m["runner_sha256"]:
        raise RunError("invoke this run with its frozen/hybrid_candidates.py; current runner source differs")
    return m


@contextlib.contextmanager
def locked(path, blocking=True):
    with Path(path).open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as e:
            raise RunError(f"another worker owns {path}") from e
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def journal(run):
    rows = []
    with (run / "journal.jsonl").open() as stream:
        for index, line in enumerate(stream):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RunError(f"torn journal line {index + 1}; preserve and repair before resuming") from e
    return rows


def append(run, value):
    with (run / "journal.jsonl").open("a") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def latest(rows):
    result = {}
    for row in rows:
        if "task_id" in row:
            result[row["task_id"]] = row
    return result


def task_id(task):
    return digest(task)[:24]


def host_for(m, task):
    # Keep one configuration's workload block and confirmation on one host.
    return m["hosts"][int(digest(task["configuration"]), 16) % len(m["hosts"])]["id"]


def tasks(m, phase, finalists=None):
    selections = m["configurations"] if phase == "screen" else [c for c in m["configurations"] if c["id"] in finalists]
    rng = random.Random(m["seed"] + (0 if phase == "screen" else 1))
    if phase == "screen":
        selections = list(selections)
        rng.shuffle(selections)
        generated = []
        for configuration in selections:
            cases = list(m["cases"])
            rng.shuffle(cases)
            generated.extend({"phase": phase, "configuration": configuration["id"],
                              "case": case["id"], "repetition": 0} for case in cases)
        return generated
    generated = [{"phase": phase, "configuration": c["id"], "case": case["id"], "repetition": rep}
                 for rep in range(-1, REPETITIONS) for case in m["cases"] for c in selections]
    ordered = []
    for repetition in range(-1, REPETITIONS):
        group = [t for t in generated if t["repetition"] == repetition]
        rng.shuffle(group)
        ordered.extend(group)
    return ordered


def consumed(rows, phase, host):
    accounting = [r for r in rows if r.get("event") == "phase-accounting" and r["phase"] == phase and r["host"] == host]
    covered = {identifier for r in accounting for identifier in r["covered_tasks"]}
    return sum(r["charged_seconds"] for r in accounting) + sum(
        row.get("charged_seconds", row.get("reserved_seconds", 0))
        for identifier, row in latest(rows).items() if identifier not in covered
        and row["task"]["phase"] == phase and row["host"] == host)


def available(m, rows, phase, host):
    return max(0.0, m["budgets"][phase] / len(m["hosts"]) - consumed(rows, phase, host))


def execute(command, cwd, area, label, deadline, environment):
    left = deadline - time.monotonic()
    if left <= 0:
        raise RunError("task wall-clock reservation exhausted")
    stdout, stderr = area / (label + ".stdout"), area / (label + ".stderr")
    start = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err,
                                   stdin=subprocess.DEVNULL, env=environment, start_new_session=True)
        timed_out = False
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(min(.01, max(.001, deadline - time.monotonic())))
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
            raise
        process.returncode = os.waitstatus_to_exitcode(status)
    wall = time.monotonic() - start
    if sys.platform == "darwin":
        rss = usage.ru_maxrss
    elif sys.platform.startswith(("linux", "freebsd")):
        rss = usage.ru_maxrss * 1024
    else:
        rss = None
    result = {"command": command, "exit": process.returncode, "timeout": timed_out,
              "wall_seconds": wall, "cpu_seconds": usage.ru_utime + usage.ru_stime,
              "peak_rss_bytes": rss, "filesystem_input_blocks": usage.ru_inblock,
              "filesystem_output_blocks": usage.ru_oublock,
              "io_bytes": None, "io_scope": "wait4 filesystem block counters; byte totals unavailable",
              "stdout": stdout.name, "stderr": stderr.name}
    write_json(area / (label + ".json"), result)
    if process.returncode:
        raise RunError(f"{label} exited {process.returncode}" + (" (timeout)" if timed_out else ""))
    return result


def mandatory_filter(options):
    names = {"--delta-filter", "--e8-filter", "--e8e9-filter", "--arm-filter", "--itanium-filter", "--rgb-filter", "--audio-filter"}
    return any(token.split("=", 1)[0] in names for token in options.get("rars_add", []))


def valid_cases(m, configuration):
    excluded = {r["case"] for r in m.get("invalid_combinations", []) if r["configuration"] == configuration}
    return {case["id"] for case in m["cases"]} - excluded


def control_settings(profile, case):
    if profile not in PROFILES:
        raise RunError("unknown control profile")
    sizes = [record["bytes"] for record in case["members"].values() if record["type"] == "file"]
    if any(isinstance(size, bool) or not isinstance(size, int) or size < 0 for size in sizes):
        raise RunError("control dictionary requires nonnegative frozen member sizes")
    reach = sum(sizes) if case["solid"] else max(sizes, default=0)
    ceiling = (4 if profile == "desktop" else 64) * 1024**2
    dictionary = min(ceiling, max(128 * 1024, 1 << max(0, reach - 1).bit_length()))
    return {"dictionary_reach_bytes": reach, "dictionary_bytes": dictionary,
            "dictionary_ceiling_bytes": ceiling, "encoder_threads": 1,
            "memory_limit_bytes": (256 * 1024**2 if profile == "desktop" else 8 * 1024**3)}


def compression_command(m, run, role, configuration, case, archive, member_order=None):
    binary_role = "native" if role == "native_ordered" else (role if role in m["binaries"] else "candidate")
    binary = str(run / m["binaries"][binary_role]["path"])
    opts = m["worker_options"]
    settings = control_settings(configuration["profile"], case)
    if role in ("native", "native_ordered"):
        return [binary, "a", "-idq", "-y", "-ma5", "-m3", f'-md{settings["dictionary_bytes"] // 1024}k', "-mt1",
                "-s" if case["solid"] else "-s-", *(["-ds", "-r-"] if role == "native_ordered" else []),
                *opts.get("native_add", []), str(archive), *(member_order if member_order is not None else case["archive_members"])]
    variant = configuration["variant"] & 15 if role == "streams" else configuration["variant"]
    result = [binary, "--threads", "1", "--progress", "never", "a", "--format", "rar50", "--level", "3",
              "--memory-limit", str(settings["memory_limit_bytes"]), "--max-memory", str(settings["memory_limit_bytes"])]
    if role == "baseline":
        result.extend(["--dict-size", str(settings["dictionary_bytes"])])
    if case["solid"]:
        result.append("--solid")
    result.extend(opts.get("rars_add", []))
    if role != "baseline":
        if not mandatory_filter(opts):
            result.append("--auto-filter" if variant & 8 else "--no-filter")
        architecture = {"candidate": "hybrid", "relationships": "relationships", "streams": "streams"}[role]
        result.extend(["--experimental-hybrid", configuration["profile"], "--hybrid-variant", str(variant),
                       "--hybrid-architecture", architecture])
        if role in ("candidate", "relationships"):
            result.append("--analyze-relationships")
        if role in ("candidate", "relationships") and variant & 16:
            result.append("--optimize-member-order")
    return [*result, str(archive), *case["archive_members"]]


def sample(run, m, task, deadline):
    check_deadline(deadline)
    identifier = task_id(task)
    area = run / "tasks" / identifier
    area.mkdir(parents=True, exist_ok=False)
    configuration = next(c for c in m["configurations"] if c["id"] == task["configuration"])
    case = next(c for c in m["cases"] if c["id"] == task["case"])
    for name, expected in case["members"].items():
        path = run / case["input_path"] / name
        if expected["type"] == "file" and sha(path, deadline) != expected["sha256"]:
            raise SampleError("frozen input changed: " + name, control_failure=True)
    try:
        validate_tree(snapshot_tree(run / case["input_path"], deadline), case["members"])
    except RunError as e:
        raise SampleError("frozen workload changed: " + str(e), control_failure=True) from e
    order = ["native", "baseline", "candidate", "relationships", "streams"]
    random.Random(m["seed"] ^ int(identifier, 16)).shuffle(order)
    result = {"task": task, "order": order, "roles": {},
              "host": {"hostname": socket.gethostname(), "system": platform.system(), "machine": platform.machine(), "python": platform.python_version(),
                       "load_before": os.getloadavg() if hasattr(os, "getloadavg") else None},
              "metadata_scope": m["metadata_scope"],
              "cold_scope": m["cold_scope"], "cold_extraction": None}
    env = {**os.environ, "LC_ALL": "C", "TZ": "UTC"}
    # Disable ambient knobs that would silently alter the frozen experiment.
    for key in list(env):
        if key.startswith("RARS_") or key.startswith("RAYON_"):
            del env[key]
    for role in order:
        try:
            run_role(run, m, task, configuration, case, area, deadline, env, result, role)
        except (RunError, OSError) as e:
            raise SampleError(str(e), control_failure=role in ("native", "baseline")) from e
    candidate_order = archive_order(run, m, area / "candidate.rar", area, "candidate-order", case, deadline, env)
    result["candidate_member_order"] = candidate_order
    result["order"].append("native_ordered")
    run_role(run, m, task, configuration, case, area, deadline, env, result, "native_ordered", candidate_order)
    actual_order = archive_order(run, m, area / "native_ordered.rar", area, "native-ordered-order", case, deadline, env)
    if actual_order != candidate_order:
        raise RunError("native assisted-order control did not preserve the candidate member sequence; no ordering-equivalence claim")
    result["roles"]["native_ordered"]["ordering_assisted"] = True
    result["roles"]["native_ordered"]["verified_member_order"] = actual_order
    if m.get("cold_prepare") is not None:
        result["cold_extraction"] = {role: data["cold_selective"] for role, data in result["roles"].items()}
    write_json(area / "result.json", result)
    return result


def archive_order(run, m, archive, area, label, case, deadline, environment):
    command = [str(run / m["binaries"]["native"]["path"]), "lb", "-p-", str(archive)]
    execute(command, area, area, label, deadline, environment)
    names = (area / (label + ".stdout")).read_text(encoding="utf-8", errors="strict").splitlines()
    names = [name.rstrip("/").replace("\\", "/") for name in names]
    if len(names) != len(set(names)) or set(names) != set(case["header_members"]):
        raise RunError("native bare listing does not exactly cover the already-extracted candidate paths")
    return names


def run_role(run, m, task, configuration, case, area, deadline, env, result, role, member_order=None):
    archive = area / (role + ".rar")
    encoded = execute(compression_command(m, run, role, configuration, case, archive, member_order),
                          run / case["input_path"], area, role + "-encode", deadline, env)
    data = {"encode": encoded, "archive_bytes": archive.stat().st_size,
            "archive_sha256": sha(archive, deadline), "decoders": {}}
    result["roles"][role] = data
    native_binary = str(run / m["binaries"]["native"]["path"])
    execute([native_binary, "lt", "-p-", str(archive)], area, area,
            role + "-actual-archive-metadata", deadline, env)
    data["actual_archive_metadata"] = role + "-actual-archive-metadata.stdout"
    data["format_scope"] = "native metadata retained verbatim; -ma5 does not imply a particular RAR5 compression algorithm version"
    for decoder in ("native", "candidate"):
        binary = str(run / m["binaries"][decoder]["path"])
        target = area / (role + "-by-" + decoder)
        target.mkdir()
        native = decoder == "native"
        extra = m["worker_options"].get("native_read" if native else "rars_read", [])
        test = [binary, "t", "-idq", "-p-", *extra, str(archive)] if native else [binary, "--threads", "1", "test", *extra, str(archive)]
        execute(test, area, area, role + "-" + decoder + "-integrity", deadline, env)
        command = [binary, "x", "-idq", "-y", "-p-", *extra, str(archive), str(target) + "/"] if native else [binary, "--threads", "1", "extract", *extra, str(archive), str(target)]
        decoded = execute(command, area, area, role + "-" + decoder + "-extract", deadline, env)
        tree = snapshot_tree(target, deadline)
        validate_tree(tree, case["members"])
        members_path = area / (role + "-" + decoder + "-members.json")
        write_json(members_path, tree)
        proof_path = area / (role + "-" + decoder + "-verified.json")
        write_json(proof_path, {"verified": True, "task_id": task_id(task),
                   "expected_tree_sha256": digest(case["members"]),
                   "members_json": members_path.name, "members_sha256": sha(members_path, deadline)})
        # Only this successfully verified, derived tree is removed. Its durable
        # proof and the archive remain; failed trees are left for investigation.
        shutil.rmtree(target)
        data["decoders"][decoder] = {"extract": decoded, "verified_members": len(tree),
                                      "cold_requested": False, "verification_receipt": proof_path.name,
                                      "verification_sha256": sha(proof_path, deadline),
                                      "successful_tree_removed": True}
    data["temporary_output_bytes"] = data["archive_bytes"] + 2 * sum(x.get("bytes", 0) for x in case["members"].values())
    data["temporary_io_scope"] = "materialized archive plus two extracted regular-file trees; not a kernel I/O byte counter or transient peak"
    data["cold_selective"] = cold_selective(run, m, task, case, area, archive, role, data["archive_sha256"], deadline, env)
    if data["cold_selective"] and data["cold_selective"]["available"]:
        data["temporary_output_bytes"] += case["members"][data["cold_selective"]["requested_member"]]["bytes"]
        data["temporary_io_scope"] += "; includes the additional verified selective tree; helper I/O is not inferred"


def cold_selective(run, m, task, case, area, archive, role, archive_sha256, deadline, environment):
    preparation = m.get("cold_prepare")
    if preparation is None:
        return None
    files = sorted(name for name, record in case["members"].items() if record["type"] == "file")
    if not files:
        return {"available": False, "reason": "workload has no requested regular member", "scope": m["cold_scope"]}
    selected = files[-1]
    expected = {selected: case["members"][selected]}
    for parent in PurePosixPath(selected).parents:
        if parent != PurePosixPath("."):
            expected[parent.as_posix()] = {"type": "directory", "implicit_parent": True}
    command = [str(run / m["binaries"][preparation["binary"]]["path"]),
               *(str(archive) if arg == "{archive}" else arg for arg in preparation["arguments"])]
    prepared = execute(command, area, area, role + "-cold-prepare", deadline, environment)
    target = area / (role + "-cold-selective")
    target.mkdir()
    native = str(run / m["binaries"]["native"]["path"])
    extraction = execute([native, "x", "-idq", "-y", "-p-", *m["worker_options"].get("native_read", []),
                          str(archive), selected, str(target) + "/"],
                         area, area, role + "-cold-selective-extract", deadline, environment)
    actual = snapshot_tree(target, deadline)
    validate_tree(actual, expected)
    # Check afterward: reading the archive before extraction would undermine
    # the operator's preparation. Mutation never becomes a valid measurement.
    if sha(archive, deadline) != archive_sha256:
        raise RunError("cache preparation changed the measured archive")
    members_path = area / (role + "-cold-selective-members.json")
    write_json(members_path, actual)
    proof = area / (role + "-cold-selective-verified.json")
    write_json(proof, {"verified": True, "task_id": task_id(task), "requested_member": selected,
                      "expected_tree_sha256": digest(expected), "members_json": members_path.name,
                      "members_sha256": sha(members_path, deadline)})
    shutil.rmtree(target)
    return {"available": True, "scope": m["cold_scope"], "requested_member": selected,
            "preparation": prepared, "extract": extraction,
            "verification_receipt": proof.name, "verification_sha256": sha(proof, deadline),
            "successful_tree_removed": True}

def verified_results(run, rows, phase):
    result = []
    for row in latest(rows).values():
        if row["task"]["phase"] != phase or row.get("event") != "complete":
            continue
        path = run / row["result"]
        if sha(path) != row["result_sha256"]:
            raise RunError("completed task receipt changed")
        value = read_json(path)
        for role in value["roles"].values():
            records = list(role.get("decoders", {}).values())
            cold_record = role.get("cold_selective")
            if cold_record and cold_record.get("available"):
                records.append(cold_record)
            for decoded in records:
                if "verification_receipt" in decoded:
                    proof = path.parent / decoded["verification_receipt"]
                    if sha(proof) != decoded["verification_sha256"]:
                        raise RunError("verification receipt changed")
                    record = read_json(proof)
                    if not record["verified"] or sha(path.parent / record["members_json"]) != record["members_sha256"]:
                        raise RunError("verified member proof changed")
        result.append(value)
    return result


def aggregate(samples, relative=False):
    """Equal weight per workload, then geometric mean across workloads."""
    by_case = {}
    for sample_row in samples:
        if sample_row["task"]["repetition"] < 0:
            continue
        role = sample_row["roles"]["candidate"]
        metric = [role["encode"]["wall_seconds"], role["archive_bytes"], role["encode"]["peak_rss_bytes"],
                  role["decoders"]["candidate"]["extract"]["wall_seconds"]]
        if relative:
            control = sample_row["roles"]["native"]
            denominator = [control["encode"]["wall_seconds"], control["archive_bytes"], control["encode"]["peak_rss_bytes"],
                           control["decoders"]["candidate"]["extract"]["wall_seconds"]]
            if any(x is None or x <= 0 for x in metric + denominator):
                raise RunError("paired native promotion metric unavailable")
            metric = [a / b for a, b in zip(metric, denominator)]
        if any(x is None or x <= 0 for x in metric):
            raise RunError("Pareto metric unavailable; sample cannot be ranked")
        by_case.setdefault(sample_row["task"]["case"], []).append(metric)
    medians = [[statistics.median(values[i] for values in rows) for i in range(4)] for rows in by_case.values()]
    return [math.exp(statistics.mean(math.log(row[i]) for row in medians)) for i in range(4)]


def choose_finalists(run, m, rows):
    samples = verified_results(run, rows, "screen")
    grouped = {}
    for row in samples:
        grouped.setdefault(row["task"]["configuration"], []).append(row)
    eligible, unranked = {}, {}
    coverage = {c["id"]: {"valid_workloads": sorted(valid_cases(m, c["id"])),
                           "verified_workloads": sorted(x["task"]["case"] for x in grouped.get(c["id"], [])),
                           "inapplicable": [r for r in m.get("invalid_combinations", []) if r["configuration"] == c["id"]]}
                for c in m["configurations"]}
    for key, value in grouped.items():
        required = valid_cases(m, key)
        if not required or {x["task"]["case"] for x in value} != required:
            continue
        try:
            eligible[key] = aggregate(value, relative=True)
        except RunError as e:
            unranked[key] = str(e)
    selected = []
    for profile in m["profiles"]:
        comparable = {}
        for key, metric in eligible.items():
            if key.startswith(profile + "-"):
                signature = tuple(sorted(valid_cases(m, key)))
                comparable.setdefault(signature, {})[key] = metric
        frontiers = []
        for signature in sorted(comparable, key=lambda cases: (-len(cases), cases)):
            candidates = comparable[signature]
            frontier = [key for key, metric in candidates.items() if not any(
                all(a <= b for a, b in zip(other, metric)) and any(a < b for a, b in zip(other, metric))
                for other_key, other in candidates.items() if other_key != key)]
            # Ratios are comparable only across identical valid workloads.
            minima = [min(v[i] for v in candidates.values()) for i in range(4)]
            frontier.sort(key=lambda key: (sum(math.log(x / low) for x, low in zip(candidates[key], minima)), key))
            frontiers.append(frontier)
        promoted = []
        for rank in range(max(map(len, frontiers), default=0)):
            for frontier in frontiers:
                if rank < len(frontier) and len(promoted) < 3:
                    promoted.append(frontier[rank])
            if len(promoted) == 3:
                break
        selected.extend(promoted)
    return {"manifest_sha256": sha(run / "manifest.json"), "finalists": selected,
            "screen_metrics": eligible, "eligible_configurations": len(eligible), "unranked": unranked, "coverage": coverage,
            "rule": "four-dimensional non-dominance of within-host/task candidate/native ratios (encode wall, archive bytes, encode RSS, rars extraction wall); compare and sum-log rank only identical valid-workload signatures, then round-robin groups by descending coverage and stable signature; at most three per profile; equal workload weight"}


def worker(run, host_id, max_tasks=None):
    run = run.resolve()
    m = load(run)
    host = next((h for h in m["hosts"] if h["id"] == host_id), None)
    if host is None or host["hostname"] != socket.gethostname():
        raise RunError("worker hostname does not match explicit frozen inventory")
    lock = Path(tempfile.gettempdir()) / ("rars-hybrid-" + str(os.getuid()) + "-" + digest(socket.gethostname())[:16] + ".lock")
    count = 0
    with locked(lock, blocking=False):
        if any(r.get("control_failure") for r in journal(run)):
            raise RunError("a retained control failure blocks this run; use a new frozen run after repairing its cause")
        for phase in ("screen", "confirm"):
            phase_start = time.monotonic()
            starting_charge = consumed(journal(run), phase, host_id)
            phase_deadline = phase_start + max(0, m["budgets"][phase] / len(m["hosts"]) - starting_charge)
            attempted = []
            try:
                with locked(run / "journal.lock"):
                    rows = journal(run)
                    if phase == "confirm":
                        selection_file = run / "selection.json"
                        if not selection_file.exists():
                            done_hosts = {r["host"] for r in rows if r.get("event") == "phase-done" and r.get("phase") == "screen"}
                            if done_hosts != {h["id"] for h in m["hosts"]}:
                                return {"status": "waiting-for-screen-workers", "tasks_run": count}
                            write_json(selection_file, choose_finalists(run, m, rows))
                        selection = read_json(selection_file)
                        if selection["manifest_sha256"] != sha(run / "manifest.json"):
                            raise RunError("selection belongs to a different immutable run")
                        finalists = selection["finalists"]
                        known = {c["id"] for c in m["configurations"]}
                        if (len(finalists) != len(set(finalists)) or set(finalists) - known
                                or any(sum(name.startswith(profile + "-") for name in finalists) > 3 for profile in m["profiles"])):
                            raise RunError("confirmation selection exceeds the frozen configuration/profile limits")
                        generated = tasks(m, phase, finalists)
                    else:
                        generated = tasks(m, phase)
                for task in generated:
                    if host_for(m, task) != host_id:
                        continue
                    invalid = next((r for r in m.get("invalid_combinations", []) if r["configuration"] == task["configuration"] and r["case"] == task["case"]), None)
                    if invalid is not None:
                        with locked(run / "journal.lock"):
                            if task_id(task) not in latest(journal(run)):
                                append(run, {"event": "excluded", "task": task, "task_id": task_id(task), "host": host_id,
                                             "charged_seconds": 0, "pre_dispatch": True, **invalid})
                        continue
                    if time.monotonic() >= phase_deadline:
                        break
                    with locked(run / "journal.lock"):
                        rows = journal(run)
                        if task_id(task) in latest(rows):
                            continue
                        failed = {r["task"]["configuration"] for r in latest(rows).values() if r["event"] == "failed"}
                        if task["configuration"] in failed:
                            append(run, {"event": "excluded", "task": task, "task_id": task_id(task), "host": host_id,
                                         "charged_seconds": 0, "reason": "configuration has a failed correctness sample"})
                            continue
                        begin = time.monotonic()
                        deadline = min(begin + m["task_timeout_seconds"], phase_deadline)
                        if deadline <= begin:
                            break
                        started = {"event": "started", "task": task, "task_id": task_id(task), "host": host_id,
                                   "reserved_seconds": deadline - begin, "manifest_sha256": sha(run / "manifest.json")}
                        append(run, started)
                        attempted.append(task_id(task))
                    try:
                        sample(run, m, task, deadline)
                        path = run / "tasks" / task_id(task) / "result.json"
                        completed = {**started, "event": "complete", "result": str(path.relative_to(run)), "result_sha256": sha(path, deadline)}
                    except (RunError, OSError) as e:
                        completed = {**started, "event": "failed", "error": str(e),
                                     "control_failure": bool(getattr(e, "control_failure", False))}
                    completed["charged_seconds"] = time.monotonic() - begin
                    with locked(run / "journal.lock"):
                        append(run, completed)
                    count += 1
                    if completed.get("control_failure"):
                        raise RunError("control failed; run stopped, receipt retained: " + completed["error"])
                    if max_tasks is not None and count >= max_tasks:
                        return {"status": "paused-at-task-boundary", "tasks_run": count}
                with locked(run / "journal.lock"):
                    if not any(r.get("event") == "phase-done" and r.get("phase") == phase and r.get("host") == host_id for r in journal(run)):
                        append(run, {"event": "phase-done", "phase": phase, "host": host_id})
            finally:
                with locked(run / "journal.lock"):
                    states = latest(journal(run))
                    covered = [identifier for identifier in attempted if states[identifier]["event"] != "started"]
                    append(run, {"event": "phase-accounting", "id": uuid.uuid4().hex, "phase": phase, "host": host_id,
                                 "charged_seconds": time.monotonic() - phase_start, "covered_tasks": covered})
    return {"status": "finished-or-budget-exhausted", "tasks_run": count}


def paired_controls(samples):
    result = {}
    for case in sorted({x["task"]["case"] for x in samples}):
        chosen = [x for x in samples if x["task"]["case"] == case and x["task"]["repetition"] >= 0]
        result[case] = {}
        for control in ("baseline", "native", "relationships", "streams", "native_ordered"):
            ratios = {}
            for metric in ("wall_seconds", "cpu_seconds", "peak_rss_bytes"):
                values = [x["roles"]["candidate"]["encode"][metric] / x["roles"][control]["encode"][metric]
                          for x in chosen if x["roles"][control]["encode"][metric] and x["roles"]["candidate"]["encode"][metric] is not None]
                ratios[metric] = {"median_ratio": statistics.median(values) if values else None, "paired_ratios": values}
            ratios["archive_bytes"] = {"paired_ratios": [x["roles"]["candidate"]["archive_bytes"] / x["roles"][control]["archive_bytes"] for x in chosen]}
            result[case][control] = ratios
    return result


def absolute_frontiers(samples):
    grouped = {}
    for sample_row in samples:
        key = sample_row["task"]["case"] + "@" + sample_row.get("host", {}).get("hostname", "unrecorded-host")
        grouped.setdefault(key, {}).setdefault(sample_row["task"]["configuration"], []).append(sample_row)
    result = {}
    for key, configurations in grouped.items():
        metrics = {name: aggregate(rows) for name, rows in configurations.items()}
        frontier = [name for name, metric in metrics.items() if not any(
            all(a <= b for a, b in zip(other, metric)) and any(a < b for a, b in zip(other, metric))
            for other_name, other in metrics.items() if other_name != name)]
        result[key] = {"absolute_candidate_metrics": metrics, "frontier": sorted(frontier),
                       "scope": "within-workload/host absolute measurements; not cross-host promotion scores"}
    return result


def report(run):
    m = load(run)
    rows = journal(run)
    events = list(latest(rows).values())
    result = {"manifest_sha256": sha(run / "manifest.json"), "tasks": {name: sum(x["event"] == name for x in events) for name in ("started", "complete", "failed", "excluded")},
              "budget_seconds": {phase: {h["id"]: {"charged": consumed(rows, phase, h["id"]), "remaining": available(m, rows, phase, h["id"])} for h in m["hosts"]} for phase in BUDGETS},
              "selection": read_json(run / "selection.json") if (run / "selection.json").exists() else None,
              "predeclared_invalid_combinations": m.get("invalid_combinations", []),
              "absolute_screen_frontiers": absolute_frontiers(verified_results(run, rows, "screen")),
              "scope": "Partial runs and failed/incomplete confirmations are not qualified finalists. No byte identity, size percentage or native-parity acceptance is inferred."}
    confirmations = verified_results(run, rows, "confirm")
    grouped = {}
    for item in confirmations:
        if item["task"]["repetition"] >= 0:
            grouped.setdefault(item["task"]["configuration"], []).append(item)
    result["qualified_finalists"] = {key: {"metrics": aggregate(samples), "applicable_workloads": sorted(valid_cases(m, key)), "paired_repetitions_per_case": 15, "paired_controls": paired_controls(samples)}
        for key, samples in grouped.items() if valid_cases(m, key) and all(
            {x["task"]["repetition"] for x in samples if x["task"]["case"] == case["id"]} == set(range(15))
            for case in m["cases"] if case["id"] in valid_cases(m, key))}
    return result


def export_worker(run, host_id, output):
    m = load(run)
    if host_id not in {h["id"] for h in m["hosts"]}:
        raise RunError("worker is absent from explicit inventory")
    if output.exists():
        raise RunError("worker bundle destination exists")
    with tarfile.open(output, "w:gz") as archive:
        for name in ("manifest.json", "manifest.sha256", "journal.jsonl", "selection.json", "frozen"):
            path = run / name
            if path.exists():
                archive.add(path, arcname="hybrid-run/" + name)
        for path in (run / "tasks").glob("*/*") if (run / "tasks").exists() else []:
            if path.is_file() and path.suffix in (".json", ".stdout", ".stderr"):
                archive.add(path, arcname="hybrid-run/" + path.relative_to(run).as_posix())
    return {"bundle": str(output), "sha256": sha(output), "host": host_id,
            "command": f"python3 hybrid-run/frozen/hybrid_candidates.py run hybrid-run --host {host_id}",
            "scope": "Only this host's deterministic tasks and fixed budget share execute; no automatic SSH"}


def import_results(run, source):
    """Merge exported worker receipts without extracting untrusted tar paths."""
    m = load(run)
    other = load(source)
    if digest(m) != digest(other):
        raise RunError("worker results belong to a different frozen experiment")
    added = 0
    with locked(run / "journal.lock"):
        own = journal(run)
        known = latest(own)
        for row in latest(journal(source)).values():
            if row["host"] not in {h["id"] for h in m["hosts"]} or host_for(m, row["task"]) != row["host"]:
                raise RunError("receipt has the wrong deterministic host assignment")
            expected_id = task_id(row["task"])
            if row["task_id"] != expected_id:
                raise RunError("invalid task ID")
            if expected_id in known:
                if known[expected_id] != row:
                    raise RunError("conflicting receipt for an existing task")
                continue
            if row["event"] == "complete":
                expected_path = "tasks/" + expected_id + "/result.json"
                if row["result"] != expected_path or sha(source / expected_path) != row["result_sha256"]:
                    raise RunError("invalid completed receipt path/hash")
                result = read_json(source / expected_path)
                if result["task"] != row["task"]:
                    raise RunError("receipt task mismatch")
            src = source / "tasks" / expected_id
            dst = run / "tasks" / expected_id
            dst.mkdir(parents=True, exist_ok=False)
            for path in src.iterdir() if src.exists() else []:
                if path.is_file() and not path.is_symlink() and path.suffix in (".json", ".stdout", ".stderr"):
                    shutil.copy2(path, dst / path.name)
            append(run, row)
            known[expected_id] = row
            added += 1
        for row in journal(source):
            if row.get("event") in ("phase-done", "phase-accounting") and row not in own:
                append(run, row)
    return {"imported_tasks": added}


def ssh_argv(host, command):
    """Only the explicitly inventoried destination; never a local shell."""
    inventory([host])
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-p", str(host.get("port", 22)),
            "--", host["ssh_target"], command]


def checked_command(command):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if result.returncode:
        raise RunError(f"explicit worker transport failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def unpack_bundle(bundle, destination):
    """Reject links/devices/traversal before copying returned worker records."""
    with tarfile.open(bundle) as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "hybrid-run" or not (member.isdir() or member.isfile()):
                raise RunError("unsafe worker bundle member")
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as src, path.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(member.mode & 0o777)


def dispatch_ssh(run, host):
    m = load(run)
    # Repeating a failed transport uses the same remote state, so already
    # completed remote work is resumed/imported rather than silently discarded.
    token = sha(run / "manifest.json")[:16] + "-" + sha(run / "journal.jsonl")[:16]
    remote = host["remote_directory"].rstrip("/") + "/" + token
    local = run / "transport" / host["id"] / token
    local.mkdir(parents=True, exist_ok=True)
    bundle = local / "worker.tar.gz"
    if not bundle.exists():
        export_worker(run, host["id"], bundle)
    checked_command(ssh_argv(host, "mkdir -p " + shlex.quote(remote)))
    scp = ["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-P", str(host.get("port", 22)), "--"]
    checked_command([*scp, str(bundle), host["ssh_target"] + ":" + remote + "/worker.tar.gz"])
    worker = remote + "/hybrid-run/frozen/hybrid_candidates.py"
    state = remote + "/hybrid-run"
    command = ("test -f " + shlex.quote(state + "/manifest.json") + " || tar -xzf " +
               shlex.quote(remote + "/worker.tar.gz") + " -C " + shlex.quote(remote))
    checked_command(ssh_argv(host, command))
    # Export even after a worker error, retaining typed failure receipts.
    run_command = shlex.join(["python3", worker, "run", state, "--host", host["id"]])
    export_command = shlex.join(["python3", worker, "export-worker", state, "--host", host["id"], "--output", remote + "/results.tar.gz"])
    completed = subprocess.run(ssh_argv(host, run_command), stdin=subprocess.DEVNULL, capture_output=True, text=True)
    checked_command(ssh_argv(host, "test -f " + shlex.quote(remote + "/results.tar.gz") + " || " + export_command))
    checked_command([*scp, host["ssh_target"] + ":" + remote + "/results.tar.gz", str(local / "results.tar.gz")])
    returned = local / "returned"
    if not returned.exists():
        returned.mkdir()
        unpack_bundle(local / "results.tar.gz", returned)
    imported = import_results(run, returned / "hybrid-run")
    output = completed.stdout
    write_json(local / "transport.json", {"manifest_sha256": sha(run / "manifest.json"),
               "host": host, "remote": remote, "worker_stdout": output, **imported})
    if completed.returncode:
        raise RunError("SSH worker failed; returned receipts retained and imported: " + completed.stderr[-1000:])
    return imported


def dispatch(run):
    m = load(run)
    responses = []
    def dispatch_host(host):
        if host["kind"] == "local":
            return {"host": host["id"], **worker(run, host["id"])}
        if host["kind"] == "ssh":
            return {"host": host["id"], **dispatch_ssh(run, host)}
        return {"host": host["id"], "status": "export-worker and import-results required; no undisclosed SSH destination"}
    for _ in range(2):  # screen/merge, then frozen confirmation/merge
        # Each physical host retains its own worker lock and budget. Join the
        # entire phase before selection, retaining inventory order in receipts.
        with ThreadPoolExecutor(max_workers=len(m["hosts"])) as pool:
            responses.extend(pool.map(dispatch_host, m["hosts"]))
        rows = journal(run)
        if {r["host"] for r in rows if r.get("event") == "phase-done" and r.get("phase") == "screen"} == {h["id"] for h in m["hosts"]}:
            if not (run / "selection.json").exists():
                write_json(run / "selection.json", choose_finalists(run, m, rows))
    return {"workers": responses, "summary": report(run)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--rars", type=Path, required=True)
    init.add_argument("--baseline", type=Path, help="ordinary rars control; defaults to the same frozen executable without hybrid flags")
    init.add_argument("--native-rar", type=Path, required=True)
    init.add_argument("--corpus", type=Path, required=True)
    init.add_argument("--profile", choices=PROFILES, action="append")
    init.add_argument("--repository", type=Path, default=ROOT)
    init.add_argument("--seed", type=int, default=20261017)
    init.add_argument("--plan", type=Path, help="optional JSON worker_options, cold_prepare argv, timeouts and reduced budgets")
    init.add_argument("--inventory", type=Path, help="explicit local/SSH/export host array; otherwise this host only")
    run = sub.add_parser("run")
    run.add_argument("directory", type=Path)
    run.add_argument("--host", default="local")
    run.add_argument("--max-tasks", type=int, help="pause after this many tasks, without changing the frozen experiment")
    status = sub.add_parser("status")
    status.add_argument("directory", type=Path)
    export = sub.add_parser("export-worker")
    export.add_argument("directory", type=Path)
    export.add_argument("--host", required=True)
    export.add_argument("--output", type=Path, required=True)
    imported = sub.add_parser("import-results")
    imported.add_argument("directory", type=Path)
    imported.add_argument("--from-directory", type=Path, required=True)
    dispatched = sub.add_parser("dispatch", help="run only explicitly inventoried local/SSH workers; never discover hosts")
    dispatched.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = freeze(args)
        elif args.command == "run":
            if args.max_tasks is not None and args.max_tasks <= 0:
                raise RunError("max-tasks must be positive")
            result = worker(args.directory, args.host, args.max_tasks)
        elif args.command == "status":
            result = report(args.directory.resolve())
        elif args.command == "import-results":
            result = import_results(args.directory.resolve(), args.from_directory.resolve())
        elif args.command == "dispatch":
            result = dispatch(args.directory.resolve())
        else:
            result = export_worker(args.directory.resolve(), args.host, args.output.resolve())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (RunError, OSError, ValueError, KeyError) as e:
        print(f"hybrid runner: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
