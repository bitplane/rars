#!/usr/bin/env python3
"""Untimed, fresh-directory native correctness smoke for supplied executables.

Usage: python3 scripts/hybrid/native_smoke.py --candidate /path/to/rars
       --native /path/to/rar --out /path/to/fresh-report.json

The output report and its adjacent artifacts directory must not already exist.
This checks correctness only and records exact commands; it makes no speed claim.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

STAMP = 1_700_000_002
PASSWORD = "hybrid-smoke-fixture-only"


def sha(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def noise(size):
    state = 0x6D2B79F5
    out = bytearray()
    for _ in range(size):
        state = (state * 1_664_525 + 1_013_904_223) & 0xFFFFFFFF
        out.append(state >> 24)
    return bytes(out)


def fixture(root):
    duplicate = (b"independent duplicate content\n" * 113)
    values = {
        "flat/alpha.txt": ((b"a deterministic native correctness window ABCDEFGH\n" * 6000)[:262_161], 0o640),
        "flat/dup-a.bin": (duplicate, 0o600),
        "flat/dup-b.bin": (duplicate, 0o600),
        "flat/empty": (b"", 0o640),
        "tree/a.txt": (b"nested metadata and bytes\n" * 73, 0o640),
        "tree/nested/run.sh": (b"#!/bin/sh\nprintf '%s\\n' fixture\n", 0o751),
        "tree/nested/copy-a.bin": (duplicate, 0o600),
        "tree/nested/copy-b.bin": (duplicate, 0o600),
        "delta.bin": (b"".join(bytes((n & 255, (n >> 8) & 255, 7, 19)) for n in range(8192)), 0o640),
        "x86.bin": (b"".join(b"\xe8" + ((0x1000 - n * 5) & 0xFFFFFFFF).to_bytes(4, "little") + b"\x90" * 3 for n in range(4096)), 0o640),
        "continuation-e8.bin": (b"".join(b"\xe8" + ((0x1000 - n * 5) & 0xFFFFFFFF).to_bytes(4, "little") + b"\x90" * 3 for n in range(38_400)), 0o640),
        "arm.bin": (b"".join((0xEB000100 + n).to_bytes(4, "little") for n in range(8192)), 0o640),
        "solid-a.bin": ((b"solid predecessor with an unaligned repeat period ABCDEFGH\n" * 997), 0o640),
        "solid-b.bin": ((b"solid predecessor with an unaligned repeat period ABCDEFGH\n" * 997), 0o640),
        "volume.bin": (noise(40 * 1024), 0o640),
    }
    for name, (data, mode) in values.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        os.utime(path, ns=(STAMP * 10**9, STAMP * 10**9))
    for directory in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        directory.chmod(0o750)
        os.utime(directory, ns=(STAMP * 10**9, STAMP * 10**9))


def requested(root, names):
    paths = set()
    for name in names:
        source = root / name
        paths.add(source)
        if source.is_dir():
            paths.update(source.rglob("*"))
    result = {}
    for path in sorted(paths):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        item = {"type": "directory" if path.is_dir() else "file", "mode": stat.S_IMODE(info.st_mode),
                "mtime_ns": info.st_mtime_ns}
        if path.is_file():
            item.update(bytes=info.st_size, sha256=sha(path))
        result[name] = item
    # Synthesized parent directories have no requested header metadata.
    for name in list(result):
        parent=Path(name).parent
        while parent != Path('.'):
            result.setdefault(parent.as_posix(), {"type":"directory", "implicit":True})
            parent=parent.parent
    return result


def listings(text):
    entries, current = [], None
    for line in text.splitlines():
        match = re.match(r"\s*(Name|Type|Size|Packed size|Compression|mtime|Attributes|Flags|CRC32|BLAKE2):\s*(.*)$", line, re.I)
        if not match:
            continue
        key, value = match.groups()
        if key.lower() == "name":
            current = {"name": value.replace("\\", "/").rstrip("/")}
            entries.append(current)
        if current is not None and key.lower() != "name":
            current[key.lower()] = value
    return entries


def header_ns(value):
    match = re.search(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?", value)
    if not match:
        return None
    date, time, fraction = match.groups()
    seconds = int(dt.datetime.fromisoformat(date + "T" + time).replace(tzinfo=dt.timezone.utc).timestamp())
    return seconds * 10**9 + int(((fraction or "") + "0" * 9)[:9])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    candidate, native, report_path = args.candidate.resolve(), args.native.resolve(), args.out.resolve()
    if report_path.exists():
        raise SystemExit("Choose a fresh report path; previous evidence is immutable.")
    run_dir = report_path.parent / (report_path.stem + "-artifacts")
    run_dir.mkdir(parents=True, exist_ok=False)
    source = run_dir / "input"
    source.mkdir()
    fixture(source)
    report = {"purpose": "Correctness only: no performance/RSS measurements or parity claims.",
              "harness_sha256": sha(Path(__file__)), "candidate": str(candidate), "candidate_sha256": sha(candidate),
              "native": str(native), "native_sha256": sha(native), "host": platform.platform(),
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "fixture_mtime_seconds": STAMP,
              "password_note": "Public synthetic fixture password, not a user credential.",
              "cases": [], "commands": [], "known_limitations": [], "failures": []}
    environment = dict(os.environ, TZ="UTC", LC_ALL="C")

    def save():
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    def command(case, stage, argv, cwd=None):
        row = {"case": case, "stage": stage, "argv": list(map(str, argv)), "cwd": str(cwd or run_dir)}
        report["commands"].append(row)
        try:
            completed = subprocess.run(row["argv"], cwd=row["cwd"], env=environment, capture_output=True, timeout=args.timeout)
            row.update(returncode=completed.returncode, stdout=completed.stdout.decode(errors="replace"),
                       stderr=completed.stderr.decode(errors="replace"))
        except subprocess.TimeoutExpired as error:
            row.update(returncode=None, timeout_seconds=args.timeout,
                       stdout=(error.stdout or b"").decode(errors="replace"), stderr=(error.stderr or b"").decode(errors="replace"))
        save()
        return row

    def require(row, condition, message, stage):
        if not condition:
            failure = {"case": row["id"], "stage": stage, "message": message}
            row["failures"].append(failure)
            report["failures"].append(failure)

    flat = ["flat/alpha.txt", "flat/dup-a.bin", "flat/dup-b.bin", "flat/empty"]
    cases = [
        ("flat-rar5-t1", "rar50", flat, ["--no-filter"], 1, True),
        ("flat-rar5-t2", "rar50", flat, ["--no-filter"], 2, True),
        ("minimal-variant0-implicit-none", "rar50", ["delta.bin"], ["--hybrid-variant", "0"], 1, True),
        ("nested-rar5", "rar50", ["tree"], ["--no-filter"], 1, True),
        ("baseline-nested-rar5", "rar50", ["tree"], ["--no-filter"], 1, False),
        ("rar7-fractional-192k", "rar70", flat, ["--no-filter"], 1, True),
        ("mandatory-delta", "rar50", ["delta.bin"], ["--delta-filter", "4"], 1, True),
        ("mandatory-e8", "rar50", ["x86.bin"], ["--e8-filter"], 1, True),
        ("mandatory-arm", "rar50", ["arm.bin"], ["--arm-filter"], 1, True),
        ("solid-two-members", "rar50", ["solid-a.bin", "solid-b.bin"], ["--solid", "--no-filter"], 1, True),
        ("encrypted-data", "rar50", ["delta.bin"], ["--password", PASSWORD, "--no-filter"], 1, True),
        ("encrypted-headers", "rar50", ["delta.bin"], ["--password", PASSWORD, "--encrypt-headers", "--no-filter"], 1, True),
        ("volumes-rar5", "rar50", ["volume.bin"], ["--volume-size", "8k", "--no-filter"], 1, True),
        ("volumes-rar7-fractional", "rar70", ["volume.bin"], ["--volume-size", "8k", "--no-filter"], 1, True),
        ("continuation-rar5-variant63-e8", "rar50", ["continuation-e8.bin"], ["--hybrid-variant", "63", "--e8-filter"], 1, True),
    ]
    archive_hashes = {}
    directory_headers = {}
    for case_id, version, names, options, threads, hybrid in cases:
        row = {"id": case_id, "version": version, "threads": threads, "hybrid": hybrid, "requested": requested(source, names),
               "failures": [], "extractions": {}}
        report["cases"].append(row)
        destination = run_dir / case_id
        destination.mkdir()
        archive = destination / "case.rar"
        dictionary = "192k" if version == "rar70" else "128k"
        argv = [candidate, "--threads", str(threads), "--progress", "never", "a", "--format", version,
                "--level", "3", "--dict-size", dictionary,
                *(["--experimental-hybrid", "desktop"] if hybrid else []), *options, archive, *names]
        created = command(case_id, "create", argv, source)
        require(row, created["returncode"] == 0, "archive creation refused or failed", "create")
        if created["returncode"] != 0:
            row["status"] = "creation-failed"
            save()
            print(case_id, row["status"], flush=True)
            continue
        archives = sorted(destination.glob("*.rar"))
        require(row, bool(archives), "creation returned success without archive", "artifact")
        if not archives:
            row["status"] = "missing-artifact"
            save()
            continue
        archive = archives[0]
        row["archives"] = [{"name": p.name, "bytes": p.stat().st_size, "sha256": sha(p)} for p in archives]
        archive_hashes[case_id] = row["archives"]
        if "--volume-size" in options:
            require(row, len(archives) >= 2, "requested volume case did not produce multiple volumes", "artifact")
            row["volume_size_semantics"] = "Existing max_payload_per_volume contract; archive headers are additional."
        password = PASSWORD if "--password" in options else None
        password_switch = f"-p{password}" if password else "-p-"
        listing = command(case_id, "native-list", [native, "lt", "-cfg-", password_switch, archive])
        require(row, listing["returncode"] == 0, "native technical listing failed", "native-list")
        entries = listings(listing["stdout"])
        row["native_headers"] = entries
        if "--volume-size" in options:
            payloads=[]
            for part in archives:
                part_listing=command(case_id,"native-volume-list:"+part.name,[native,"lt","-cfg-",password_switch,part])
                part_entries=listings(part_listing["stdout"])
                packed=[int(entry["packed size"].replace(",","")) for entry in part_entries if entry.get("type","").lower()=="file" and "packed size" in entry]
                payload=sum(packed)
                payloads.append({"name":part.name,"packed_payload_bytes":payload,"archive_bytes":part.stat().st_size,"header_overhead_bytes":part.stat().st_size-payload})
                require(row,part_listing["returncode"]==0 and bool(packed),"native per-volume payload listing failed","volume-payload")
                require(row,payload<=8192,"volume payload exceeded requested8KiB","volume-payload")
            row["volume_payloads"]=payloads
        wanted = row["requested"]
        file_names = {name for name, item in wanted.items() if item["type"] == "file"}
        actual_file_names = {entry["name"] for entry in entries if entry.get("type", "").lower() == "file"}
        require(row, file_names == actual_file_names, f"native listing names differ: {sorted(actual_file_names)}", "native-headers")
        for entry in entries:
            name = entry["name"]
            if name not in wanted:
                continue
            expected = wanted[name]
            if expected.get("implicit"):
                continue
            actual_time = header_ns(entry.get("mtime", ""))
            require(row, actual_time == expected["mtime_ns"], f"header mtime differs for {name}: {entry.get('mtime')}", "native-headers")
            mode_text = stat.filemode((stat.S_IFDIR if expected["type"] == "directory" else stat.S_IFREG) | expected["mode"])
            require(row, mode_text in entry.get("attributes", ""), f"header mode differs/unparsed for {name}: {entry.get('attributes')}", "native-headers")
            if expected["type"] == "directory":
                directory_headers.setdefault(case_id, {})[name] = actual_time
        if version == "rar70":
            require(row, any(re.search(r"(?:md|\b)192\s*[kK]", entry.get("compression", "")) for entry in entries), "native metadata does not show requested 192KiB dictionary", "native-headers")
        if "--solid" in options:
            require(row, any("solid" in entry.get("flags", "").lower() for entry in entries), "native headers do not show solid continuation", "native-headers")
        native_test = command(case_id, "native-test", [native, "t", "-cfg-", "-inul", "-mt1", password_switch, archive])
        require(row, native_test["returncode"] == 0, "native archive integrity test failed", "native-test")
        if password:
            wrong = command(case_id, "native-wrong-password", [native, "t", "-cfg-", "-inul", "-mt1", "-pdeliberately-wrong-smoke", archive])
            require(row, wrong["returncode"] not in (None, 0), "wrong password was accepted or command timed out", "native-password")
        if "--encrypt-headers" in options:
            hidden = command(case_id, "native-no-header-password", [native, "lt", "-cfg-", "-p-", archive])
            require(row, hidden["returncode"] not in (None, 0), "encrypted headers readable without password or command timed out", "native-password")
        own_test = command(case_id, "candidate-test", [candidate, "--threads", "1", "test", *(["--password", password] if password else []), archive])
        require(row, own_test["returncode"] == 0, "rars integrity test failed", "candidate-test")
        for reader in ["native", "rars"]:
            output = destination / (reader + "-extracted")
            if reader == "native":
                extract = command(case_id, "native-extract", [native, "x", "-cfg-", "-inul", "-mt1", "-o-", password_switch, archive, str(output) + os.sep])
            else:
                extract = command(case_id, "candidate-extract", [candidate, "--threads", "1", "x", *(["--password", password] if password else []), archive, output])
            require(row, extract["returncode"] == 0, f"{reader} extraction failed", "extract")
            actual = {}
            if output.exists():
                for path in sorted(output.rglob("*")):
                    info = path.lstat()
                    name = path.relative_to(output).as_posix()
                    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                        require(row, False, f"unexpected extracted special entry {name}", "extract-manifest")
                        continue
                    item = {"type": "directory" if path.is_dir() else "file", "mode": stat.S_IMODE(info.st_mode),
                            "mtime_ns": info.st_mtime_ns, "inode": info.st_ino, "device": info.st_dev}
                    if path.is_file():
                        item.update(bytes=info.st_size, sha256=sha(path))
                    actual[name] = item
            row["extractions"][reader] = actual
            require(row, set(actual) == set(wanted), f"{reader} extracted entry names differ", "extract-manifest")
            for name in sorted(set(actual) & set(wanted)):
                expected, found = wanted[name], actual[name]
                for field in ("type", "mode", "bytes", "sha256"):
                    if field in expected:
                        require(row, found.get(field) == expected[field], f"{reader} {name}: {field} differs", "extract-manifest")
                if "mtime_ns" in expected and found["mtime_ns"] != expected["mtime_ns"]:
                    if reader == "native" and expected["type"] == "directory":
                        report["known_limitations"].append({"case": case_id, "entry": name, "kind": "native-directory-mtime",
                            "requested": expected["mtime_ns"], "actual": found["mtime_ns"], "header_matches": directory_headers.get(case_id, {}).get(name) == expected["mtime_ns"]})
                    else:
                        require(row, False, f"{reader} {name}: mtime differs", "extract-manifest")
            duplicate_names = [name for name in wanted if name.endswith(("dup-a.bin", "dup-b.bin", "copy-a.bin", "copy-b.bin"))]
            if len(duplicate_names) == 2 and all(name in actual for name in duplicate_names):
                left, right = (output / name for name in duplicate_names)
                different = (left.stat().st_dev, left.stat().st_ino) != (right.stat().st_dev, right.stat().st_ino)
                before = sha(right)
                with left.open("ab") as stream:
                    stream.write(b"independence witness")
                independent = different and sha(right) == before
                row.setdefault("independent_duplicates", {})[reader] = independent
                require(row, independent, f"{reader} duplicate outputs share inode/content mutation", "independent-duplicates")
        row["status"] = "ok" if not row["failures"] else "failed"
        save()
        print(case_id, row["status"], flush=True)
    if all(name in archive_hashes for name in ["flat-rar5-t1", "flat-rar5-t2"]):
        deterministic = archive_hashes["flat-rar5-t1"] == archive_hashes["flat-rar5-t2"]
        report["threads_1_vs_2_archive_identity"] = deterministic
        if not deterministic:
            report["failures"].append({"case": "threads-1-vs-2", "stage": "determinism", "message": "archive bytes differ"})
    report["baseline_directory_header_comparison"] = directory_headers.get("nested-rar5") == directory_headers.get("baseline-nested-rar5") and bool(directory_headers.get("nested-rar5"))
    if not report["baseline_directory_header_comparison"]:
        report["failures"].append({"case": "nested-directory-mtime", "stage": "baseline", "message": "hybrid/baseline directory header mtimes differ or missing"})
    report["binary_unchanged"] = sha(candidate) == report["candidate_sha256"] and sha(native) == report["native_sha256"]
    if not report["binary_unchanged"]:
        report["failures"].append({"case": "artifacts", "stage": "immutability", "message": "binary changed during correctness smoke"})
    report["completed_cases"] = len(report["cases"])
    report["passing_cases"] = sum(row.get("status") == "ok" for row in report["cases"])
    report["status"] = "ok" if not report["failures"] else "failed"
    save()
    print(json.dumps({"report": str(report_path), "status": report["status"], "cases": report["completed_cases"], "failures": len(report["failures"])}), flush=True)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
