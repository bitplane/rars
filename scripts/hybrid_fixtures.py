#!/usr/bin/env python3
"""Generate the small, deterministic additions to the existing parity corpus."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def noise(length, seed):
    # Fixed integer arithmetic: identical bytes across Python versions/hosts.
    state = seed
    output = bytearray()
    for _ in range(length):
        state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 7
        state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
        output.append(state & 255)
    return bytes(output)


def generate(destination, base_corpus=None):
    destination.mkdir(parents=True, exist_ok=False)
    records, workloads = [], []
    if base_corpus is not None:
        existing = json.loads(base_corpus.read_text())
        root = base_corpus.parent.resolve()
        for record in existing["files"]:
            relative = Path(record["path"])
            source = root / relative
            if (relative.is_absolute() or ".." in relative.parts or source.is_symlink()
                    or not source.resolve().is_relative_to(root)):
                raise ValueError("base corpus path escapes its source directory")
            target = destination / relative
            if record.get("type", "file") == "directory":
                target.mkdir(parents=True, exist_ok=True)
                shutil.copystat(source, target)
            else:
                if hashlib.sha256(source.read_bytes()).hexdigest() != record["sha256"]:
                    raise ValueError("base corpus content changed: " + relative.as_posix())
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            records.append(record)
        workloads.extend(existing["workloads"])
    release = b"".join(
        ('{"id":%d,"name":"record-%04d","active":true,"value":%d}\n' %
         (i, i, (i * 17) % 1009)).encode("ascii") for i in range(256)
    )
    updated = release.replace(b'"active":true', b'"active":false', 3)
    base = noise(8192, 0x123456789ABCDEF)
    files = {
        "hybrid/releases/v1/export.jsonl": release,
        "hybrid/releases/v2/export.jsonl": updated,
        "hybrid/shifted/base.bin": base,
        "hybrid/shifted/with-prefix.bin": noise(257, 0x514F) + base,
        "hybrid/distance/long-gap.bin": base + noise(160 * 1024, 0xD157A) + base,
        "hybrid/unrelated/first.bin": noise(12 * 1024, 0x554E52454C415445),
        "hybrid/unrelated/second.bin": noise(12 * 1024, 0xA1177E5),
    }
    for name, contents in files.items():
        path = destination / name
        if path.exists():
            raise ValueError("base corpus collides with generated fixture: " + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o644)
        os.utime(path, (1700000000, 1700000000))
        records.append({"path": name, "size": len(contents),
                        "sha256": hashlib.sha256(contents).hexdigest()})
    manifest = {
        "generator": "hybrid-fixtures-v1/xorshift64",
        "seed_policy": "fixed literals in committed generator",
        "files": records,
        "workloads": workloads + [
            {"id": "hybrid-related-releases", "files": list(files)[:2], "solid": True},
            {"id": "hybrid-shifted-repeat", "files": list(files)[2:4], "solid": True},
            {"id": "hybrid-dictionary-distance", "files": ["hybrid/distance/long-gap.bin"], "solid": False},
            {"id": "hybrid-unrelated-data", "files": list(files)[5:], "solid": False},
        ],
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory; existing paths are never replaced")
    parser.add_argument("--base-corpus", type=Path, help="existing manifest; verify and retain its workloads")
    args = parser.parse_args()
    manifest = generate(args.output, args.base_corpus)
    print(json.dumps({"manifest": str(args.output / "manifest.json"),
                      "files": len(manifest["files"]),
                      "bytes": sum((args.output / f["path"]).stat().st_size
                                   for f in manifest["files"] if f.get("type", "file") == "file")}))


if __name__ == "__main__":
    main()
