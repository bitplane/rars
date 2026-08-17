#!/usr/bin/env python3
"""Time the compression ladder on a few kinds of data.

A ratio sweep takes an hour and tells you nothing about speed until it is
finished. This takes about a minute and answers one question: how long does a
megabyte take at each level, and how much of that is the level itself.

    python3 scripts/speed.py                     # built-in samples, rar50
    python3 scripts/speed.py --format rar29
    python3 scripts/speed.py --levels 3,5 path/to/file

The samples are built from the repository so there is nothing to download:
source text, the release binary's own bytes, and a block that repeats, which
is where a match finder is at its worst. Sizes are in the table because a
level that costs time and saves nothing is the thing worth catching.

`--decompose` adds a line for level 5 specifically. Level 5 encodes the member
once per level on the ladder below it and keeps the smallest result, so its
wall time is the sum of every cheaper level plus its own optimal parse. The
line prints that arithmetic: how much of level 5 is the parse, and how much is
the re-encoding.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_BYTES = 1 << 20


def build_samples(directory: Path) -> list[Path]:
    """Three megabytes of very different data, made from what is already here."""
    directory.mkdir(parents=True, exist_ok=True)
    samples = []

    text = directory / "source-1m.bin"
    if not text.is_file():
        blob = bytearray()
        for path in sorted(ROOT.glob("crates/*/src/**/*.rs")):
            blob += path.read_bytes()
            if len(blob) >= SAMPLE_BYTES:
                break
        text.write_bytes(bytes(blob[:SAMPLE_BYTES]))
    samples.append(text)

    binary = directory / "binary-1m.bin"
    release = ROOT / "target/release/rars"
    if not binary.is_file() and release.is_file():
        binary.write_bytes(release.read_bytes()[:SAMPLE_BYTES])
    if binary.is_file():
        samples.append(binary)

    # One 4 KiB block, over and over. Every position hashes into the same chain,
    # which is where a chain walk degenerates.
    repeat = directory / "repeat-1m.bin"
    if not repeat.is_file():
        block = bytes((index * 7 + (index >> 5)) & 0xFF for index in range(4096))
        repeat.write_bytes((block * (SAMPLE_BYTES // len(block)))[:SAMPLE_BYTES])
    samples.append(repeat)

    return samples


def encode(binary: Path, fmt: str, level: int, source: Path, out: Path) -> tuple[float, int]:
    out.unlink(missing_ok=True)
    start = time.perf_counter()
    result = subprocess.run(
        [str(binary), "--progress", "never", "a", "--format", fmt,
         "--level", str(level), str(out), str(source)],
        capture_output=True,
    )
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        sys.exit(f"{binary} failed at level {level} on {source.name}:\n"
                 f"{result.stderr.decode(errors='replace')}")
    size = out.stat().st_size
    out.unlink(missing_ok=True)
    return elapsed, size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="*", type=Path,
                        help="files to time; defaults to the built-in samples")
    parser.add_argument("--rars-bin", type=Path, default=ROOT / "target/release/rars")
    parser.add_argument("--format", default="rar50")
    parser.add_argument("--levels", default="1,2,3,4,5")
    parser.add_argument("--work", type=Path, default=ROOT / "target/speed",
                        help="where samples and archives go; never /tmp")
    parser.add_argument("--decompose", action="store_true",
                        help="split level 5 into its parse and its re-encodes")
    args = parser.parse_args()

    if not args.rars_bin.is_file():
        return int(bool(sys.stderr.write(
            f"no binary at {args.rars_bin}; run `cargo build --release`\n")))

    levels = [int(part) for part in args.levels.split(",")]
    args.work.mkdir(parents=True, exist_ok=True)
    inputs = args.inputs or build_samples(args.work / "samples")

    print(f"{args.rars_bin}  --format {args.format}\n")
    header = f"{'input':18}{'size':>10}" + "".join(f"{'m' + str(l):>18}" for l in levels)
    print(header)
    print("-" * len(header))

    for source in inputs:
        timings = {}
        cells = []
        for level in levels:
            seconds, packed = encode(args.rars_bin, args.format, level, source,
                                     args.work / "speed.rar")
            timings[level] = seconds
            megabytes = source.stat().st_size / (1 << 20)
            cells.append(f"{seconds:7.2f}s {packed / megabytes / 1024:6.0f}K/MB")
        print(f"{source.name:18}{source.stat().st_size:10,}" + "".join(f"{c:>18}" for c in cells))

        if args.decompose and 5 in timings:
            below = sum(timings[l] for l in timings if l < 5)
            parse = timings[5] - below
            print(f"{'':18}{'':10}  level 5 = {parse:.2f}s parse"
                  f" + {below:.2f}s re-encoding levels 1-4"
                  f"  ({parse / timings[5] * 100:.0f}% / {below / timings[5] * 100:.0f}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
