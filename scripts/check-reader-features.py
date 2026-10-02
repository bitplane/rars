#!/usr/bin/env python3
"""Check the independent consumer without workspace feature unification.

Run from any directory. Defaults to all 16 combinations. Build logs and dependency
inventories stay below target/reader-features; Cargo builds run sequentially.
"""
import argparse
import itertools
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ("write", "recovery", "encryption", "parallel")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", help="One comma-separated combination; 'none' for no features")
    args = parser.parse_args()
    if args.features is None:
        combinations = [tuple(f for f, enabled in zip(FEATURES, mask) if enabled)
                        for mask in itertools.product((False, True), repeat=4)]
    else:
        combination = tuple(f for f in args.features.split(",") if f and f != "none")
        if set(combination) - set(FEATURES):
            parser.error("unknown feature")
        combinations = [combination]
    logs = ROOT / "target/reader-features"
    logs.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for key, value in [("CARGO_BUILD_JOBS", "1"), ("RUST_TEST_THREADS", "2"), ("RAYON_NUM_THREADS", "2")]:
        env.setdefault(key, value)
    manifest = "scripts/reader-consumer/Cargo.toml"
    common = ["--offline", "--locked"]
    consumer = ["--manifest-path", manifest, "--target-dir", "target/reader-consumer-check"]
    for combination in combinations:
        name = "-".join(combination) or "none"
        flags = ["--features", ",".join(combination)] if combination else []
        print(f"Checking {name}", flush=True)
        commands = [
            ["cargo", "clippy", "-p", "rars", "--no-default-features", *flags, "--lib", *common, "--", "-D", "warnings"],
            ["cargo", "clippy", *consumer, *flags, "--all-targets", *common, "--", "-D", "warnings"],
            ["cargo", "test", *consumer, *flags, *common],
        ]
        with (logs / f"{name}.log").open("w") as log:
            for command in commands:
                log.write("$ " + " ".join(command) + "\n")
                log.flush()
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                if result.returncode:
                    print((logs / f"{name}.log").read_text())
                    raise SystemExit(result.returncode)
        tree = subprocess.check_output(
            ["cargo", "tree", "--manifest-path", manifest, *flags, *common, "--edges", "normal", "--prefix", "none"],
            cwd=ROOT, env=env, text=True,
        )
        (logs / f"{name}-dependencies.txt").write_text(tree)
        dependencies = set(re.findall(r"^([\w-]+) v", tree, re.MULTILINE))
        excluded = set()
        if "encryption" not in combination:
            excluded.update(("aes", "hmac", "sha1", "sha2", "zeroize"))
        if "parallel" not in combination:
            excluded.update(("rayon", "rayon-core", "crossbeam-deque", "crossbeam-epoch"))
        if not {"write", "recovery"}.intersection(combination):
            excluded.add("getrandom")
        unexpected = dependencies.intersection(excluded)
        if unexpected:
            raise SystemExit(f"{name} unexpectedly includes: {sorted(unexpected)}")
        print(f"Passed {name} (including dependency exclusions)", flush=True)


if __name__ == "__main__":
    main()
