#!/usr/bin/env python3
"""Test the library units for all 16 optional-feature combinations.

Use --features none or a comma-separated subset for one configuration. This
selects only rars's library harness, avoiding workspace feature unification.
Existing default integration and documentation checks remain separate.
"""
import argparse
import itertools
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ("write", "recovery", "encryption", "parallel")
# Clippy builds a set's unit tests a second time, so it runs on two: write
# alone, which compiles the fewest helpers the writer's tests lean on (its
# `useless_vec` buffers only had to be a Vec with encryption on), and no
# features at all. The workspace clippy run lints them with every feature on.
# Every set still builds with warnings denied.
LINTED = {("write",), ()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", help="One comma-separated subset, or 'none'")
    parser.add_argument("-j", "--jobs", type=int,
                        help="Parallel cargo jobs (default: CARGO_BUILD_JOBS, else 1)")
    args = parser.parse_args()
    if args.features is None:
        combinations = [tuple(f for f, selected in zip(FEATURES, mask) if selected)
                        for mask in itertools.product((False, True), repeat=len(FEATURES))]
    else:
        requested = args.features.split(",") if args.features != "none" else []
        if len(set(requested)) != len(requested) or set(requested) - set(FEATURES):
            parser.error("features must be distinct names from: " + ", ".join(FEATURES))
        combinations = [tuple(f for f in FEATURES if f in requested)]
    env = dict(os.environ)
    # Resolve an externally supplied relative target before subprocess cwd changes.
    target = Path(env.get("CARGO_TARGET_DIR", ROOT / "target/unit-features")).resolve()
    env["CARGO_TARGET_DIR"] = str(target)
    if args.jobs is not None:
        env["CARGO_BUILD_JOBS"] = str(args.jobs)
    env.setdefault("CARGO_BUILD_JOBS", "1")
    env.setdefault("CARGO_INCREMENTAL", "0")
    env.setdefault("RUST_TEST_THREADS", "2")
    env.setdefault("RAYON_NUM_THREADS", "2")
    if "CARGO_ENCODED_RUSTFLAGS" in env:
        flags = env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f") if env["CARGO_ENCODED_RUSTFLAGS"] else []
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([*flags, "-D", "warnings"])
    else:
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -D warnings").strip()
    logs = target / "unit-feature-tests"
    logs.mkdir(parents=True, exist_ok=True)
    for features in combinations:
        name = "-".join(features) or "none"
        flags = ["--features", ",".join(features)] if features else []
        selection = ["--locked", "-p", "rars", "--lib", "--no-default-features", *flags]
        commands = [["cargo", "test", *selection]]
        if features in LINTED:
            # The test profile lints the unit-test target of this subset.
            commands.insert(0, ["cargo", "clippy", *selection, "--profile", "test",
                                "--", "-D", "warnings"])
        print(f"Testing library units: {name}", flush=True)
        log_path = logs / (name + ".log")
        with log_path.open("w") as log:
            for command in commands:
                log.write("$ " + " ".join(command) + "\n")
                log.flush()
                result = subprocess.run(command, cwd=ROOT, env=env,
                                        stdout=log, stderr=subprocess.STDOUT)
                if result.returncode:
                    break
        if result.returncode:
            print(log_path.read_text()[-16000:])
            raise SystemExit(result.returncode)
        print(f"Passed {name}; log: {log_path}", flush=True)


if __name__ == "__main__":
    main()
