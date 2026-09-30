#!/usr/bin/env python3
"""Measure Rust WASM source coverage from real Node execution (LLVM 23)."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = importlib.util.spec_from_file_location("rars_coverage", ROOT / "scripts/coverage.py")
coverage = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(coverage)
SECTIONS = [f"__{boundary}___llvm_prf_{kind}"
            for kind in ("data", "cnts", "names") for boundary in ("start", "stop")]


def run(command, environment, log):
    with log.open("w") as output:
        result = subprocess.run([str(part) for part in command], cwd=ROOT, env=environment,
                                stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, command))} failed:\n{log.read_text()[-6000:]}")


def validate_probe(output, environment, rustc, flags, llvm):
    """An independent positive control proves counters follow both outcomes."""
    source = output / "probe.rs"
    source.write_text('#[no_mangle]\npub extern "C" fn branch(value: u32) -> u32 {\n'
                      '    if value == 0 { 11 } else { 29 }\n}\n')
    probe = output / "probe.wasm"
    run(rustc + ["--edition", "2021", "--target", "wasm32-unknown-unknown", "--crate-type", "cdylib",
                 "-Copt-level=1", *flags, "-Clink-arg=--no-gc-sections", source, "-o", probe],
        environment, output / "probe-build.log")
    javascript = output / "probe.cjs"
    javascript.write_text(
        'const fs = require("node:fs"); const assert = require("node:assert/strict");\n'
        f'const {{profile}} = require({json.dumps(str(ROOT / "scripts/wasm-profile.cjs"))});\n'
        f'const instance = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync({json.dumps(str(probe))})));\n'
        'assert.equal(instance.exports.branch(0), 11); assert.equal(instance.exports.branch(1), 29);\n'
        f'assert.equal(profile(instance.exports, {json.dumps(str(output / "probe.txt"))}), 1);\n')
    run(["node", javascript], environment, output / "probe-run.log")
    run([llvm / "llvm-profdata", "merge", output / "probe.txt", "-o", output / "probe.profdata"],
        environment, output / "probe-merge.log")
    measured = json.loads(subprocess.check_output([
        str(llvm / "llvm-cov"), "export", str(probe), "--instr-profile", str(output / "probe.profdata")
    ]))["data"][0]
    assert measured["totals"]["branches"]["covered"] == 2
    assert measured["functions"][0]["branches"][0][4:6] == [1, 1]
    (output / "probe-validation.json").write_text(json.dumps(measured, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/coverage-wasm-focused")
    parser.add_argument("--toolchain", default="nightly")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if hasattr(os, "sched_getaffinity"):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    environment = os.environ.copy()
    environment.update(CARGO_BUILD_JOBS="1", RAYON_NUM_THREADS="2",
                       CARGO_TARGET_DIR=str(output), CARGO_PROFILE_DEV_OPT_LEVEL="1",
                       CARGO_PROFILE_DEV_DEBUG="1")
    rustc = ["rustc", f"+{args.toolchain}"]
    version = subprocess.check_output(rustc + ["-vV"], text=True)
    if "LLVM version: 23." not in version:
        raise RuntimeError("wasm-profile.cjs validates the LLVM 23 wasm32 profiling layout; "
                           "audit the layout before using another LLVM major version")
    (output / "rustc.txt").write_text(version)
    runtime = output / "runtime.rs"
    runtime.write_text("#[no_mangle]\npub static __llvm_profile_runtime: i32 = 0;\n")
    run(rustc + ["--edition", "2021", "--target", "wasm32-unknown-unknown", "--crate-type", "lib",
                 "--emit=obj", runtime, "-o", output / "runtime.o"], environment, output / "runtime.log")
    flags = ["-Cinstrument-coverage", "-Zcoverage-options=branch", "-Zno-profiler-runtime",
             '--cfg', 'getrandom_backend="wasm_js"', f"-Clink-arg={output / 'runtime.o'}"]
    flags.extend(f"-Clink-arg=--export={section}" for section in SECTIONS)
    environment.pop("RUSTFLAGS", None)
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    llvm, _ = coverage.llvm_tools(args.toolchain)
    validate_probe(output, environment, rustc, flags, llvm)
    # Root-only cfg(test) exports private boundary tests; it is absent from releases.
    # Retain names for unused instrumented functions: linker GC breaks coverage maps.
    run(["nice", "-n", "10", "cargo", f"+{args.toolchain}", "rustc", "--lib", "-p", "rars-wasm",
         "--target", "wasm32-unknown-unknown", "--locked", "--offline", "--",
         "-Clink-arg=--no-gc-sections", "--emit=link,obj", "--cfg", "test", "-Dwarnings"],
        environment, output / "build.log")
    original = output / "wasm32-unknown-unknown/debug/rars_wasm.wasm"
    engine = output / "engine"
    engine.mkdir(exist_ok=True)
    run(["wasm-bindgen", original, "--out-dir", engine, "--target", "nodejs", "--keep-debug"],
        environment, output / "bindgen.log")
    # Expose memory only in the generated test glue, never in the package API.
    with (engine / "rars_wasm.js").open("a") as glue:
        glue.write("\nmodule.exports.__coverage_exports = wasm;\n")
    environment.update(RARS_WASM_REQUIRE_TEST_EXPORTS="1",
                       RARS_WASM_PROFILE_HELPER=str(ROOT / "scripts/wasm-profile.cjs"),
                       RARS_WASM_PROFILE_OUT=str(output / "checked-engine.txt"))
    run(["nice", "-n", "10", "node", ROOT / "scripts/test-wasm-bindings.cjs", engine / "rars_wasm.js"],
        environment, output / "tests.log")
    llvm, _ = coverage.llvm_tools(args.toolchain)
    run([llvm / "llvm-profdata", "merge", output / "checked-engine.txt", "-o", output / "coverage.profdata"],
        environment, output / "merge.log")
    export = [str(llvm / "llvm-cov"), "export", str(original), "--instr-profile",
              str(output / "coverage.profdata"), "--ignore-filename-regex", coverage.IGNORE_REGEX]
    raw = json.loads(subprocess.check_output(export))["data"][0]
    lcov = subprocess.check_output(export + ["--format=lcov"], text=True)
    source = ROOT / "crates/rars-wasm/src/lib.rs"
    helper_environment = environment.copy()
    helper_environment.pop("RUSTFLAGS", None)
    helper_environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
    helper_environment.pop("CARGO_PROFILE_DEV_OPT_LEVEL", None)
    helper_environment.pop("CARGO_PROFILE_DEV_DEBUG", None)
    helper_environment["CARGO_TARGET_DIR"] = str(ROOT / "target/coverage-tools")
    run(["nice", "-n", "10", "cargo", "build", "--manifest-path", ROOT / "scripts/coverage-tools/Cargo.toml",
         "--locked", "--offline"], helper_environment, output / "tools.log")
    sources = {entry["path"]: entry for entry in map(json.loads, coverage.helper("source", [str(source)]))}
    symbols = [function["name"] for function in raw["functions"]]
    names = dict(zip(symbols, coverage.helper("demangle", symbols)))
    rows, missing, unmapped = coverage.summarize(raw, coverage.read_lcov(lcov), sources, names)
    for name, value in [("production", rows), ("missing", missing), ("unmapped", unmapped)]:
        (output / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")
    (output / "lib.rs.snapshot").write_bytes(source.read_bytes())
    (output / "selection.json").write_text(json.dumps({
        "source": str(source.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "tests": ["scripts/test-wasm-bindings.cjs", "cfg(test) host_tests::error_records"],
        "test_sha256": hashlib.sha256((ROOT / "scripts/test-wasm-bindings.cjs").read_bytes()).hexdigest(),
        "measurement": "Real Node execution of wasm-bindgen WASM; LLVM 23 wasm32 counter "
                       "records converted to LLVM text profiles. --no-gc-sections retains names. "
                       "Reports describe Rust source, not V8 facade coverage.",
        "rustc": version,
    }, indent=2) + "\n")
    print((output / "tests.log").read_text().strip())
    print({key: rows[0][key] for key in ("lines", "branches", "regions", "functions")})


if __name__ == "__main__":
    main()
