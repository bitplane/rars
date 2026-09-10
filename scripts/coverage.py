#!/usr/bin/env python3
"""Reproducible native coverage, with raw LLVM data and actionable gap inventories.

Run with --branches --toolchain nightly for branch instrumentation. Native Rust
and Python boundary coverage share a profile; JS and WASM are separate targets.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
IGNORE_REGEX = r"/.cargo/registry|/rustc/|/tests/"


def run(command, *, env=None, log=None):
    print("+", " ".join(map(str, command)), flush=True)
    with open(log, "w") if log else open(os.devnull, "w") as output:
        try:
            return subprocess.call(list(map(str, command)), cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        except OSError as error:
            output.write(str(error) + "\n")
            return 127


def capture(command, **kwargs):
    return subprocess.check_output(list(map(str, command)), cwd=ROOT, text=True, **kwargs)


def llvm_tools(toolchain):
    compiler = ["rustc"] + ([f"+{toolchain}"] if toolchain else [])
    version = capture(compiler + ["-vV"])
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    tools = Path(capture(compiler + ["--print", "sysroot"]).strip()) / "lib/rustlib" / host / "bin"
    for name in ["llvm-profdata", "llvm-cov"]:
        if not (tools / name).is_file():
            raise RuntimeError(f"Missing {tools / name}; install llvm-tools-preview for this toolchain")
    return tools, version


def source_state():
    files = sorted(path for crate in (ROOT / "crates").iterdir() for path in (crate / "src").rglob("*.rs"))
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return files, digest.hexdigest()


def helper(mode, lines):
    binary = ROOT / "target/coverage-tools/debug/rars-coverage-tools"
    return capture([binary, mode], input="\n".join(lines) + "\n").splitlines()


def test_symbol(name):
    # A production generic instantiated with a test callback is still production.
    return "::tests::" in name.split("::<", 1)[0]


def read_lcov(text):
    files = {}
    current = None
    for line in text.splitlines():
        if line.startswith("SF:"):
            current = files.setdefault(line[3:], {})
        elif line.startswith("DA:") and current is not None:
            number, count, *_ = line[3:].split(",")
            current[int(number)] = max(current.get(int(number), 0), int(count))
    return files


def classify_external_test_modules(sources):
    """Carry cfg(test) through out-of-line module files as well as inline ASTs."""
    marked = set()
    while True:
        references = defaultdict(list)
        for filename, source in sources.items():
            path = Path(filename)
            directory = path.parent if path.stem in {"lib", "main", "mod"} else path.parent / path.stem
            for module in source.get("modules", []):
                candidates = ([path.parent / module["path"]] if module.get("path") else
                              [directory / (module["name"] + ".rs"), directory / module["name"] / "mod.rs"])
                for candidate in candidates:
                    resolved = str(candidate.resolve())
                    if resolved in sources:
                        references[resolved].append(module["test_only"] or filename in marked)
        added = {filename for filename, flags in references.items() if all(flags)} - marked
        if not added:
            break
        marked.update(added)
    for filename in marked:
        source = sources[filename]
        source["test_ranges"].append([1, len(Path(filename).read_text().splitlines()) + 1])
        for decl in source["declarations"]:
            decl["test_only"] = True


def summarize(data, line_counts, sources, names):
    """Union generic instantiations; retain zero counters and exclude test source.

    Lines come from LLVM's own LCOV aggregation. Regions/functions are unique
    source locations, not an approximation formed by subtracting test totals.
    """
    stats = {}
    missing = []
    unmapped = []
    for filename, source in sources.items():
        excluded = {line for start, end in source["test_ranges"] for line in range(start, end + 1)}
        stats[filename] = {"lines": {n: c for n, c in line_counts.get(filename, {}).items() if n not in excluded},
                           "regions": {}, "functions": {}, "branches": {}, "excluded": excluded}
    for fn in data["functions"]:
        name = names[fn["name"]]
        if test_symbol(name):
            continue
        code = [r for r in fn["regions"] if r[7] == 0 and fn["filenames"][r[5]] in stats]
        if not code:
            continue
        first = code[0]
        filename = fn["filenames"][first[5]]
        entry = stats[filename]
        if first[0] in entry["excluded"]:
            continue
        key = tuple(first[:4])
        previous = entry["functions"].setdefault(key, {"count": 0, "names": set()})
        previous["count"] = max(previous["count"], fn["count"])
        previous["names"].add(name)
        for region in code:
            entry = stats[fn["filenames"][region[5]]]
            if region[0] in entry["excluded"]:
                continue
            key = tuple(region[:4])
            entry["regions"][key] = max(entry["regions"].get(key, 0), region[4])
        for branch in fn.get("branches", []):
            # [start line/column, end line/column, true, false, file, expanded, kind]
            filename = fn["filenames"][branch[6]]
            if filename not in stats or branch[0] in stats[filename]["excluded"]:
                continue
            key = tuple(branch[:4])
            previous = stats[filename]["branches"].get(key, (0, 0))
            stats[filename]["branches"][key] = (max(previous[0], branch[4]), max(previous[1], branch[5]))
    rows = []
    for filename, entry in sorted(stats.items()):
        relative = str(Path(filename).relative_to(ROOT))
        for location, fn in entry["functions"].items():
            if fn["count"] == 0:
                missing.append({"file": relative, "line": location[0], "end_line": location[2], "names": sorted(fn["names"])})
        for decl in sources[filename]["declarations"]:
            if not decl["test_only"] and not any(start <= decl["line"] <= end for start, _, end, _ in entry["functions"]):
                unmapped.append({"file": relative, **decl})
        row = {"file": relative}
        for category in ["lines", "regions", "functions", "branches"]:
            values = list(entry[category].values())
            if category == "functions":
                values = [fn["count"] for fn in values]
            if category == "branches":
                values = [count for pair in values for count in pair]
            row[category] = {"covered": sum(count > 0 for count in values), "total": len(values)}
        row["uncovered_lines"] = [line for line, count in sorted(entry["lines"].items()) if count == 0]
        row["uncovered_regions"] = [list(location) for location, count in entry["regions"].items() if count == 0]
        row["uncovered_branches"] = [{"location": list(location), "true": counts[0], "false": counts[1]} for location, counts in entry["branches"].items() if 0 in counts]
        rows.append(row)
    return rows, missing, unmapped


def artifact_objects(messages):
    objects = []
    for line in messages.splitlines():
        try:
            artifact = json.loads(line)
        except json.JSONDecodeError:
            continue
        if artifact.get("reason") == "compiler-artifact" and artifact.get("executable"):
            objects.append(Path(artifact["executable"]))
    return objects


def report(output, tools, manifest, source_files):
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(ROOT / "target/coverage-tools")
    if run(["cargo", "build", "--manifest-path", "scripts/coverage-tools/Cargo.toml", "--locked", "--offline"], env=env, log=output / "tools.log"):
        raise RuntimeError("Coverage source helper failed; see tools.log")
    profiles = sorted((output / "profraw").glob("*.profraw"))
    if not profiles:
        raise RuntimeError("No profiles produced")
    profile = output / "coverage.profdata"
    # A response file also works when the suite creates thousands of profiles.
    response = output / "profiles.txt"
    response.write_text("\n".join('"' + str(p) + '"' for p in profiles))
    subprocess.run([str(tools / "llvm-profdata"), "merge", "-sparse", "@" + str(response), "-o", str(profile)], check=True)
    # Cargo's artifact layout differs between stable and recent nightly builds.
    # Ask Cargo for its executable manifest instead of guessing a deps directory.
    build_env = os.environ.copy()
    build_env.update(CARGO_TARGET_DIR=str(output), CARGO_PROFILE_DEV_OPT_LEVEL="1", CARGO_PROFILE_DEV_DEBUG="1", LLVM_PROFILE_FILE=str(output / "profraw/%p-%m.profraw"))
    build_env["RUSTFLAGS"] = "-Cinstrument-coverage" + (" -Zcoverage-options=branch" if manifest["branches"] else "")
    toolchain = manifest.get("toolchain") or ("nightly" if "nightly" in manifest["rustc"] else None)
    cargo = ["cargo"] + ([f"+{toolchain}"] if toolchain else [])
    artifact_log = output / "cargo-artifacts.jsonl"
    if run(cargo + ["test", "--workspace", "--tests", "--no-run", "--locked", "--message-format=json"], env=build_env, log=artifact_log):
        raise RuntimeError("Cannot collect executable manifest; see cargo-artifacts.jsonl")
    objects = artifact_objects(artifact_log.read_text())
    for path in [output / "debug/rars", output / "python/rars.abi3.so"]:
        if path.is_file():
            objects.append(path)
    if not objects:
        raise RuntimeError("No instrumented executable objects found")
    objects = list(dict.fromkeys(objects))
    arguments = [str(objects[0])]
    for obj in objects[1:]:
        arguments += ["--object", str(obj)]
    common = ["--instr-profile", str(profile), "--ignore-filename-regex", IGNORE_REGEX, *arguments]
    for name, command in [("coverage.json", ["export"]), ("coverage.lcov", ["export", "--format=lcov"]), ("llvm-summary.txt", ["report"])]:
        with (output / name).open("w") as destination:
            subprocess.run([str(tools / "llvm-cov"), *command, *common], stdout=destination, check=True)
    raw = json.loads((output / "coverage.json").read_text())["data"][0]
    sources = {entry["path"]: entry for entry in map(json.loads, helper("source", [str(p) for p in source_files]))}
    classify_external_test_modules(sources)
    names = [fn["name"] for fn in raw["functions"]]
    names = dict(zip(names, helper("demangle", names)))
    rows, missing, unmapped = summarize(raw, read_lcov((output / "coverage.lcov").read_text()), sources, names)
    (output / "production.json").write_text(json.dumps(rows, indent=2))
    (output / "uncovered-functions.json").write_text(json.dumps(missing, indent=2))
    (output / "unmapped-declarations.json").write_text(json.dumps(unmapped, indent=2))
    (output / "source-inventory.json").write_text(json.dumps(sources, indent=2))
    totals = defaultdict(lambda: defaultdict(lambda: {"covered": 0, "total": 0}))
    for row in rows:
        for category in ["lines", "regions", "functions", "branches"]:
            for key in ["covered", "total"]:
                totals[row["file"].split("/")[1]][category][key] += row[category][key]
    def ratio(value):
        return f"{value['covered']}/{value['total']} ({value['covered']/value['total']:.1%})" if value['total'] else "not mapped"
    text = ["# Coverage baseline", "", f"Revision: `{manifest['revision']}`", f"Source fingerprint: `{manifest['source_sha256']}`", f"Host: {manifest['host']}",
            f"Test outcomes: `{manifest['steps']}`", "", "Production code only; test-only source ranges excluded.",
            "Line counts use LLVM LCOV; regions and functions union source locations across instantiations.",
            "Unmapped declarations are not counted as covered or dead: inspect cfgs, macros and compiler elimination.",
            "Native coverage does not measure WASM execution, Windows/macOS paths or JavaScript.",
            "Branch counts cover instrumented conditions, not every short-circuit decision or path combination.", "",
            "| Crate | Lines | Code regions | Functions | Branch outcomes |", "| --- | --- | --- | --- | --- |"]
    for crate, categories in sorted(totals.items()):
        text.append("| " + crate + " | " + " | ".join(ratio(categories[c]) for c in ["lines", "regions", "functions", "branches"]) + " |")
    text += ["", f"Uncovered mapped functions: {len(missing)}; declarations requiring mapping/cfg review: {len(unmapped)}.", "",
             "Raw LLVM: coverage.json, coverage.lcov, llvm-summary.txt; production detail: production.json.",
             "Gap inventories: uncovered-functions.json, unmapped-declarations.json. HTML includes test code."]
    (output / "summary.md").write_text("\n".join(text) + "\n")
    if run([tools / "llvm-cov", "show", "--format=html", "--show-line-counts-or-regions", "--show-branches=count", "--output-dir", output / "html", *common], log=output / "html.log"):
        raise RuntimeError("HTML generation failed")
    manifest["reported_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest["objects"] = list(map(str, objects))
    manifest["profiles"] = len(profiles)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("\n".join(text))
    print(f"HTML: {output / 'html/index.html'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/coverage")
    parser.add_argument("--toolchain")
    parser.add_argument("--branches", action="store_true")
    parser.add_argument("--reuse", action="store_true", help="Regenerate reports from existing profiles; source fingerprint must match")
    parser.add_argument("--python", type=Path, default=ROOT / ".venv/bin/python", help="Python with pytest installed; its native boundary suite is included")
    args = parser.parse_args()
    output = args.output.resolve()
    tools, version = llvm_tools(args.toolchain)
    if args.branches and "nightly" not in version:
        raise RuntimeError("Branch instrumentation requires --toolchain nightly")
    source_files, fingerprint = source_state()
    if args.reuse:
        manifest = json.loads((output / "manifest.json").read_text())
        if manifest["rustc"] != version:
            raise RuntimeError("Compiler differs from profiling; select the original toolchain or collect fresh profiles")
        if manifest["source_sha256"] != fingerprint:
            raise RuntimeError("Source changed since profiling; collect fresh profiles instead of reusing stale coverage")
    else:
        if (output / "profraw").exists():
            raise RuntimeError("Output already contains profiles; use --reuse or a fresh --output directory")
        (output / "profraw").mkdir(parents=True)
        manifest = {"revision": capture(["git", "rev-parse", "HEAD"]).strip(), "working_tree": capture(["git", "status", "--porcelain"]),
                    "source_sha256": fingerprint, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "host": platform.platform(),
                    "rustc": version, "toolchain": args.toolchain, "branches": args.branches, "steps": {}}
        env = os.environ.copy()
        env.update(CARGO_TARGET_DIR=str(output), CARGO_PROFILE_DEV_OPT_LEVEL="1", CARGO_PROFILE_DEV_DEBUG="1", LLVM_PROFILE_FILE=str(output / "profraw/%p-%m.profraw"))
        env["RUSTFLAGS"] = "-Cinstrument-coverage" + (" -Zcoverage-options=branch" if args.branches else "")
        manifest["environment"] = {key: env[key] for key in ["CARGO_TARGET_DIR", "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_DEBUG", "LLVM_PROFILE_FILE", "RUSTFLAGS"]}
        cargo = ["cargo"] + ([f"+{args.toolchain}"] if args.toolchain else [])
        manifest["steps"]["native_tests"] = run(cargo + ["test", "--workspace", "--tests", "--locked", "--no-fail-fast"], env=env, log=output / "native-tests.log")
        manifest["steps"]["python_build"] = run(cargo + ["build", "-p", "rars-python", "--features", "extension-module", "--locked"], env=env, log=output / "python-build.log")
        if manifest["steps"]["python_build"] == 0:
            import shutil
            (output / "python").mkdir()
            shutil.copy2(output / "debug/librars.so", output / "python/rars.abi3.so")
            env["PYTHONPATH"] = str(output / "python")
            manifest["steps"]["python_tests"] = run([args.python, "-m", "pytest", "-q", "python/tests", "--basetemp", output / "pytest-tmp"], env=env, log=output / "python-tests.log")
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    report(output, tools, manifest, source_files)
    return int(any(manifest["steps"].values()))


if __name__ == "__main__":
    sys.exit(main())
