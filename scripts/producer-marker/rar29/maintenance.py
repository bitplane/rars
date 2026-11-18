#!/usr/bin/env python3
"""Check RAR 2.9 marker framing and reference-reader updates/comments."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rar34"))
from maintenance import blocks, has_marker
from probe import manifest, run
from probe import commands
# The shared adapter exports Windows path conversion through its parent module.
def windows(path):
    return "Z:" + str(path).replace("/", "\\")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--engines", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, matrix = args.output.resolve(), args.matrix.resolve()
    root.mkdir(parents=True, exist_ok=False)
    evidence = {"framing": [], "updates": []}
    for path in sorted((matrix / "archives").rglob("*")):
        if not path.is_file() or path.name == "create.log":
            continue
        records = list(blocks(path.read_bytes()))
        marked = path.parent.name == "marked"
        assert sum(r["name"] == b"RARS" for r in records) == int(marked)
        if marked:
            leads = records[1]["kind"] == 0x75 or records[1]["name"] == b"CMT"
            index = 2 if leads else 1
            assert records[index]["name"] == b"RARS"
        evidence["framing"].append(str(path.relative_to(matrix)))
    for engine in json.loads(args.engines.read_text()):
        assert engine["family"] == "rar"
        convert = windows if engine.get("windows") else str
        for label in ("control", "marked"):
            work = root / engine["name"] / label
            work.mkdir(parents=True)
            archive = work / "archive.rar"
            shutil.copyfile(matrix / "archives/rar29/comment" / label / "archive.rar", archive)
            env = {**os.environ, **engine.get("env", {})}
            def call(arguments, log):
                return run(engine["command"] + arguments, work, env, work / log)
            assert call(["cw", "-y", convert(archive), "before.txt"], "before.log") == 0
            assert (work / "before.txt").read_bytes() == b"User comment survives independently"
            (work / "added.txt").write_bytes(b"Added by reference RAR.\n")
            assert call(["a", "-y", convert(archive), "added.txt"], "update.log") == 0
            assert call(["cw", "-y", convert(archive), "after.txt"], "after.log") == 0
            assert (work / "after.txt").read_bytes() == b"User comment survives independently"
            output = work / "extracted"
            output.mkdir()
            test, extract = commands(engine, archive, output)
            assert run(test, work, env, work / "test.log") == 0
            assert run(extract, work, env, work / "extract.log") == 0
            assert manifest(output) == {**manifest(matrix / "input"), "added.txt": manifest(work)["added.txt"]}
            evidence["updates"].append({"engine": engine["name"], "variant": label,
                                        "comment_preserved": True, "contents_match": True,
                                        "marker_retained": has_marker(archive.read_bytes())})
    (root / "report.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Checked {len(evidence['framing'])} archive/volume files and {len(evidence['updates'])} updates.")


if __name__ == "__main__":
    main()
