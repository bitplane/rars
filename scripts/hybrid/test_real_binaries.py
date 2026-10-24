"""Bounded real-RAR integration tests; missing external binaries are explicit skips.

Build target/debug/rars, or set RARS_SMOKE_BINARY to a compiled executable.
RARS_NATIVE_RAR optionally selects a licensed native RAR executable; otherwise
the native comparison uses rar from PATH when available. No encoder is simulated.
Run from a clean committed checkout so the runner freezes the actual source.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts/hybrid_candidates.py"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
TASK_TIMEOUT = 30
COMMAND_TIMEOUT = 75
BUDGETS = {"screen": 90, "confirm": 30}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "wait4"),
                     "real-binary runner smoke requires POSIX permissions and wait4")
class RealBinaryTests(unittest.TestCase):
    def binary(self, variable, default):
        explicit = variable in os.environ
        value = os.environ.get(variable) if explicit else default
        if not value:
            if explicit:
                self.fail(f"{variable} is explicitly set but does not name an executable")
            self.skipTest(f"native RAR unavailable; set {variable} to a licensed executable")
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = REPOSITORY / path
        path = path.resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            if explicit:
                self.fail(f"{variable} is explicitly set to an unavailable executable: {path}")
            self.skipTest(f"compiled rars unavailable at {path}; build it or set {variable}")
        # Exercise the compiled program itself, never a shell/Python fixture.
        with path.open("rb") as stream:
            magic = stream.read(4)
        self.assertIn(magic, (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                              b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                              b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                              b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"),
                      f"{variable} must name a compiled ELF/Mach-O executable: {path}")
        return path

    def prepare(self, native=False):
        # A broken explicit native path is a configuration error even when the
        # default candidate has not been built yet.
        self.native = self.binary("RARS_NATIVE_RAR", None) if native and "RARS_NATIVE_RAR" in os.environ else None
        self.candidate = self.binary("RARS_SMOKE_BINARY", REPOSITORY / "target/debug/rars")
        if native and self.native is None:
            self.native = self.binary("RARS_NATIVE_RAR", shutil.which("rar"))
        if native:
            self.assertNotEqual(self.native, self.candidate,
                                "RARS_NATIVE_RAR must be native RAR, not the rars candidate")
        status = self.git("status", "--porcelain", "--untracked-files=all")
        self.assertFalse(status, "real-binary tests require a clean committed source checkout; "
                                "commit the intended runner/test changes before testing")
        self.source = {"revision": self.git("rev-parse", "HEAD"),
                       "tree": self.git("rev-parse", "HEAD^{tree}"),
                       "dirty_diff_sha256": hashlib.sha256(b"").hexdigest()}
        self.temp = tempfile.TemporaryDirectory(prefix="rars-real-smoke-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        (self.corpus / "nested").mkdir()
        (self.corpus / "empty").mkdir()
        (self.corpus / "nested/data.txt").write_bytes(b"real RAR smoke content\n" * 128)
        (self.corpus / "nested/run.sh").write_bytes(b"#!/bin/sh\nprintf 'RAR smoke\\n'\n")
        modes = {"nested": 0o750, "empty": 0o750,
                 "nested/data.txt": 0o640, "nested/run.sh": 0o751}
        self.expected = {}
        for index, (name, mode) in enumerate(modes.items()):
            path = self.corpus / name
            timestamp = 1700000001 + index * 7
            path.chmod(mode)
            os.utime(path, (timestamp, timestamp))
            record = {"type": "directory" if path.is_dir() else "file",
                      "mode": stat.S_IMODE(path.stat().st_mode), "mtime": timestamp}
            self.assertEqual(record["mode"], mode, "filesystem must preserve POSIX modes")
            if path.is_file():
                record.update(bytes=path.stat().st_size, sha256=sha(path))
            self.expected[name] = record
        self.assertLess(sum(record.get("bytes", 0) for record in self.expected.values()), 64 * 1024)
        files = [{"path": name, **({"sha256": record["sha256"]} if record["type"] == "file" else {})}
                 for name, record in self.expected.items()]
        corpus_manifest = {"files": files, "workloads": [
            {"id": "nonsolid", "files": list(self.expected), "solid": False},
            {"id": "solid", "files": list(self.expected), "solid": True}]}
        # Corpus paths are relative to its manifest, so keep the manifest with it.
        self.corpus_manifest = self.corpus / "manifest.json"
        self.corpus_manifest.write_text(json.dumps(corpus_manifest))
        plan = {"budgets": BUDGETS, "task_timeout_seconds": TASK_TIMEOUT,
                "execution": {"screen_threads": 1, "confirm_threads": 1},
                "worker_options": {"rars_add": ["--no-filter"]}}
        if native:
            plan["worker_options"]["native_add"] = ["-mc-"]
        self.plan = self.root / "plan.json"
        self.plan.write_text(json.dumps(plan))
        self.run = self.root / "run"

    def git(self, *args):
        completed = subprocess.run(["git", "-C", str(REPOSITORY), *args],
                                   capture_output=True, text=True, timeout=15, check=True)
        return completed.stdout.strip()

    def cli(self, script, *args):
        completed = subprocess.run([sys.executable, str(script), *map(str, args)],
                                   cwd=REPOSITORY, capture_output=True, text=True,
                                   timeout=COMMAND_TIMEOUT)
        self.assertEqual(completed.returncode, 0,
                         f"runner command failed: {args}\n{completed.stdout}\n{completed.stderr}")
        return json.loads(completed.stdout)

    def freeze(self, experiment):
        args = ["init", "--output", self.run, "--rars", self.candidate,
                "--experiment", experiment, "--corpus", self.corpus_manifest,
                "--profile", "desktop", "--repository", REPOSITORY,
                "--seed", "47", "--plan", self.plan]
        if self.native is not None:
            args += ["--native-rar", self.native]
        self.manifest = self.cli(SCRIPT, *args)
        self.frozen_script = self.run / "frozen/hybrid_candidates.py"
        self.manifest_bytes = (self.run / "manifest.json").read_bytes()
        self.assertEqual(self.manifest, read_json(self.run / "manifest.json"))
        self.assertEqual(self.manifest["source"], self.source)
        self.assertEqual(self.manifest["runner_sha256"], sha(SCRIPT))
        self.assertEqual(self.manifest["budgets"], BUDGETS)
        self.assertEqual(self.manifest["task_timeout_seconds"], TASK_TIMEOUT)
        self.assertEqual(self.manifest["corpus_manifest_sha256"], sha(self.corpus_manifest))
        self.assertEqual(self.manifest["execution"]["screen_threads"], 1)
        self.assertEqual(self.manifest["execution"]["confirm_threads"], 1)
        self.assertFalse(self.manifest["execution"]["parallel_screening"])
        self.assertEqual(self.manifest["sample_roles"], ["native", "candidate"] if self.native else ["candidate"])
        self.assertEqual(set(self.manifest["binaries"]), {"native", "candidate", "baseline"} if self.native else {"candidate"})
        for role, binary in self.manifest["binaries"].items():
            source = self.native if role == "native" else self.candidate
            self.assertEqual(binary["source"], str(source))
            self.assertEqual(binary["sha256"], sha(source))
            self.assertEqual(binary["bytes"], source.stat().st_size)
        for case in self.manifest["cases"]:
            self.assertEqual(case["members"], self.expected)
            self.assertEqual(case["solid"], case["id"] == "solid")
            resources = case["control_settings"]["desktop"]
            self.assertEqual(resources["dictionary_bytes"], 128 * 1024)
            self.assertEqual(resources["memory_limit_bytes"], 256 * 1024**2)
            self.assertEqual(resources["encoder_threads"], 1)
        self.assert_frozen()

    def assert_frozen(self):
        self.assertEqual((self.run / "manifest.json").read_bytes(), self.manifest_bytes)
        manifest_sha = sha(self.run / "manifest.json")
        self.assertEqual((self.run / "manifest.sha256").read_text().strip(), manifest_sha)
        self.assertEqual(sha(self.frozen_script), self.manifest["runner_sha256"])
        for binary in self.manifest["binaries"].values():
            self.assertEqual(sha(self.run / binary["path"]), binary["sha256"])

    def journal(self):
        return [json.loads(line) for line in (self.run / "journal.jsonl").read_text().splitlines()]

    def assert_command(self, area, label):
        receipt = read_json(area / (label + ".json"))
        self.assertEqual(receipt["exit"], 0, receipt)
        self.assertFalse(receipt["timeout"], receipt)
        self.assertGreaterEqual(receipt["wall_seconds"], 0)
        self.assertLessEqual(receipt["wall_seconds"], TASK_TIMEOUT + 1)
        self.assertGreaterEqual(receipt["cpu_seconds"], 0)
        self.assertIsNone(receipt["io_bytes"])
        if sys.platform == "darwin" or sys.platform.startswith(("linux", "freebsd")):
            self.assertGreater(receipt["peak_rss_bytes"], 0)
        self.assertTrue((area / receipt["stdout"]).is_file())
        self.assertTrue((area / receipt["stderr"]).is_file())
        return receipt

    def assert_sample(self, row, roles, decoders):
        self.assertEqual(row["event"], "complete", row)
        self.assertEqual(row["task"]["phase"], "screen")
        self.assertEqual(row["task"]["repetition"], 0)
        self.assertEqual(row["task_id"], digest(row["task"])[:24])
        self.assertEqual(row["manifest_sha256"], sha(self.run / "manifest.json"))
        self.assertGreater(row["reserved_seconds"], 0)
        # Rounding begin + timeout can put deadline - begin just above the
        # timeout. Allow a microsecond even on hosts with long uptimes.
        self.assertLessEqual(row["reserved_seconds"], TASK_TIMEOUT + 1e-6)
        result_path = self.run / row["result"]
        self.assertEqual(sha(result_path), row["result_sha256"])
        result = read_json(result_path)
        self.assertEqual(result["task"], row["task"])
        self.assertEqual(result["execution"]["threads"], 1)
        self.assertEqual(set(result["roles"]), set(roles))
        self.assertIsNone(result["cold_extraction"])
        area = result_path.parent
        retained = {result_path: result_path.read_bytes()}
        for role, data in result["roles"].items():
            archive = area / (role + ".rar")
            archive_bytes = archive.read_bytes()
            self.assertTrue(archive_bytes.startswith(RAR5_MAGIC), "expected a real RAR5 archive, not ZIP")
            self.assertEqual(len(archive_bytes), data["archive_bytes"])
            self.assertEqual(sha(archive), data["archive_sha256"])
            retained[archive] = archive_bytes
            encoded = self.assert_command(area, role + "-encode")
            self.assertEqual(encoded, data["encode"])
            command = encoded["command"]
            self.assertEqual(command[0], str(self.run / self.manifest["binaries"][role]["path"]))
            if role == "native":
                for option in ("-mt1", "-m3", "-md128k", "-ma5", "-mc-"):
                    self.assertIn(option, command)
                self.assertIn("-s" if row["task"]["case"] == "solid" else "-s-", command)
            else:
                for option, value in (("--threads", "1"), ("--level", "3"),
                                      ("--dict-size", str(128 * 1024)),
                                      ("--memory-limit", str(256 * 1024**2)),
                                      ("--max-memory", str(256 * 1024**2))):
                    self.assertEqual(command[command.index(option) + 1], value)
                self.assertEqual("--solid" in command, row["task"]["case"] == "solid")
                self.assertNotIn("--experimental-hybrid", command)
            self.assertEqual(set(data["decoders"]), set(decoders))
            for decoder, decoded in data["decoders"].items():
                integrity = self.assert_command(area, role + "-" + decoder + "-integrity")
                extraction = self.assert_command(area, role + "-" + decoder + "-extract")
                frozen_binary = str(self.run / self.manifest["binaries"][decoder]["path"])
                self.assertEqual(integrity["command"][0], frozen_binary)
                self.assertEqual(extraction["command"][0], frozen_binary)
                for command in (integrity["command"], extraction["command"]):
                    if decoder == "native":
                        self.assertIn("-mt1", command)
                    else:
                        self.assertEqual(command[command.index("--threads") + 1], "1")
                self.assertEqual(decoded["extract"], extraction)
                self.assertEqual(decoded["verified_members"], len(self.expected))
                proof_path = area / decoded["verification_receipt"]
                self.assertEqual(sha(proof_path), decoded["verification_sha256"])
                proof = read_json(proof_path)
                self.assertTrue(proof["verified"])
                self.assertEqual(proof["task_id"], row["task_id"])
                self.assertEqual(proof["expected_tree_sha256"], digest(self.expected))
                members_path = area / proof["members_json"]
                self.assertEqual(sha(members_path), proof["members_sha256"])
                # These are trees produced by real extraction, including explicit
                # directories, file bytes, executable bits, and exact second mtimes.
                self.assertEqual(read_json(members_path), self.expected)
                self.assertTrue(decoded["successful_tree_removed"])
                self.assertFalse((area / (role + "-by-" + decoder)).exists())
        return retained

    def run_two_tasks(self, roles, decoders):
        first_run = self.cli(self.frozen_script, "run", self.run, "--max-tasks", "1")
        self.assertEqual(first_run, {"status": "paused-at-task-boundary", "tasks_run": 1})
        first_rows = [row for row in self.journal() if row.get("event") == "complete"]
        self.assertEqual(len(first_rows), 1, self.journal())
        first = first_rows[0]
        retained = self.assert_sample(first, roles, decoders)
        prefix = (self.run / "journal.jsonl").read_bytes()
        second_run = self.cli(self.frozen_script, "run", self.run, "--max-tasks", "1")
        self.assertEqual(second_run, {"status": "paused-at-task-boundary", "tasks_run": 1})
        self.assertTrue((self.run / "journal.jsonl").read_bytes().startswith(prefix))
        rows = self.journal()
        complete = [row for row in rows if row.get("event") == "complete"]
        self.assertEqual(len(complete), 2, rows)
        self.assertEqual({row["task"]["case"] for row in complete}, {"solid", "nonsolid"})
        self.assertEqual([row for row in complete if row["task_id"] == first["task_id"]], [first])
        self.assertEqual(len([row for row in rows if row.get("event") == "started"]), 2)
        self.assertFalse(any(row.get("event") in ("failed", "excluded") for row in rows), rows)
        self.assertFalse(any(row.get("task", {}).get("phase") == "confirm" for row in rows))
        for path, content in retained.items():
            self.assertEqual(path.read_bytes(), content)
        for row in complete:
            if row["task_id"] != first["task_id"]:
                retained.update(self.assert_sample(row, roles, decoders))
        self.assert_frozen()
        status = self.cli(self.frozen_script, "status", self.run)
        self.assertEqual(status["tasks"], {"started": 0, "complete": 2, "failed": 0, "interrupted": 0, "excluded": 0})
        self.assertIsNone(status["selection"])
        self.assertFalse((self.run / "selection.json").exists())
        return retained

    def test_compiled_rars_create_verify_extract_metadata_and_resume(self):
        self.prepare()
        self.freeze("smoke")
        retained = self.run_two_tasks(["candidate"], ["candidate"])
        prefix = (self.run / "journal.jsonl").read_bytes()
        finished = self.cli(self.frozen_script, "run", self.run, "--max-tasks", "1")
        self.assertEqual(finished["tasks_run"], 0)
        self.assertTrue((self.run / "journal.jsonl").read_bytes().startswith(prefix))
        self.assertEqual(len([row for row in self.journal() if row.get("event") == "started"]), 2)
        self.assertFalse((self.run / "selection.json").exists())
        for path, content in retained.items():
            self.assertEqual(path.read_bytes(), content)
        self.assert_frozen()

    def test_native_rar_two_encoder_comparison_and_cross_decoding(self):
        self.prepare(native=True)
        self.freeze("controls")
        # Two screen tasks only: each verifies both real encoders using both
        # decoders, yielding four independent extraction proofs per task.
        self.run_two_tasks(["native", "candidate"], ["native", "candidate"])


if __name__ == "__main__":
    unittest.main()
