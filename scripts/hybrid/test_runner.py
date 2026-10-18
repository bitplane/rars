"""Mechanical runner controls; no native RAR installation or performance claim."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "hybrid_candidates.py"
spec = importlib.util.spec_from_file_location("hybrid_candidates", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

FAKE = r'''#!/usr/bin/env python3
import json,os,stat,sys,time,zipfile
from pathlib import Path
args=sys.argv[1:]
if '--fake-sleep' in args: time.sleep(2)
archive=next((Path(a) for a in args if a.endswith('.rar')),None)
if archive is None: raise SystemExit(3)
if 'a' in args:
    hybrid='--experimental-hybrid' in args
    if '--fail-native' in args:raise SystemExit(18)
    if hybrid and '--fail-hybrid' in args: raise SystemExit(17)
    metadata={}
    names=args[args.index(str(archive))+1:]
    paths=[]
    for name in names:
        p=Path(name);paths.append(p)
        if p.is_dir():paths.extend(sorted(p.rglob('*')))
    with zipfile.ZipFile(archive,'w') as z:
        for p in paths:
            s=p.stat();name=p.as_posix()
            mode=stat.S_IMODE(s.st_mode)
            if hybrid and '--bad-hybrid-mode' in args and not p.is_dir(): mode^=0o100
            metadata[name]={'mode':mode,'mtime':int(s.st_mtime),'directory':p.is_dir()}
            if not p.is_dir():z.writestr(name,p.read_bytes())
        z.writestr('__fake_metadata',json.dumps(metadata))
    if hybrid:
        variant=int(args[args.index('--hybrid-variant')+1])
        with archive.open('ab') as f:f.write(b'x'*variant)
elif 'lt' in args:
    print('Fake archive metadata: ZIP fixture, not RAR')
elif 'lb' in args:
    with zipfile.ZipFile(archive) as z:
        print('\n'.join(json.loads(z.read('__fake_metadata'))))
elif 't' in args or 'test' in args:
    with zipfile.ZipFile(archive) as z:
        if z.testzip():raise SystemExit(19)
elif 'x' in args or 'extract' in args:
    tail=args[args.index(str(archive))+1:]
    out=Path(tail[-1]);out.mkdir(parents=True,exist_ok=True)
    requested=tail[:-1]
    with zipfile.ZipFile(archive) as z:
        meta=json.loads(z.read('__fake_metadata'))
        if requested:meta={name:m for name,m in meta.items() if name in requested}
        for name,m in meta.items():
            p=out/name
            if m['directory']:p.mkdir(parents=True,exist_ok=True)
            else:p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(name))
        for name,m in sorted(meta.items(),key=lambda item:len(Path(item[0]).parts),reverse=True):
            p=out/name;p.chmod(m['mode']);os.utime(p,(m['mtime'],m['mtime']))
else:raise SystemExit(5)
'''


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        (self.corpus / "folder").mkdir()
        payload = self.corpus / "folder/data.txt"
        payload.write_bytes(b"small actual content\n")
        payload.chmod(0o640)
        os.utime(payload, (1700000000, 1700000000))
        self.manifest = self.corpus / "manifest.json"
        runner.write_json(self.manifest, {"files": [{"path": "folder/data.txt", "sha256": runner.sha(payload)}],
            "workloads": [{"id": "small", "files": ["folder/data.txt"]}]})
        self.fake = self.root / "fake"
        self.fake.write_text(FAKE)
        self.fake.chmod(0o755)
        self.run = self.root / "run"
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        (self.repository / "tracked").write_text("frozen source")
        subprocess.run(["git", "-C", str(self.repository), "add", "tracked"], check=True)
        subprocess.run(["git", "-C", str(self.repository), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)

    def tearDown(self):
        self.temp.cleanup()

    def freeze(self, **plan):
        path = self.root / "plan.json"
        runner.write_json(path, plan)
        args = argparse.Namespace(output=self.run, corpus=self.manifest, plan=path,
            profile=["desktop"], inventory=getattr(self, "inventory", None), rars=self.fake, baseline=None,
            native_rar=self.fake, repository=self.repository, seed=47)
        return runner.freeze(args)

    def test_exact_matrix_and_boundary_validation(self):
        matrix = runner.configs(["desktop", "server"])
        self.assertEqual(len(matrix), 128)
        self.assertEqual([x["variant"] for x in matrix[:64]], list(range(64)))
        for c in matrix:
            self.assertEqual([c["choices"][b] for b in runner.BITS], [bool(c["variant"] & (1 << i)) for i in range(6)])
        for name in (".", "../bad", "name\nline", "@response"):
            with self.assertRaises(runner.RunError):runner.relative_name(name)
        for wrong in [-1, 64, True, 1.5]:
            with self.assertRaises(runner.RunError): runner.choices(wrong)
        with self.assertRaises(runner.RunError): runner.configs(["desktop", "desktop"])

    def test_execute_reports_peak_rss_in_platform_units(self):
        usage = mock.Mock(ru_maxrss=1234, ru_utime=1, ru_stime=2, ru_inblock=0, ru_oublock=0)
        process = mock.Mock(pid=42)
        for system, expected in (("darwin", 1234), ("linux", 1234 * 1024),
                                 ("freebsd14", 1234 * 1024), ("freebsd15", 1234 * 1024),
                                 ("unknown", None)):
            with self.subTest(platform=system), \
                 mock.patch.object(runner.sys, "platform", system), \
                 mock.patch.object(runner.subprocess, "Popen", return_value=process), \
                 mock.patch.object(runner.os, "wait4", return_value=(42, 0, usage)):
                result = runner.execute(["frozen-encoder"], self.root, self.root,
                                        system, time.monotonic() + 5, {})
                self.assertEqual(result["peak_rss_bytes"], expected)

    def test_freeze_hashes_and_stable_tasks(self):
        m = self.freeze()
        self.assertEqual(m, runner.load(self.run))
        self.assertEqual(runner.tasks(m, "screen"), runner.tasks(m, "screen"))
        self.assertEqual(len({runner.task_id(t) for t in runner.tasks(m, "screen")}), 64)
        confirm = runner.tasks(m, "confirm", ["desktop-00"])
        self.assertEqual(len(confirm), 16)
        self.assertEqual([x["repetition"] for x in confirm], list(range(-1, 15)))
        (self.run / m["binaries"]["native"]["path"]).write_bytes(b"modified")
        with self.assertRaisesRegex(runner.RunError, "executable changed"): runner.load(self.run)

    def test_real_fake_tool_smoke_resume_and_metadata(self):
        self.freeze()
        first = runner.worker(self.run, "local", 1)
        self.assertEqual(first["status"], "paused-at-task-boundary")
        rows = runner.latest(runner.journal(self.run))
        self.assertEqual(len(rows), 1)
        receipt = next(iter(rows.values()))
        self.assertEqual(receipt["event"], "complete")
        data = runner.read_json(self.run / receipt["result"])
        self.assertIsNone(data["cold_extraction"])
        self.assertTrue(all(role["cold_selective"] is None for role in data["roles"].values()))
        self.assertEqual(set(data["roles"]), {"candidate", "baseline", "native", "relationships", "streams", "native_ordered"})
        self.assertTrue(data["roles"]["native_ordered"]["ordering_assisted"])
        self.assertEqual(data["candidate_member_order"], data["roles"]["native_ordered"]["verified_member_order"])
        for role in data["roles"].values():
            self.assertEqual(role["decoders"]["native"]["verified_members"], 2)
            self.assertEqual(role["decoders"]["candidate"]["verified_members"], 2)
            self.assertGreater(role["encode"]["peak_rss_bytes"], 0)
            self.assertIsNone(role["encode"]["io_bytes"])
        runner.worker(self.run, "local", 1)
        self.assertEqual(len(runner.latest(runner.journal(self.run))), 2)
        self.assertEqual(runner.latest(runner.journal(self.run))[receipt["task_id"]], receipt)

    def test_candidate_failure_is_retained_and_never_retried(self):
        self.freeze(worker_options={"rars_add": ["--fail-hybrid"]})
        runner.worker(self.run, "local", 1)
        first = next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(first["event"], "failed")
        self.assertFalse(first["control_failure"])
        runner.worker(self.run, "local", 1)
        self.assertEqual(runner.latest(runner.journal(self.run))[first["task_id"]], first)

    def test_metadata_loss_is_a_failure_not_listing_success(self):
        self.freeze(worker_options={"rars_add": ["--bad-hybrid-mode"]})
        runner.worker(self.run, "local", 1)
        row = next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"], "failed")
        self.assertIn("supported-metadata mismatch", row["error"])
        area=self.run/"tasks"/row["task_id"]
        retained=[path for path in area.glob("*-by-native") if path.is_dir()]
        self.assertEqual(len(retained),1)
        failed_role=retained[0].name.removesuffix("-by-native")
        self.assertIn(failed_role,{"candidate","relationships","streams"})
        self.assertTrue((area/(failed_role+".rar")).is_file())
        self.assertFalse((area/(failed_role+"-native-verified.json")).exists())

    def test_exhausted_and_interrupted_budget_never_restarts(self):
        m = self.freeze(budgets={"screen": .03, "confirm": .03},
                        worker_options={"rars_add": ["--fake-sleep"], "native_add": ["--fake-sleep"]})
        runner.worker(self.run, "local")
        rows = runner.journal(self.run)
        self.assertEqual(len(runner.latest(rows)), 1)
        self.assertGreater(runner.consumed(rows, "screen", "local"), .02)
        task = runner.tasks(m, "confirm", ["desktop-00"])[0]
        with runner.locked(self.run / "journal.lock"):
            runner.append(self.run, {"event": "started", "task": task, "task_id": runner.task_id(task), "host": "local", "reserved_seconds": .03})
        self.assertEqual(runner.available(m, runner.journal(self.run), "confirm", "local"), 0)

    def test_path_escape_and_matrix_owned_options_refused(self):
        m = runner.read_json(self.manifest); m["files"][0]["path"] = "../bad"
        runner.write_json(self.manifest, m)
        with self.assertRaises(runner.RunError): self.freeze()
        self.assertTrue((self.run / "INIT_FAILED").exists())
        shutil.rmtree(self.run)
        with self.assertRaisesRegex(runner.RunError, "matrix-owned"):
            self.freeze(worker_options={"rars_add": ["--hybrid-variant=7"]})

    def test_exclusive_host_lock_and_unknown_host(self):
        self.freeze()
        with self.assertRaisesRegex(runner.RunError, "inventory"):
            runner.worker(self.run, "unknown", 1)
        lock = self.root / "lock"
        with runner.locked(lock):
            with self.assertRaises(runner.RunError):
                with runner.locked(lock, blocking=False): pass

    def test_export_and_receipt_import_are_hash_bound_and_idempotent(self):
        self.freeze()
        archive = self.root / "worker.tar.gz"
        runner.export_worker(self.run, "local", archive)
        unpack = self.root / "unpack"
        unpack.mkdir()
        with tarfile.open(archive) as t:
            # This archive was generated in this test from trusted local paths.
            self.assertTrue(all(not Path(x.name).is_absolute() and ".." not in Path(x.name).parts for x in t.getmembers()))
            t.extractall(unpack)
        other = unpack / "hybrid-run"
        runner.worker(other, "local", 1)
        self.assertEqual(runner.import_results(self.run, other)["imported_tasks"], 1)
        self.assertEqual(runner.import_results(self.run, other)["imported_tasks"], 0)
        row = next(iter(runner.latest(runner.journal(other)).values()))
        (other / row["result"]).write_text("{}")
        third = self.root / "third"
        shutil.copytree(self.run, third)
        (third / "journal.jsonl").write_text("")
        shutil.rmtree(third / "tasks")
        with self.assertRaisesRegex(runner.RunError, "path/hash"):
            runner.import_results(third, other)

    def test_control_failure_stops_the_run(self):
        self.freeze(worker_options={"native_add": ["--fail-native"]})
        with self.assertRaisesRegex(runner.RunError, "control failed"):
            runner.worker(self.run, "local")
        rows = list(runner.latest(runner.journal(self.run)).values())
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["control_failure"])

    def test_manifest_and_input_changes_and_torn_journal_fail_closed(self):
        self.freeze()
        # Frozen copies are independent of later changes to the original files.
        (self.corpus / "folder/data.txt").write_text("original changed")
        runner.worker(self.run, "local", 1)
        row = next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"], "complete")
        (self.run / "frozen/cases/small/folder/data.txt").write_text("frozen changed")
        with self.assertRaisesRegex(runner.RunError, "control failed"):
            runner.worker(self.run, "local", 1)
        with (self.run / "journal.jsonl").open("a") as stream:stream.write('{"event":')
        with self.assertRaisesRegex(runner.RunError, "torn journal"):
            runner.journal(self.run)
        (self.run / "manifest.json").write_text("{}")
        with self.assertRaisesRegex(runner.RunError, "manifest hash changed"):
            runner.load(self.run)

    def test_cli_local_smoke(self):
        command = [sys.executable, str(SCRIPT), "init", "--output", str(self.run),
                   "--rars", str(self.fake), "--native-rar", str(self.fake),
                   "--corpus", str(self.manifest), "--repository", str(self.repository)]
        init = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(init.returncode, 0, init.stderr)
        worker = subprocess.run([sys.executable, str(SCRIPT), "run", str(self.run), "--max-tasks", "1"], capture_output=True, text=True)
        self.assertEqual(worker.returncode, 0, worker.stderr)
        self.assertEqual(json.loads(worker.stdout)["tasks_run"], 1)
        status = subprocess.run([sys.executable, str(SCRIPT), "status", str(self.run)], capture_output=True, text=True)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["tasks"]["complete"], 1)

    def test_empty_directories_and_directory_metadata_are_verified(self):
        empty = self.corpus / "empty"
        empty.mkdir();empty.chmod(0o750);os.utime(empty,(1700000003,1700000003))
        manifest=runner.read_json(self.manifest)
        manifest["files"].append({"path":"empty", "type":"directory"})
        manifest["workloads"][0]["files"].append("empty")
        runner.write_json(self.manifest,manifest)
        self.freeze()
        runner.worker(self.run,"local",1)
        row=next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"],"complete")
        m=runner.load(self.run);self.assertEqual(m["cases"][0]["members"]["empty"]["mode"],0o750)
        actual=runner.snapshot_tree(self.run/"frozen/cases/small")
        (self.run/"frozen/cases/small/empty").chmod(0o700)
        with self.assertRaises(runner.RunError):runner.validate_tree(runner.snapshot_tree(self.run/"frozen/cases/small"),actual)

    def test_dirty_or_untracked_source_is_not_a_frozen_revision(self):
        (self.repository/"untracked.py").write_text("uncommitted")
        with self.assertRaisesRegex(runner.RunError,"clean committed"):
            self.freeze()
        self.assertFalse(self.run.exists())

    def test_explicit_ssh_inventory_has_structured_quoted_commands(self):
        host={"id":"worker1","kind":"ssh","hostname":"worker1.example","ssh_target":"user@worker1.example", "remote_directory":"/work/rars-run", "port":2222}
        command=runner.ssh_argv(host,"python3 /work/run.py")
        self.assertEqual(command[-2:],["user@worker1.example","python3 /work/run.py"])
        self.assertIn("2222",command)
        with self.assertRaises(runner.RunError):runner.ssh_argv({**host,"ssh_target":"-oProxyCommand=bad"},"true")
        with self.assertRaises(runner.RunError):runner.ssh_argv({**host,"remote_directory":"/work/a;bad"},"true")

    def cache_helper(self, body):
        path=self.root/"cache-helper"
        path.write_text("#!/usr/bin/env python3\n"+body+"\n")
        path.chmod(0o755)
        return path

    def test_frozen_cold_selective_uses_exact_member_and_literal_argv(self):
        extra=self.corpus/"folder/z-last.txt"
        extra.write_bytes(b"deterministic selected bytes")
        extra.chmod(0o600);os.utime(extra,(1700000009,1700000009))
        corpus=runner.read_json(self.manifest)
        corpus["files"].append({"path":"folder/z-last.txt","sha256":runner.sha(extra)})
        corpus["workloads"][0]["files"].append("folder/z-last.txt")
        runner.write_json(self.manifest,corpus)
        helper=self.cache_helper("import json,sys; print(json.dumps(sys.argv[1:]))")
        m=self.freeze(cold_prepare=[str(helper),"literal; $(not-a-command)","{archive}"])
        self.assertIn("operator-supplied",m["cold_scope"])
        self.assertEqual(runner.sha(self.run/m["binaries"]["cold_prepare"]["path"]),runner.sha(helper))
        helper.write_text("original helper changed after freeze")
        runner.worker(self.run,"local",1)
        row=next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"],"complete")
        area=self.run/"tasks"/row["task_id"]
        result=runner.read_json(self.run/row["result"])
        self.assertEqual(set(result["cold_extraction"]),set(result["roles"]))
        for name,role in result["roles"].items():
            cold=role["cold_selective"]
            self.assertTrue(cold["available"])
            self.assertEqual(cold["requested_member"],"folder/z-last.txt")
            self.assertEqual(cold["extract"]["command"][-2],"folder/z-last.txt")
            self.assertGreater(cold["extract"]["wall_seconds"],0)
            self.assertGreater(cold["extract"]["peak_rss_bytes"],0)
            self.assertFalse((area/(name+"-cold-selective")).exists())
            args=json.loads((area/cold["preparation"]["stdout"]).read_text())
            self.assertEqual(args,["literal; $(not-a-command)",str((area/(name+".rar")).resolve())])
            proof=runner.read_json(area/cold["verification_receipt"])
            actual=runner.read_json(area/proof["members_json"])
            self.assertEqual(set(actual),{"folder","folder/z-last.txt"})
            self.assertNotIn("folder/data.txt",actual)
            self.assertEqual(set(role["decoders"]),{"native","candidate"})
        runner.verified_results(self.run,runner.journal(self.run),"screen")
        cold=result["roles"]["candidate"]["cold_selective"]
        (area/cold["verification_receipt"]).write_text("{}")
        with self.assertRaisesRegex(runner.RunError,"verification receipt changed"):
            runner.verified_results(self.run,runner.journal(self.run),"screen")

    def test_cold_helper_mutation_failure_and_no_implicit_command(self):
        helper=self.cache_helper("raise SystemExit(7)")
        m=self.freeze(cold_prepare=[str(helper),"{archive}"])
        runner.worker(self.run,"local",1)
        row=next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"],"failed")
        self.assertIn("cold-prepare exited 7",row["error"])
        area=self.run/"tasks"/row["task_id"]
        self.assertEqual(list(area.glob("*-cold-selective-extract.json")),[])
        frozen=self.run/m["binaries"]["cold_prepare"]["path"]
        frozen.write_text("mutated frozen command")
        with self.assertRaisesRegex(runner.RunError,"executable changed"):
            runner.load(self.run)

    def test_cold_preparation_cannot_change_archive(self):
        helper=self.cache_helper("import sys; from pathlib import Path; p=Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b'changed')")
        self.freeze(cold_prepare=[str(helper),"{archive}"])
        runner.worker(self.run,"local",1)
        row=next(iter(runner.latest(runner.journal(self.run)).values()))
        self.assertEqual(row["event"],"failed")
        self.assertIn("preparation changed the measured archive",row["error"])
        area=self.run/"tasks"/row["task_id"]
        self.assertTrue(any(p.is_dir() for p in area.glob("*-cold-selective")))

    def test_cold_option_validation_and_directory_only_unavailability(self):
        for option in ([],"shell command",["relative-helper"],["/bin/sh","-c","anything"]):
            with self.assertRaises(runner.RunError):self.freeze(cold_prepare=option)
            self.assertFalse(self.run.exists())
        helper=self.cache_helper("raise SystemExit('must not run')")
        m=self.freeze(cold_prepare=[str(helper)])
        case={"members":{"empty":{"type":"directory","mode":0o755,"mtime":1700000000}}}
        with mock.patch.object(runner,"execute") as command:
            result=runner.cold_selective(self.run,m,{},case,self.root,self.root/"none.rar","role","unused",time.monotonic()+5,{})
        self.assertFalse(result["available"])
        self.assertIn("no requested regular",result["reason"])
        command.assert_not_called()

    def test_dispatch_runs_hosts_concurrently_with_stable_phase_order(self):
        hosts=[{"id":"remote","kind":"ssh"},{"id":"local","kind":"local"},
               {"id":"offline","kind":"export"}]
        barrier=threading.Barrier(2)
        lock=threading.Lock()
        calls={"remote":0,"local":0}
        def invoke(host_id):
            with lock:
                phase=calls[host_id]
                calls[host_id]+=1
            # Serial dispatch cannot cross this barrier. Both phases must
            # overlap hosts, while their returned order stays deterministic.
            barrier.wait(timeout=3)
            return {"phase":phase}
        with mock.patch.object(runner,"load",return_value={"hosts":hosts}), \
             mock.patch.object(runner,"worker",side_effect=lambda run,host:invoke(host)), \
             mock.patch.object(runner,"dispatch_ssh",side_effect=lambda run,host:invoke(host["id"])), \
             mock.patch.object(runner,"journal",return_value=[]), \
             mock.patch.object(runner,"report",return_value={"complete":True}):
            result=runner.dispatch(self.run)
        self.assertEqual([row["host"] for row in result["workers"]],
                         ["remote","local","offline"]*2)
        self.assertEqual([row["phase"] for row in result["workers"] if "phase" in row],
                         [0,0,1,1])
        self.assertEqual(calls,{"remote":2,"local":2})
        self.assertEqual(result["summary"],{"complete":True})

    def test_solid_auto_combinations_are_frozen_excluded_without_children(self):
        corpus=runner.read_json(self.manifest)
        corpus["workloads"][0]["solid"]=True
        runner.write_json(self.manifest,corpus)
        m=self.freeze(budgets={"screen":10,"confirm":10})
        self.assertEqual(len(m["configurations"]),64)
        self.assertEqual(len(m["invalid_combinations"]),32)
        self.assertEqual(runner.valid_cases(m,"desktop-08"),set())
        calls=[]
        def fixture(run,manifest,task,deadline):
            variant=int(task["configuration"].rsplit("-",1)[1])
            self.assertEqual(variant&8,0)
            calls.append(task)
            roles={}
            for role in ("native","baseline","candidate","relationships","streams","native_ordered"):
                delta=variant if role=="candidate" else 0
                roles[role]={"encode":{"wall_seconds":1+delta,"cpu_seconds":.5+delta,"peak_rss_bytes":100+delta},
                             "archive_bytes":100+delta,"decoders":{"candidate":{"extract":{"wall_seconds":1+delta}}}}
            value={"task":task,"roles":roles}
            path=run/"tasks"/runner.task_id(task)/"result.json";path.parent.mkdir(parents=True)
            runner.write_json(path,value)
            return value
        with mock.patch.object(runner,"sample",side_effect=fixture),mock.patch.object(runner,"execute") as process:
            runner.worker(self.run,"local")
        process.assert_not_called()
        self.assertEqual(len(calls),48)
        report=runner.report(self.run)
        self.assertEqual(report["tasks"]["excluded"],32)
        self.assertEqual(report["selection"]["eligible_configurations"],32)
        self.assertEqual(report["selection"]["coverage"]["desktop-08"]["valid_workloads"],[])
        self.assertNotIn("desktop-08",report["qualified_finalists"])
        self.assertEqual(report["qualified_finalists"]["desktop-00"]["applicable_workloads"],["small"])
        case=m["cases"][0];archive=self.root/"out.rar"
        off=m["configurations"][0];on=m["configurations"][8]
        for role in ("candidate","relationships","streams"):
            self.assertIn("--no-filter",runner.compression_command(m,self.run,role,off,case,archive))
            self.assertIn("--auto-filter",runner.compression_command(m,self.run,role,on,case,archive))
        m["worker_options"]={"rars_add":["--delta-filter","1"]}
        command=runner.compression_command(m,self.run,"candidate",on,case,archive)
        self.assertNotIn("--auto-filter",command)
        self.assertNotIn("--no-filter",command)

    def test_success_cleanup_keeps_durable_proofs_and_resume(self):
        self.freeze()
        runner.worker(self.run,"local",1)
        row=next(iter(runner.latest(runner.journal(self.run)).values()))
        path=self.run/row["result"]
        data=runner.read_json(path)
        for role_name,role in data["roles"].items():
            self.assertTrue((path.parent/(role_name+".rar")).is_file())
            for decoder_name,decoder in role["decoders"].items():
                self.assertFalse((path.parent/(role_name+"-by-"+decoder_name)).exists())
                self.assertTrue((path.parent/decoder["verification_receipt"]).is_file())
        runner.verified_results(self.run,runner.journal(self.run),"screen")
        runner.worker(self.run,"local",1)
        self.assertEqual(len(runner.latest(runner.journal(self.run))),2)
        proof=path.parent/data["roles"]["candidate"]["decoders"]["native"]["verification_receipt"]
        proof.write_text("{}")
        with self.assertRaisesRegex(runner.RunError,"verification receipt changed"):
            runner.verified_results(self.run,runner.journal(self.run),"screen")

    def test_configuration_blocks_and_within_host_ratio_promotion(self):
        m=self.freeze()
        m["cases"].append({**m["cases"][0],"id":"another"})
        generated=runner.tasks(m,"screen")
        for index in range(0,len(generated),2):
            self.assertEqual(generated[index]["configuration"],generated[index+1]["configuration"])
            self.assertEqual({generated[index]["case"],generated[index+1]["case"]},{"small","another"})
            self.assertEqual(runner.host_for(m,generated[index]),runner.host_for(m,generated[index+1]))
        m["cases"]=m["cases"][:1]
        rows=[]
        for variant,wall,native_wall in [(0,100,1000),(1,10,20)]:
            task={"phase":"screen","configuration":f"desktop-{variant:02d}","case":"small","repetition":0}
            def role(wall,rss):return {"encode":{"wall_seconds":wall,"peak_rss_bytes":rss},"archive_bytes":100,"decoders":{"candidate":{"extract":{"wall_seconds":wall}}}}
            value={"task":task,"host":{"hostname":f"host-{variant}"},"roles":{"candidate":role(wall,10),"native":role(native_wall,100 if variant==0 else 20)}}
            path=self.run/"tasks"/runner.task_id(task)/"result.json";path.parent.mkdir(parents=True)
            runner.write_json(path,value)
            rows.append({"event":"complete","task":task,"task_id":runner.task_id(task),"host":"local","result":str(path.relative_to(self.run)),"result_sha256":runner.sha(path)})
        selection=runner.choose_finalists(self.run,m,rows)
        self.assertEqual(selection["finalists"],["desktop-00"])
        self.assertAlmostEqual(selection["screen_metrics"]["desktop-00"][0],.1)
        values=runner.verified_results(self.run,rows,"screen")
        frontiers=runner.absolute_frontiers(values)
        self.assertAlmostEqual(frontiers["small@host-0"]["absolute_candidate_metrics"]["desktop-00"][0],100)

    def test_finalists_compare_identical_workloads_and_round_robin_coverage_groups(self):
        m=self.freeze()
        m["cases"]=[{**m["cases"][0],"id":name} for name in ("small","solid","third")]
        measured={"desktop-00":[2,2,2,2],"desktop-01":[3,3,3,3],
                  "desktop-02":[1,4,4,4],"desktop-08":[.01]*4,"desktop-16":[.02]*4}
        m["configurations"]=[c for c in m["configurations"] if c["id"] in measured]
        m["invalid_combinations"]=[{"configuration":"desktop-08","case":"solid"},
                                   {"configuration":"desktop-16","case":"third"}]
        rows=[]
        def role(metric):
            wall,size,rss,decode=metric
            return {"encode":{"wall_seconds":wall,"peak_rss_bytes":rss},"archive_bytes":size,
                    "decoders":{"candidate":{"extract":{"wall_seconds":decode}}}}
        for configuration,metric in measured.items():
            for case in sorted(runner.valid_cases(m,configuration)):
                task={"phase":"screen","configuration":configuration,"case":case,"repetition":0}
                value={"task":task,"roles":{"candidate":role(metric),"native":role([1]*4)}}
                path=self.run/"tasks"/runner.task_id(task)/"result.json"
                path.parent.mkdir(parents=True)
                runner.write_json(path,value)
                rows.append({"event":"complete","task":task,"task_id":runner.task_id(task),"host":"local",
                             "result":str(path.relative_to(self.run)),"result_sha256":runner.sha(path)})
        selection=runner.choose_finalists(self.run,m,rows)
        # Tiny ratios on partial coverage must not dominate complete coverage.
        # Equal-size groups use their stable workload signatures, not scores.
        self.assertEqual(selection["finalists"],["desktop-00","desktop-16","desktop-08"])
        self.assertEqual(selection["eligible_configurations"],5)
        # After one turn per group, the next full-coverage frontier member wins
        # the third slot; its dominated sibling never enters the round robin.
        rows=[row for row in rows if row["task"]["configuration"]!="desktop-16"]
        self.assertEqual(runner.choose_finalists(self.run,m,rows)["finalists"],
                         ["desktop-00","desktop-08","desktop-02"])

    def test_nested_file_implicit_parent_has_path_type_not_unrequested_metadata(self):
        m=self.freeze()
        case=m["cases"][0]
        self.assertEqual(case["archive_members"],["folder/data.txt"])
        self.assertEqual(case["header_members"],["folder/data.txt"])
        self.assertEqual(case["members"]["folder"],{"type":"directory","implicit_parent":True})
        actual=runner.snapshot_tree(self.run/case["input_path"])
        actual["folder"]["mtime"]+=1000
        actual["folder"]["mode"]^=0o100
        runner.validate_tree(actual,case["members"])
        actual["folder"]["type"]="file"
        with self.assertRaises(runner.RunError):runner.validate_tree(actual,case["members"])

    def test_architecture_controls_and_assisted_order_are_explicit(self):
        m=self.freeze()
        c=next(c for c in m["configurations"] if c["variant"]==63)
        case=m["cases"][0];archive=self.root/"archive.rar"
        relationship=runner.compression_command(m,self.run,"relationships",c,case,archive)
        self.assertIn("relationships",relationship)
        self.assertIn("--analyze-relationships",relationship)
        self.assertIn("--optimize-member-order",relationship)
        stream=runner.compression_command(m,self.run,"streams",c,case,archive)
        self.assertEqual(stream[stream.index("--hybrid-variant")+1],"15")
        self.assertNotIn("--dict-size",stream)
        self.assertNotIn("--analyze-relationships",stream)
        self.assertNotIn("--optimize-member-order",stream)
        ordered=runner.compression_command(m,self.run,"native_ordered",c,case,archive,["folder/data.txt","folder"])
        self.assertIn("-ds",ordered)
        self.assertEqual(ordered[-2:],["folder/data.txt","folder"])
        with self.assertRaises(runner.RunError):runner.relative_name("name\nnew-line")

    def test_analysis_order_dictionary_and_resource_controls_are_unconfounded(self):
        m=self.freeze()
        case=m["cases"][0];archive=self.root/"archive.rar"
        self.assertEqual(case["control_settings"]["desktop"],runner.control_settings("desktop",case))
        for variant in (0,16,32,48):
            configuration=next(c for c in m["configurations"] if c["variant"]==variant)
            for role in ("candidate","relationships","streams"):
                command=runner.compression_command(m,self.run,role,configuration,case,archive)
                self.assertNotIn("--dict-size",command)
                self.assertEqual("--analyze-relationships" in command,role!="streams")
                self.assertEqual("--optimize-member-order" in command,role!="streams" and bool(variant&16))
                self.assertEqual(command[command.index("--memory-limit")+1],str(256*1024**2))
                self.assertEqual(command[command.index("--max-memory")+1],str(256*1024**2))
        for solid,sizes,desktop,server in (
            (False,[0],128*1024,128*1024),
            (False,[128*1024],128*1024,128*1024),
            (False,[131073,200000],256*1024,256*1024),
            (True,[100000,100000],256*1024,256*1024),
            (False,[5*1024**2],4*1024**2,8*1024**2),
            (True,[40*1024**2]*2,4*1024**2,64*1024**2)):
            fixture={"solid":solid,"archive_members":["member"],
                     "members":{str(i):{"type":"file","bytes":size} for i,size in enumerate(sizes)}}
            for profile,expected in (("desktop",desktop),("server",server)):
                configuration=runner.configs([profile])[0]
                settings=runner.control_settings(profile,fixture)
                self.assertEqual(settings["dictionary_bytes"],expected)
                self.assertEqual(settings["dictionary_reach_bytes"],sum(sizes) if solid else max(sizes))
                for role in ("native","native_ordered"):
                    command=runner.compression_command(m,self.run,role,configuration,fixture,archive)
                    self.assertIn(f"-md{expected//1024}k",command)
                    self.assertIn("-mt1",command)
                cap=256*1024**2 if profile=="desktop" else 8*1024**3
                for role in ("baseline","candidate","relationships","streams"):
                    command=runner.compression_command(m,self.run,role,configuration,fixture,archive)
                    self.assertEqual(command[command.index("--threads")+1],"1")
                    self.assertEqual(command[command.index("--memory-limit")+1],str(cap))
                    self.assertEqual(command[command.index("--max-memory")+1],str(cap))
                    if role=="baseline":
                        self.assertEqual(command[command.index("--dict-size")+1],str(expected))
                    else:
                        self.assertNotIn("--dict-size",command)
        with self.assertRaisesRegex(runner.RunError,"member sizes"):
            runner.control_settings("desktop",{"solid":False,"members":{"bad":{"type":"file","bytes":-1}}})

    def test_matrix_dictionary_thread_and_memory_overrides_refused_before_freeze(self):
        for channel,flags in (
            ("rars_add",["--dict-size","8m"]),("rars_add",["--hybrid-dictionary-ceiling=8m"]),
            ("rars_add",["--threads=2"]),("rars_read",["--threads","2"]),
            ("rars_add",["--memory-limit","1g"]),("rars_add",["--max-memory=1g"]),
            ("native_add",["-MD4m"]),("native_add",["-mt2"]),("native_read",["-mt2"])):
            with self.assertRaisesRegex(runner.RunError,"matrix-owned"):
                self.freeze(worker_options={channel:flags})
            self.assertFalse(self.run.exists())

    def test_validation_consumes_deadline_before_any_child_is_launched(self):
        m=self.freeze()
        task=runner.tasks(m,"screen")[0]
        case=m["cases"][0]
        real_sha=runner.sha
        clock=[100.0]
        target=(self.run/case["input_path"]/"folder/data.txt").resolve()
        def slow_validation(path,deadline=None):
            if Path(path).resolve()==target:
                clock[0]=106.0
                runner.check_deadline(deadline)
            return real_sha(path,deadline)
        with mock.patch.object(runner.time,"monotonic",side_effect=lambda:clock[0]), mock.patch.object(runner,"sha",side_effect=slow_validation), mock.patch.object(runner,"execute") as child:
            with self.assertRaisesRegex(runner.RunError,"reservation exhausted"):
                runner.sample(self.run,m,task,105.0)
        child.assert_not_called()

    def test_whole_unattended_screen_selection_and_15_pair_confirmation(self):
        self.freeze(budgets={"screen": 10, "confirm": 10})
        def measured_fixture(run, m, task, reservation):
            i=int(task["configuration"].rsplit("-",1)[1])
            roles={}
            for role in ("native","baseline","candidate","relationships","streams","native_ordered"):
                delta=i if role=="candidate" else 0
                roles[role]={"encode":{"wall_seconds":1+delta,"cpu_seconds":.5+delta,"peak_rss_bytes":100+delta},
                             "archive_bytes":100+delta,"decoders":{"candidate":{"extract":{"wall_seconds":1+delta}}}}
            result={"task":task,"roles":roles}
            path=run/"tasks"/runner.task_id(task)/"result.json"
            path.parent.mkdir(parents=True)
            runner.write_json(path,result)
            return result
        with mock.patch.object(runner,"sample",side_effect=measured_fixture):
            result=runner.worker(self.run,"local")
        self.assertEqual(result["status"],"finished-or-budget-exhausted")
        self.assertEqual(result["tasks_run"],80)
        report=runner.report(self.run)
        self.assertEqual(report["selection"]["finalists"],["desktop-00"])
        self.assertEqual(report["qualified_finalists"]["desktop-00"]["paired_repetitions_per_case"],15)
        completed=[r for r in runner.journal(self.run) if r.get("event")=="complete" and r["task"]["phase"]=="confirm"]
        self.assertEqual([r["task"]["repetition"] for r in completed],list(range(-1,15)))
        self.assertEqual(runner.worker(self.run,"local")["tasks_run"],0)

    def test_mocked_explicit_ssh_dispatch_imports_receipt(self):
        self.inventory=self.root/"hosts.json"
        host={"id":"worker1","kind":"ssh","hostname":socket.gethostname(),"ssh_target":"user@worker1.example","remote_directory":"/work/rars-hybrid"}
        runner.write_json(self.inventory,[host])
        self.freeze()
        source=self.root/"remote-return"
        shutil.copytree(self.run,source)
        runner.worker(source,"worker1",1)
        returned=self.root/"returned.tar.gz"
        runner.export_worker(source,"worker1",returned)
        commands=[]
        def transport(command):
            commands.append(command)
            if command[0]=="scp" and command[-1].endswith("results.tar.gz"):
                shutil.copy2(returned,command[-1])
            return ""
        finished=subprocess.CompletedProcess([],0,stdout="worker complete",stderr="")
        with mock.patch.object(runner,"checked_command",side_effect=transport), mock.patch.object(runner.subprocess,"run",return_value=finished):
            result=runner.dispatch_ssh(self.run,host)
        self.assertEqual(result["imported_tasks"],1)
        self.assertTrue(all(isinstance(c,list) for c in commands))
        self.assertTrue(any(c[0]=="ssh" and c[-2]=="user@worker1.example" for c in commands))
        self.assertEqual(len(runner.latest(runner.journal(self.run))),1)

    def test_pareto_limit_and_full_confirmation_contract(self):
        m = self.freeze()
        rows = []
        for i in range(4):
            task = {"phase": "screen", "configuration": f"desktop-{i:02d}", "case": "small", "repetition": 0}
            roles = {"candidate": {"encode": {"wall_seconds": 10-i, "peak_rss_bytes": 100+i},
                     "archive_bytes": 10+i, "decoders": {"candidate": {"extract": {"wall_seconds": 1}}}}}
            path = self.run / "tasks" / runner.task_id(task) / "result.json"
            path.parent.mkdir(parents=True)
            roles["native"]={"encode":{"wall_seconds":1,"peak_rss_bytes":1},"archive_bytes":1,"decoders":{"candidate":{"extract":{"wall_seconds":1}}}}
            runner.write_json(path, {"task": task, "roles": roles})
            rows.append({"event": "complete", "task": task, "task_id": runner.task_id(task), "host": "local", "result": str(path.relative_to(self.run)), "result_sha256": runner.sha(path)})
        selection = runner.choose_finalists(self.run, m, rows)
        self.assertEqual(len(selection["finalists"]), 3)
        self.assertEqual(selection["eligible_configurations"], 4)
        for row in rows:runner.append(self.run,row)
        self.assertEqual(runner.report(self.run)["qualified_finalists"], {})


if __name__ == "__main__":
    unittest.main()
