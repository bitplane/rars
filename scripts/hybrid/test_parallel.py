"""Parallel diagnostics, deterministic receipts and host-wall-budget accounting."""
import importlib.util
from pathlib import Path
import threading
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("hybrid_test_helpers", Path(__file__).with_name("test_runner.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
runner = helpers.runner


class ParallelScreenTests(unittest.TestCase):
    setUp = helpers.RunnerTests.setUp
    tearDown = helpers.RunnerTests.tearDown
    freeze = helpers.RunnerTests.freeze

    def parallel_manifest(self, cases=3, slots=3, budget=10):
        corpus = runner.read_json(self.manifest)
        corpus["workloads"] = [{"id": "case-" + str(i), "files": ["folder/data.txt"]} for i in range(cases)]
        runner.write_json(self.manifest, corpus)
        m = self.freeze(budgets={"screen": budget, "confirm": 10}, task_timeout_seconds=2)
        m["execution"] = {"parallel_screening": True}
        m["hosts"][0]["screening_slots"] = slots
        return m

    def receipt(self, run, m, task, deadline):
        roles = {role: {"encode": {"wall_seconds": 1, "cpu_seconds": 1, "peak_rss_bytes": 100},
                        "archive_bytes": 100, "decoders": {"candidate": {"extract": {"wall_seconds": 1}}}}
                 for role in ("candidate", "native", "baseline", "relationships", "streams", "native_ordered")}
        path = run / "tasks" / runner.task_id(task) / "result.json"
        path.parent.mkdir(parents=True)
        runner.write_json(path, {"task": task, "roles": roles})

    def test_configuration_blocks_parallelize_and_commit_in_frozen_order(self):
        m = self.parallel_manifest()
        guard = threading.Lock()
        active, peak, configurations, seen = [0], [0], set(), {}

        def sample(run, manifest, task, deadline):
            configuration = task["configuration"]
            with guard:
                self.assertNotIn(configuration, configurations)
                configurations.add(configuration)
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                seen.setdefault(configuration, []).append(task["case"])
            time.sleep(.03)
            self.receipt(run, manifest, task, deadline)
            with guard:
                configurations.remove(configuration)
                active[0] -= 1

        with mock.patch.object(runner, "sample", side_effect=sample):
            result = runner.parallel_screen(self.run, m, m["hosts"][0], 9)
        self.assertEqual(result, {"tasks_run": 9, "paused": True})
        self.assertEqual(peak[0], 3)
        expected = runner.tasks(m, "screen")[:9]
        rows = runner.journal(self.run)
        completed = [r for r in rows if r.get("event") == "complete"]
        self.assertEqual([r["task"] for r in completed], expected)
        for configuration, cases in seen.items():
            self.assertEqual(cases, [t["case"] for t in expected if t["configuration"] == configuration])
        plan = next(r for r in rows if r.get("event") == "dispatch-plan")
        self.assertEqual(sum(plan["configuration_blocks"], []), [runner.task_id(t) for t in expected])
        charge = runner.consumed(rows, "screen", "local")
        self.assertGreater(sum(r["charged_seconds"] for r in completed), charge * 1.5)
        self.assertTrue(all(r["contended"] for r in completed))

    def test_crash_reservation_charges_one_host_allowance(self):
        task = {"phase": "screen", "configuration": "desktop-00", "case": "small", "repetition": 0}
        rows = [{"event": "phase-reservation", "id": "phase", "phase": "screen", "host": "local", "reserved_seconds": 100}]
        rows.extend({"event": "started", "task": {**task, "case": str(i)}, "task_id": str(i),
                     "host": "local", "phase_reservation": "phase", "reserved_seconds": 30} for i in range(80))
        self.assertEqual(runner.consumed(rows, "screen", "local"), 100)
        rows.append({"event": "phase-accounting", "phase": "screen", "host": "local", "reservation_id": "phase",
                     "covered_tasks": [str(i) for i in range(80)], "charged_seconds": 5})
        self.assertEqual(runner.consumed(rows, "screen", "local"), 5)
        rows.append({"event": "started", "task": task, "task_id": "serial", "host": "local", "reserved_seconds": 3})
        self.assertEqual(runner.consumed(rows, "screen", "local"), 8)

    def test_failed_block_tail_does_not_turn_max_tasks_pause_into_completion(self):
        m = self.parallel_manifest()
        calls = []

        def sample(run, manifest, task, deadline):
            calls.append(task["configuration"])
            raise runner.RunError("fixture screening failure")

        with mock.patch.object(runner, "sample", side_effect=sample):
            first = runner.parallel_screen(self.run, m, m["hosts"][0], 3)
            second = runner.parallel_screen(self.run, m, m["hosts"][0], 3)
        self.assertEqual(first, {"tasks_run": 1, "paused": True})
        self.assertEqual(second, {"tasks_run": 1, "paused": True})
        self.assertNotEqual(calls[0], calls[1])
        self.assertFalse(any(r.get("event") == "phase-done" for r in runner.journal(self.run)))

    def test_one_deadline_bounds_all_slots_and_timeout_skips_configuration(self):
        # The phase clock starts before the reservation and journal writes, so
        # the budget has to outlast those on a slow disk or no task starts.
        m = self.parallel_manifest(slots=2, budget=1)
        calls = []

        def sample(run, manifest, task, deadline):
            calls.append((task, deadline))
            while time.monotonic() < deadline:
                time.sleep(.002)
            raise runner.RunError("fixture timeout")

        with mock.patch.object(runner, "sample", side_effect=sample):
            result = runner.parallel_screen(self.run, m, m["hosts"][0])
        self.assertEqual(result["tasks_run"], 2)
        self.assertEqual(calls[0][1], calls[1][1])
        rows = runner.journal(self.run)
        self.assertEqual(len([r for r in rows if r.get("event") == "excluded"]), 4)
        # Scheduler and durable-journal latency are not bounded by the
        # decoder deadline, especially on loaded or slow filesystems.
        accounting = [row for row in rows if row.get("event") == "phase-accounting"]
        self.assertEqual(len(accounting), 1)
        self.assertEqual(runner.consumed(rows, "screen", "local"), accounting[0]["charged_seconds"])
        self.assertGreaterEqual(accounting[0]["charged_seconds"], 1)
        self.assertEqual(runner.available(m, rows, "screen", "local"), 0)

    def test_interruption_cancels_jobs_and_charges_reservation_once(self):
        m = self.parallel_manifest(slots=2)
        first = runner.tasks(m, "screen")[0]["configuration"]
        first_calls = [0]

        def sample(run, manifest, task, deadline):
            if task["configuration"] == first:
                first_calls[0] += 1
                if first_calls[0] == 1:
                    self.receipt(run, manifest, task, deadline)
                    return
                raise KeyboardInterrupt()
            cancellation = runner.EXECUTION_CONTEXT.cancellation
            self.assertTrue(cancellation.wait(2))
            raise runner.RunError("cancelled")

        with mock.patch.object(runner, "sample", side_effect=sample):
            with self.assertRaises(KeyboardInterrupt):
                runner.parallel_screen(self.run, m, m["hosts"][0])
        rows = runner.journal(self.run)
        accounting = [r for r in rows if r.get("event") == "phase-accounting"]
        self.assertEqual(len(accounting), 1)
        self.assertTrue(accounting[0]["interrupted"])
        self.assertEqual(runner.consumed(rows, "screen", "local"), 10)
        completed = [r for r in rows if r.get("event") == "complete"]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["task"]["configuration"], first)
        self.assertTrue((self.run / completed[0]["result"]).is_file())

    def test_confirmation_waits_for_screening_drain_and_is_serial(self):
        m = self.parallel_manifest(cases=1, slots=3)
        active = [0]
        guard = threading.Lock()
        confirmation_peak = [0]

        def sample(run, manifest, task, deadline):
            with guard:
                active[0] += 1
                if task["phase"] == "confirm":
                    self.assertTrue(any(r.get("event") == "phase-done" and r.get("phase") == "screen"
                                        for r in runner.journal(self.run)))
                    confirmation_peak[0] = max(confirmation_peak[0], active[0])
            time.sleep(.001)
            self.receipt(run, manifest, task, deadline)
            with guard:
                active[0] -= 1

        with mock.patch.object(runner, "load", return_value=m), mock.patch.object(runner, "sample", side_effect=sample):
            result = runner.worker(self.run, "local")
        self.assertEqual(result["status"], "finished-or-budget-exhausted")
        self.assertEqual(confirmation_peak[0], 1)
        self.assertEqual(active[0], 0)
        before = len(runner.journal(self.run))
        with mock.patch.object(runner, "load", return_value=m), mock.patch.object(runner, "sample") as child:
            self.assertEqual(runner.worker(self.run, "local")["tasks_run"], 0)
        child.assert_not_called()
        self.assertGreaterEqual(len(runner.journal(self.run)), before)


if __name__ == "__main__":
    unittest.main()
