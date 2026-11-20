import argparse
import importlib.util
import json
from unittest.mock import patch
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).resolve().parents[1] / "scripts/acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceConfig(unittest.TestCase):
    def test_deterministic_failure_prevents_acceptance(self):
        settings = {"analysisEngine": "deterministic", "dbPath": "data/bounty.db"}
        commands = {}
        environments = {}
        def fake_run(name, args, timeout=120, env=None):
            commands[name] = args
            environments[name] = env
            acceptance.record(name, name != "deterministic_inventory", "owned fixture result")
        with patch.object(acceptance.sys, "argv", ["acceptance.py", "--model-only"]), \
             patch.object(acceptance, "runtime_settings", return_value=settings), \
             patch.object(acceptance.shutil, "which", return_value="node"), \
             patch.object(acceptance, "run", side_effect=fake_run):
            self.assertEqual(acceptance.main(), 1)
        self.assertTrue(acceptance.RESULTS["deterministic_controller"]["passed"])
        self.assertFalse(acceptance.RESULTS["deterministic_inventory"]["passed"])
        self.assertEqual(commands["deterministic_inventory"],
                         ["node", "--import", "tsx", "scripts/test-deterministic-full-inventory.ts"])
        self.assertEqual(environments["deterministic_inventory"]["LOCAL_MODEL_ADAPTER"], "deterministic")
        acceptance.RESULTS.clear()

    def test_deterministic_acceptance_never_needs_ollama(self):
        settings = {"analysisEngine": "deterministic", "dbPath": "data/bounty.db"}
        commands = {}
        def fake_run(name, args, timeout=120, env=None):
            commands[name] = args
            acceptance.record(name, True, "owned fixture result")
        with patch.object(acceptance.sys, "argv", ["acceptance.py", "--model-only"]), \
             patch.object(acceptance, "runtime_settings", return_value=settings), \
             patch.object(acceptance.shutil, "which", return_value="node"), \
             patch.object(acceptance, "run", side_effect=fake_run):
            self.assertEqual(acceptance.main(), 0)
        self.assertEqual(set(commands), {"deterministic_controller", "deterministic_inventory"})
        self.assertFalse(any("qwen" in str(args).lower() or "ollama" in str(args).lower()
                             for args in commands.values()))
        acceptance.RESULTS.clear()

    def test_report_never_claims_production_and_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text("old")
            path.chmod(0o644)
            acceptance.RESULTS.clear()
            acceptance.record("fixture", True, "passed")
            self.assertEqual(acceptance.emit(argparse.Namespace(report=str(path)), "offline_regression"), 0)
            self.assertFalse(json.loads(path.read_text())["production_verified"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            acceptance.record("failure", False, "not passed")
            self.assertEqual(acceptance.emit(argparse.Namespace(report=None), "host_acceptance"), 1)
            acceptance.RESULTS.clear()
