"""Standard-library regression tests for the cleanup inventory tool.

Run with ``python -m unittest discover -s scripts/dev -p 'test_import_graph.py'``.
These synthetic packages must never be imported by the scanner.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("import_graph.py")


class ImportGraphTests(unittest.TestCase):
    def run_graph(self, files, *options):
        self.assertTrue(SCRIPT.is_file(), "the import graph command must exist")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            output = root / "graph.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root),
                 "--entrypoint", "sentinel.entry", "--json", str(output), *options],
                capture_output=True, text=True, check=False,
            )
            return result, json.loads(output.read_text()) if output.exists() else None

    def test_relative_namespace_and_parent_initializers_without_execution(self):
        result, graph = self.run_graph({
            "sentinel/__init__.py": "raise RuntimeError('must not execute')\n",
            "sentinel/entry.py": "from .namespace import child\n",
            "sentinel/namespace/child.py": "from ..leaf import value\n",
            "sentinel/leaf.py": "value = 1\n",
        }, "--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(graph["unreachable"], [])
        self.assertEqual(graph["summary"]["modules"], 4)
        self.assertEqual(graph["modules"]["sentinel.leaf"]["loc"], 1)

    def test_unreachable_cycle_is_not_confused_with_never_imported(self):
        result, graph = self.run_graph({
            "sentinel/entry.py": "pass\n",
            "sentinel/a.py": "import sentinel.b\n",
            "sentinel/b.py": "import sentinel.a\n",
            "sentinel/orphan.py": "pass\n",
        }, "--check")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(graph["unreachable"], ["sentinel.a", "sentinel.b", "sentinel.orphan"])
        self.assertEqual(graph["never_imported"], ["sentinel.entry", "sentinel.orphan"])

    def test_lazy_export_map_and_literal_import_are_edges_not_prose(self):
        result, graph = self.run_graph({
            "sentinel/entry.py": (
                "import importlib as loader\n"
                "from types import MappingProxyType\n"
                "_LAZY = MappingProxyType({'Client': 'sentinel.client'})\n"
                "def __getattr__(name):\n"
                "    module_name = _LAZY.get(name)\n"
                "    return loader.import_module(module_name)\n"
                "loader.import_module('sentinel.other')\n"
                "description = 'sentinel.unused'\n"
            ),
            "sentinel/client.py": "pass\n",
            "sentinel/other.py": "pass\n",
            "sentinel/unused.py": "pass\n",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(graph["unreachable"], ["sentinel.unused"])
        self.assertEqual(graph["unresolved_dynamic_imports"], [])

    def test_unknown_dynamic_import_prevents_clean_check(self):
        result, graph = self.run_graph({
            "sentinel/entry.py": "from importlib import import_module as load\nload(user_input)\n",
        }, "--check")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(graph["unresolved_dynamic_imports"]), 1)

    def test_deleted_internal_dependency_prevents_clean_check(self):
        result, graph = self.run_graph({
            "sentinel/entry.py": "from sentinel.deleted import Client\nimport external_package\n",
        }, "--check")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(graph["unresolved_internal_imports"][0]["target"], "sentinel.deleted")

    def test_dynamic_bindings_do_not_cross_unrelated_scopes(self):
        for source in (
            "target = 'sentinel.live'\ndef load(target):\n    return importlib.import_module(target)\n",
            "def other():\n    target = 'sentinel.live'\nimportlib.import_module(target)\n",
            "target = 'sentinel.live'\ndef load():\n    for target in choices:\n        importlib.import_module(target)\n",
        ):
            with self.subTest(source=source):
                result, graph = self.run_graph({
                    "sentinel/entry.py": "import importlib\nimport sentinel.live\n" + source,
                    "sentinel/live.py": "pass\n",
                }, "--check")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(len(graph["unresolved_dynamic_imports"]), 1)

    def test_mutated_lazy_maps_are_not_closed_literal_targets(self):
        for mutation in (
            "MODULES['B'] = 'sentinel.deleted'\n",
            "MODULES.update({'B': 'sentinel.deleted'})\n",
            "alias = MODULES\nalias['B'] = 'sentinel.deleted'\n",
        ):
            with self.subTest(mutation=mutation):
                result, graph = self.run_graph({
                    "sentinel/entry.py": (
                        "import importlib\nimport sentinel.live\n"
                        "MODULES = {'A': 'sentinel.live'}\n" + mutation
                        + "importlib.import_module(MODULES.get(key))\n"
                    ),
                    "sentinel/live.py": "pass\n",
                }, "--check")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(len(graph["unresolved_dynamic_imports"]), 1)

    def test_deleted_namespace_child_is_not_mistaken_for_a_symbol(self):
        result, graph = self.run_graph({
            "sentinel/entry.py": "from sentinel.ns import deleted\nimport sentinel.ns.live\n",
            "sentinel/ns/live.py": "pass\n",
        }, "--check")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(graph["unresolved_internal_imports"][0]["target"], "sentinel.ns.deleted")

    def test_missing_entrypoint_and_invalid_python_are_errors(self):
        for files in ({"sentinel/other.py": "pass\n"},
                      {"sentinel/entry.py": "def broken(\n"}):
            with self.subTest(files=files):
                result, graph = self.run_graph(files)
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stderr)
                self.assertIsNone(graph)

    def test_documented_exception_is_visible_and_stale_exception_fails(self):
        files = {"sentinel/entry.py": "pass\n", "sentinel/cli.py": "pass\n"}
        result, graph = self.run_graph(files, "--check", "--allow-unreachable", "sentinel.cli")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(graph["unreachable"], ["sentinel.cli"])
        result, graph = self.run_graph(files, "--check", "--allow-unreachable", "sentinel.gone")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(graph["stale_allowances"], ["sentinel.gone"])


if __name__ == "__main__":
    unittest.main()
