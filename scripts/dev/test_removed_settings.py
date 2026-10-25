"""The removed-name scan must detect real files while honoring only its three exemptions."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest


class RemovedSettingsTests(unittest.TestCase):
    def test_scan_finds_code_docs_and_file_variants_but_exempts_only_records(self):
        scanner = Path(__file__).with_name('scan_removed_settings.py')
        self.assertTrue(scanner.is_file(), 'the executable removed-setting scan is missing')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git','init','-q',str(root)], check=True, capture_output=True)
            retired = 'SENTINEL_' + 'RETIRED_CONNECTOR'
            (root/'docs').mkdir()
            for name in ('CHANGES.md','CLEANUP_PLAN.md'):
                (root/name).write_text(retired)
            (root/'docs/PARKED.md').write_text(
                '<!-- removed-settings:start -->\n```json\n'+json.dumps([retired])+
                '\n```\n<!-- removed-settings:end -->\n'+retired)
            def run():
                return subprocess.run([sys.executable,str(scanner),'--root',str(root)],
                                      text=True,capture_output=True)
            self.assertEqual(run().returncode,0)
            for name,value in (('consumer.py',retired),('docs/OTHER.md',retired+'_FILE')):
                (root/name).write_text(value)
                result = run()
                self.assertEqual(result.returncode,1,result.stdout+result.stderr)
                self.assertIn(name,result.stdout)
                (root/name).unlink()
            self.assertEqual(run().returncode,0)

    def test_prefix_scan_catches_dynamic_names_but_not_unrelated_settings(self):
        scanner = Path(__file__).with_name('scan_removed_settings.py')
        self.assertTrue(scanner.is_file(), 'the executable removed-setting scan is missing')
        spec = importlib.util.spec_from_file_location('removed_settings',scanner)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pattern = module.name_pattern(['SENTINEL_'+'OLD_', 'SENTINEL_'+'EXACT'])
        self.assertIsNotNone(pattern.search('SENTINEL_'+'OLD_TEAM_TOKEN_FILE'))
        self.assertIsNotNone(pattern.search('SENTINEL_'+'EXACT_FILE'))
        self.assertIsNone(pattern.search('SENTINEL_'+'EXACTLY_DIFFERENT'))
        self.assertIsNone(pattern.search('SENTINEL_'+'CURRENT_TOKEN'))


if __name__ == '__main__':
    unittest.main()
