"""Refuse retired environment names outside the three removal records."""
from pathlib import Path
import argparse
import json
import re
import subprocess

EXEMPTIONS = frozenset({'CHANGES.md', 'CLEANUP_PLAN.md', 'docs/PARKED.md'})


def name_pattern(names):
    parts = [re.escape(name) + (r'[A-Z0-9_]*' if name.endswith('_') else r'(?:_FILE)?')
             for name in names]
    return re.compile(r'\b(?:' + '|'.join(parts) + r')(?![A-Z0-9_])') if parts else re.compile(r'(?!)')


def scan(root):
    record = (root / 'docs/PARKED.md').read_text(encoding='utf-8')
    catalog = re.search(r'<!-- removed-settings:start -->\s*```json\s*(.*?)\s*```\s*<!-- removed-settings:end -->', record, re.S)
    if catalog is None:
        raise ValueError('PARKED.md lacks the removed-settings catalog')
    names = json.loads(catalog[1])
    if not isinstance(names, list) or any(not isinstance(name, str) or not re.fullmatch(r'SENTINEL_[A-Z0-9_]+',name) for name in names):
        raise ValueError('invalid removed-settings catalog')
    pattern = name_pattern(names)
    paths = subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'], cwd=root).decode().split('\0')
    findings = []
    for name in sorted(set(paths) - EXEMPTIONS - {''}):
        path = root/name
        if path.is_symlink():
            findings.append(f'{name}: symlink cannot be scanned safely')
        elif path.is_file():
            for line_number, line in enumerate(path.read_bytes().decode('utf-8',errors='replace').splitlines(),1):
                for match in pattern.finditer(line):
                    findings.append(f'{name}:{line_number}: {match[0]}')
    return names, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    names, findings = scan(args.root.resolve())
    for finding in findings:
        print(finding)
    print(f'Removed-settings scan: {len(names)} names/prefixes; {len(findings)} findings; exemptions: ' + ', '.join(sorted(EXEMPTIONS)))
    return int(bool(findings))


if __name__ == '__main__':
    raise SystemExit(main())
