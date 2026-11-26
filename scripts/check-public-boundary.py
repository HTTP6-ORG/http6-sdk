#!/usr/bin/env python3
"""Fail the public build if private circuit sources or unapproved binaries enter Git."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
paths=subprocess.run(['git','ls-files','-z'],cwd=root,check=True,capture_output=True).stdout.decode().split('\0')
forbidden=('pilot/src/','pilot/vendor/','pilot/Cargo.toml','pilot/Cargo.lock','pilot/build.sh','pilot/worker.wat')
markers=[b'eni6ma_'+b'id4_auto::',b'expected_'+b'bearings',b'provision_'+b'circuit_hash',b'Secret'+b'Units']
for name in filter(None,paths):
    if any(name==f or name.startswith(f) for f in forbidden):raise SystemExit('Private circuit source path is tracked: '+name)
    if name.endswith('.wasm') and not name.startswith('circuits/demo-wasix-02/bin/'):raise SystemExit('Unapproved compiled artifact path: '+name)
    if name.endswith('.wat'):raise SystemExit('WASM source is not permitted in the public tree: '+name)
    if name.lower().endswith(('.zip','.tar','.tgz','.tar.gz','.7z','.rar')):raise SystemExit('Archives require a separate source review: '+name)
    if name.endswith('.wasm') and b'/Users/' in (root/name).read_bytes():raise SystemExit('Compiled artifact contains a local user path: '+name)
    if name=='scripts/check-public-boundary.py' or name.endswith('.wasm'):continue
    path=root/name
    if path.is_file() and path.stat().st_size<5000000:
        data=path.read_bytes()
        if any(marker in data for marker in markers):raise SystemExit('Circuit implementation marker found in: '+name)
print('Public file boundary passed: circuit source and unapproved WASM paths absent.')
