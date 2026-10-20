"""Run the supplied ESP-IDF v6.1 using this project's locked Python environment (uv .venv).

Usage: uv run --locked python tools/idf.py build
The newest installed nvm Node is prepended to PATH for the web asset build.
"""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
# Use the same Python spelling as the VS Code configuration and CMake cache. uv may launch this
# wrapper as python3; IDF treats python and python3 paths as different build environments.
project_python = str(root / '.venv/bin/python')
idf = Path(os.environ.get('IDF_PATH', Path.home() / 'esp-idf-v6.1/v6.1/esp-idf'))
node_bins = list((Path.home() / '.nvm/versions/node').glob('v*/bin'))
node_bin = max(node_bins, key=lambda p: tuple(int(n) for n in p.parent.name[1:].split('.')),
               default=None)
env = os.environ.copy()
env.update(IDF_PATH=str(idf), IDF_TOOLS_PATH=os.environ.get('IDF_TOOLS_PATH', str(Path.home() / '.espressif')),
           IDF_PYTHON_ENV_PATH=str(root/'.venv'))
if node_bin:
    env['PATH'] = f"{node_bin}{os.pathsep}{env.get('PATH', '')}"
# IDF's Python environment installer is deliberately not used: uv owns the lock.
if sys.argv[1:] == ['--install-tools']:
    raise SystemExit(subprocess.call([project_python, str(idf/'tools/idf_tools.py'),
        'install', '--targets', 'esp32s3'], env=env))
exported = subprocess.check_output([project_python, str(idf/'tools/idf_tools.py'),
    'export', '--format', 'key-value'], env=env, text=True)
for line in exported.splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        env[key] = value.replace('$PATH', env['PATH']).replace('${PATH}', env['PATH'])
raise SystemExit(subprocess.call([project_python, str(idf/'tools/idf.py'), *sys.argv[1:]], env=env, cwd=root))
