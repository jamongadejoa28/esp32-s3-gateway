"""Run the supplied ESP-IDF v6.1 using this project's locked Python environment (uv .venv).

Usage: uv run --locked python tools/idf.py build
Node (nvm v24) is prepended to PATH so the web asset build step finds node/npm.
"""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
idf = Path(os.environ.get('IDF_PATH', '/home/hajun/esp-idf-v6.1'))
node_bin = Path.home() / '.nvm/versions/node/v24.14.0/bin'
env = os.environ.copy()
env.update(IDF_PATH=str(idf), IDF_TOOLS_PATH=os.environ.get('IDF_TOOLS_PATH', '/home/hajun/dev_ws/wokwipj/.tools/espressif'),
           IDF_PYTHON_ENV_PATH=str(root/'.venv'))
if node_bin.is_dir():
    env['PATH'] = f"{node_bin}{os.pathsep}{env.get('PATH', '')}"
# IDF's Python environment installer is deliberately not used: uv owns the lock.
if sys.argv[1:] == ['--install-tools']:
    raise SystemExit(subprocess.call([sys.executable, str(idf/'tools/idf_tools.py'),
        'install', '--targets', 'esp32s3'], env=env))
exported = subprocess.check_output([sys.executable, str(idf/'tools/idf_tools.py'),
    'export', '--format', 'key-value'], env=env, text=True)
for line in exported.splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        env[key] = value.replace('$PATH', env['PATH']).replace('${PATH}', env['PATH'])
raise SystemExit(subprocess.call([sys.executable, str(idf/'tools/idf.py'), *sys.argv[1:]], env=env, cwd=root))
