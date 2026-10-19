"""Stream B host-test harness.

Builds GW_HOST_SOURCES_GW_CORE + _STORE + _ALARM (+ host-only crypto backend, cJSON) once per session,
plus fakes for the other streams' functions store/alarm call (tests/b_store/c/fake_*.c), so a broken
file of another stream cannot fail these tests. Exposes:
  b_objs     list of object files (session)
  b_lib      ctypes.CDLL of the objects + c/ctypes_helpers.c (session)
  run_c(b_objs, tmp_path, 't_name', *args) -> stdout of tests/b_store/c/t_name.c, asserting success
"""
import ctypes
import re
import subprocess
from pathlib import Path

import pytest

from conftest import CFLAGS, INCLUDE_FLAGS, LIBS, LISTS, ROOT, cc

C_DIR = Path(__file__).resolve().parent / 'c'
PRIV_INCLUDES = [f'-I{ROOT / "components" / "store"}', f'-I{ROOT / "components" / "alarm"}', f'-I{C_DIR}']


def b_sources():
    lists = LISTS
    srcs = [ROOT / p for n in ('GW_CORE', 'STORE', 'ALARM') for p in lists[f'GW_HOST_SOURCES_{n}']]
    srcs += [ROOT / p for p in lists.get('GW_HOST_ONLY_SOURCES', [])]
    srcs.append(C_DIR / 'fake_mex150.c')
    if 'components/gw_core/gw_ident.c' not in lists['GW_HOST_SOURCES_GW_CORE']:
        srcs.append(C_DIR / 'fake_gw_ident.c')
    return srcs


@pytest.fixture(scope='session')
def b_objs(tmp_path_factory, third_party_objs):
    out = tmp_path_factory.mktemp('b_objs')
    objs = []
    for i, src in enumerate(b_sources()):
        assert src.is_file(), f'missing host source {src}'
        obj = out / f'{i:02d}_{src.stem}.o'
        cc([*CFLAGS, '-fPIC', *INCLUDE_FLAGS, *PRIV_INCLUDES, '-c', str(src), '-o', str(obj)])
        objs.append(obj)
    return objs + list(third_party_objs)


@pytest.fixture(scope='session')
def b_lib(tmp_path_factory, b_objs):
    out = tmp_path_factory.mktemp('b_lib')
    so = out / 'libgw_b.so'
    cc([*CFLAGS, '-shared', '-fPIC', *INCLUDE_FLAGS, *PRIV_INCLUDES, str(C_DIR / 'ctypes_helpers.c'),
        *map(str, b_objs), '-o', str(so), *LIBS])
    return ctypes.CDLL(str(so))


_built = {}


def run_c(b_objs, tmp_path, name, *args, expect_rc=0):
    """Compile tests/b_store/c/<name>.c against the objects (cached per session), run it, check the
    summary line and return stdout."""
    exe = _built.get(name)
    if exe is None or not exe.exists():
        exe = tmp_path.parent / f'{name}.bin'
        cc([*CFLAGS, *INCLUDE_FLAGS, *PRIV_INCLUDES, str(C_DIR / f'{name}.c'), *map(str, b_objs), '-o', str(exe),
            *LIBS])
        _built[name] = exe
    r = subprocess.run([str(exe), *map(str, args)], capture_output=True, text=True, timeout=300)
    assert r.returncode == expect_rc, f'{name} rc={r.returncode}\n{r.stdout}\n{r.stderr}'
    m = re.search(r'checks=(\d+) failed=(\d+)', r.stdout)
    if expect_rc == 0:
        assert m and int(m.group(2)) == 0 and int(m.group(1)) > 0, r.stdout + r.stderr
    return r.stdout
