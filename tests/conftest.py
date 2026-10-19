"""Host test harness (monitor pattern): pure C sources are compiled with the host cc into shared
libraries and exercised through ctypes.

Sources come from cmake/gw_host_sources.cmake, so a stream only appends its file to its component's
GW_HOST_SOURCES_<COMPONENT> list to make it available to the tests:
  gwlib                 every host source in one libgw_host.so (integration-style tests)
  host_lib('STORE', …)  only the named lists (+ GW_CORE, host-only backends, third party), so a
                        compile error in another stream's file does not break this stream's tests
Third-party sources (cJSON) are compiled once without -Werror; the pure code sees their include dirs.
"""
import ctypes
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / 'components'
HOST_SOURCES_CMAKE = ROOT / 'cmake' / 'gw_host_sources.cmake'
INCLUDE_DIRS = sorted(p for p in COMPONENTS.glob('*/include') if p.is_dir())
CC = shutil.which('cc') or shutil.which('gcc') or 'cc'
CFLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g']
THIRD_PARTY_CFLAGS = ['-std=c11', '-O1', '-g', '-fPIC', '-w', '-DCJSON_NESTING_LIMIT=32',
                      '-DCJSON_CIRCULAR_LIMIT=10000']
LIBS = ['-lcrypto', '-lm']
MISSING_THIRD_PARTY_HINT = ('third-party host sources are missing; run '
                            '`uv run --locked python tools/idf.py reconfigure` once to fetch managed_components/')

# Public headers that include IDF headers on purpose; the firmware build compiles them through
# main/contract_check.c. Every other public header must compile on the host.
IDF_HEADERS = {'gw_core/gw_events.h', 'web/router.h', 'web/ws_hub.h', 'snmp_transport.h'}


def parse_cmake_lists(path=HOST_SOURCES_CMAKE):
    """Return {name: [paths]} for every set(NAME ...) block, expanding ${VAR} references."""
    text = re.sub(r'#[^\n]*', '', path.read_text())
    out = {}
    for name, body in re.findall(r'set\(\s*(\w+)(.*?)\)', text, re.S):
        items = []
        for tok in re.findall(r'"[^"]*"|\$\{\w+\}|[^\s"]+', body):
            if tok.startswith('${'):
                items += out.get(tok[2:-1], [])
            else:
                items.append(tok.strip('"'))
        out[name] = items
    return out


LISTS = parse_cmake_lists()
THIRD_PARTY_INCLUDE_DIRS = [ROOT / p for p in LISTS.get('GW_HOST_THIRD_PARTY_INCLUDE_DIRS', [])]
INCLUDE_FLAGS = [f'-I{p}' for p in INCLUDE_DIRS + [d for d in THIRD_PARTY_INCLUDE_DIRS if d.is_dir()]]


def host_sources():
    return [ROOT / p for p in LISTS.get('GW_HOST_SOURCES', []) + LISTS.get('GW_HOST_ONLY_SOURCES', [])]


def public_headers():
    """Public headers as include paths relative to their include/ dir (e.g. 'store/config.h')."""
    return sorted(str(h.relative_to(inc)) for inc in INCLUDE_DIRS for h in inc.rglob('*.h'))


def cc(args, cwd=None):
    """Run the host compiler; raise AssertionError with the diagnostics on failure."""
    r = subprocess.run([CC, *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        hint = f'\n{MISSING_THIRD_PARTY_HINT}' if 'cJSON.h' in r.stderr else ''
        raise AssertionError(f'{CC} {" ".join(map(str, args))}\n{r.stdout}{r.stderr}{hint}')
    return r


def compile_and_run(tmp_path, source, name='prog', extra_sources=(), flags=()):
    """Compile a C program (with optional extra sources) for the host and return its stdout."""
    src = tmp_path / f'{name}.c'
    src.write_text(source)
    exe = tmp_path / name
    cc([*CFLAGS, *flags, *INCLUDE_FLAGS, str(src), *map(str, extra_sources), '-o', str(exe), *LIBS])
    return subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout


def _check_listed(srcs):
    missing = [str(s) for s in srcs if not s.is_file()]
    assert not missing, f'listed in {HOST_SOURCES_CMAKE.name} but missing: {missing}'


@pytest.fixture(scope='session')
def third_party_objs(tmp_path_factory):
    """Third-party host sources compiled once (relaxed warnings). Missing ones are skipped here; a pure
    source that needs them then fails to compile with MISSING_THIRD_PARTY_HINT."""
    out = tmp_path_factory.mktemp('third_party')
    objs = []
    for rel in LISTS.get('GW_HOST_THIRD_PARTY_SOURCES', []):
        src = ROOT / rel
        if not src.is_file():
            continue
        obj = out / (src.stem + '.o')
        cc([*THIRD_PARTY_CFLAGS, *INCLUDE_FLAGS, '-c', str(src), '-o', str(obj)])
        objs.append(obj)
    return objs


def _build_so(path, srcs, objs):
    _check_listed(srcs)
    cc([*CFLAGS, '-shared', '-fPIC', *INCLUDE_FLAGS, *map(str, srcs), *map(str, objs), '-o', str(path), *LIBS])
    return ctypes.CDLL(str(path))


@pytest.fixture(scope='session')
def gwlib(tmp_path_factory, third_party_objs):
    """All host sources linked into one shared library (ctypes.CDLL)."""
    return _build_so(tmp_path_factory.mktemp('gwlib') / 'libgw_host.so', host_sources(), third_party_objs)


@pytest.fixture(scope='session')
def host_lib(tmp_path_factory, third_party_objs):
    """Factory: host_lib('MEX150', 'STORE') -> CDLL built from GW_HOST_SOURCES_GW_CORE plus the named
    GW_HOST_SOURCES_<NAME> lists, GW_HOST_ONLY_SOURCES and the third-party objects (cached)."""
    cache = {}

    def build(*names):
        key = tuple(sorted({'GW_CORE', *(n.upper() for n in names)}))
        if key not in cache:
            unknown = [n for n in key if f'GW_HOST_SOURCES_{n}' not in LISTS]
            assert not unknown, f'no GW_HOST_SOURCES_<NAME> list for {unknown}'
            srcs = [ROOT / p for n in key for p in LISTS[f'GW_HOST_SOURCES_{n}']]
            srcs += [ROOT / p for p in LISTS.get('GW_HOST_ONLY_SOURCES', [])]
            path = tmp_path_factory.mktemp('host_lib') / f'libgw_{"_".join(key).lower()}.so'
            cache[key] = _build_so(path, srcs, third_party_objs)
        return cache[key]

    return build
