"""tools/gen_web_assets.py and cmake/gw_web_assets.cmake (stream G).

The generated C table is compiled with the host cc against the frozen web/web_assets.h and read back
by a small C program (sorted for bisection, byte-exact gzip bodies). The CMake hook is exercised in a
scratch copy of the repository layout with a fake tools/build_web.mjs, so these tests never touch the
real web/ tree (owned by stream D) or a firmware build directory.
"""
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import CFLAGS, INCLUDE_FLAGS, ROOT, cc

sys.path.insert(0, str(ROOT / 'tools'))
import gen_web_assets as gwa  # noqa: E402

GEN = ROOT / 'tools' / 'gen_web_assets.py'
HOOK = ROOT / 'cmake' / 'gw_web_assets.cmake'
STRICT = [*CFLAGS, '-Wpedantic', '-Wmissing-field-initializers', '-Wconversion']

READER_C = r'''
#include <stdio.h>
#include <string.h>
#include "web/web_assets.h"

static const web_asset_t *find(const char *p) {           /* bisection: requires strcmp order */
    size_t lo = 0, hi = gw_web_assets_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(p, gw_web_assets[mid].path);
        if (c == 0) return &gw_web_assets[mid];
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return NULL;
}

int main(void) {
    for (size_t i = 0; i < gw_web_assets_count; i++) {
        const web_asset_t *a = &gw_web_assets[i];
        if (i && strcmp(gw_web_assets[i - 1].path, a->path) >= 0) { puts("UNSORTED"); return 1; }
        if (find(a->path) != a) { puts("BISECT"); return 1; }
        printf("%s\t%s\t%s\t%u\t%d\t", a->path, a->mime, a->etag, (unsigned)a->len, (int)a->immutable);
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", WEB_FS_ROOT, a->file);
        FILE *f = fopen(path, "rb");
        if (!f) return 2;
        for (uint32_t j = 0; j < a->len; j++) {
            int ch = fgetc(f);
            if (ch == EOF) return 3;
            printf("%02x", (unsigned)ch);
        }
        fclose(f);
        putchar('\n');
    }
    printf("count=%u\n", (unsigned)gw_web_assets_count);
    return find("/nope") != NULL;
}
'''


def gz(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)


def make_dist(d: Path, files: dict, manifest=None) -> Path:
    """files: {relative file: bytes}; manifest: the manifest object (or None = derive from files)."""
    d.mkdir(parents=True, exist_ok=True)
    for rel, data in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(data)
    m = d / 'manifest.json'
    m.write_text(json.dumps(manifest), encoding='utf-8')
    return m


INDEX = b'<!doctype html><title>x</title><script src="/assets/app.1a2b3c4d.js"></script>'
APP_JS = b'console.log("hello \\"world\\"");\n' * 40
CSS = b'body{margin:0}'
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"/>'


def standard(tmp_path: Path):
    files = {'index.html.gz': gz(INDEX), 'assets/app.1a2b3c4d.js.gz': gz(APP_JS),
             'assets/app.9f8e7d6c.css.gz': gz(CSS), 'favicon.svg.gz': gz(SVG)}
    entries = [
        {'path': '/assets/app.1a2b3c4d.js', 'file': 'assets/app.1a2b3c4d.js.gz', 'mime': 'text/javascript',
         'sha256': hashlib.sha256(files['assets/app.1a2b3c4d.js.gz']).hexdigest(),
         'gz': len(files['assets/app.1a2b3c4d.js.gz']), 'size': len(APP_JS), 'immutable': True},
        {'path': '/', 'file': 'index.html.gz', 'mime': 'text/html; charset=utf-8', 'etag': '"0badc0de"',
         'sha256': hashlib.sha256(INDEX).hexdigest(), 'immutable': False},
        {'path': '/favicon.svg', 'file': 'favicon.svg.gz', 'mime': 'image/svg+xml'},
        {'path': 'assets/app.9f8e7d6c.css', 'file': 'assets/app.9f8e7d6c.css.gz'},
    ]
    total = sum(len(v) for v in files.values())
    return make_dist(tmp_path / 'dist', files, {'version': 1, 'files': entries, 'total_gz': total}), files


def generate(manifest: Path, out: Path, *extra) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GEN), '--manifest', str(manifest), '--out', str(out), *extra],
                          capture_output=True, text=True)


def compile_reader(tmp_path: Path, table_c: Path) -> list:
    reader = tmp_path / 'reader.c'
    reader.write_text(READER_C)
    exe = tmp_path / 'reader'
    cc([*STRICT, *INCLUDE_FLAGS, f'-DWEB_FS_ROOT="{table_c.parent / "webfs"}"',
        str(reader), str(table_c), '-o', str(exe)])
    out = subprocess.run([str(exe)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    lines = out.stdout.splitlines()
    rows = [dict(zip(('path', 'mime', 'etag', 'len', 'imm', 'hex'), ln.split('\t'), strict=True)) for ln in lines[:-1]]
    return rows, lines[-1]


def test_generated_table_matches_contract(tmp_path):
    manifest, files = standard(tmp_path)
    out = tmp_path / 'web_assets.c'
    r = generate(manifest, out)
    assert r.returncode == 0, r.stderr
    rows, count = compile_reader(tmp_path, out)
    assert count == 'count=4'
    assert [x['path'] for x in rows] == ['/', '/assets/app.1a2b3c4d.js', '/assets/app.9f8e7d6c.css', '/favicon.svg']
    by = {x['path']: x for x in rows}
    assert by['/']['mime'] == 'text/html; charset=utf-8'
    assert by['/']['etag'] == '"0badc0de"' and by['/']['imm'] == '0'
    assert by['/favicon.svg']['imm'] == '0' and by['/favicon.svg']['mime'] == 'image/svg+xml; charset=utf-8'
    assert by['/assets/app.1a2b3c4d.js']['mime'] == 'text/javascript; charset=utf-8'
    assert by['/assets/app.9f8e7d6c.css']['imm'] == '1'                    # default for /assets/
    assert by['/assets/app.9f8e7d6c.css']['mime'] == 'text/css; charset=utf-8'
    for path, rel in [('/', 'index.html.gz'), ('/assets/app.1a2b3c4d.js', 'assets/app.1a2b3c4d.js.gz'),
                      ('/favicon.svg', 'favicon.svg.gz'), ('/assets/app.9f8e7d6c.css', 'assets/app.9f8e7d6c.css.gz')]:
        assert bytes.fromhex(by[path]['hex']) == files[rel]                 # embedded verbatim
        assert int(by[path]['len']) == len(files[rel])
        etag = by[path]['etag']
        assert etag.startswith('"') and etag.endswith('"') and not etag.startswith('W/')
    # derived ETag = first 16 hex of SHA-256 over the gzip body
    assert by['/favicon.svg']['etag'] == '"%s"' % hashlib.sha256(files['favicon.svg.gz']).hexdigest()[:16]


def test_output_is_deterministic_and_order_independent(tmp_path):
    manifest, _ = standard(tmp_path)
    a, b, c = tmp_path / 'a.c', tmp_path / 'b.c', tmp_path / 'c.c'
    assert generate(manifest, a).returncode == 0
    assert generate(manifest, b).returncode == 0
    doc = json.loads(manifest.read_text())
    doc['files'].reverse()
    manifest.write_text(json.dumps(doc, indent=2))
    assert generate(manifest, c).returncode == 0
    assert a.read_bytes() == b.read_bytes() == c.read_bytes()
    text = a.read_text()
    assert 'DO NOT EDIT' in text and str(tmp_path) not in text             # no absolute paths/timestamps


def test_plain_files_bare_list_and_index_alias(tmp_path):
    """Bare-list manifest, implicit files, uncompressed dist files (compressed here, mtime 0)."""
    d = tmp_path / 'dist'
    m = make_dist(d, {'index.html': INDEX, 'assets/x.12345678.js': APP_JS},
                  [{'path': 'index.html'}, {'url': '/assets/x.12345678.js', 'sha256': hashlib.sha256(APP_JS).hexdigest()}])
    out = tmp_path / 't.c'
    r = generate(m, out)
    assert r.returncode == 0, r.stderr
    rows, count = compile_reader(tmp_path, out)
    assert count == 'count=2'
    assert gzip.decompress(bytes.fromhex(rows[0]['hex'])) == INDEX and rows[0]['path'] == '/'
    assert bytes.fromhex(rows[1]['hex']) == gz(APP_JS)
    assert rows[0]['mime'] == 'text/html; charset=utf-8'


def test_empty_table_compiles(tmp_path):
    out = tmp_path / 'e.c'
    r = subprocess.run([sys.executable, str(GEN), '--empty', '--out', str(out)], capture_output=True, text=True)
    assert r.returncode == 0
    _, count = compile_reader(tmp_path, out)
    assert count == 'count=0'


@pytest.mark.parametrize('doc', [{'version': 1, 'files': []}, []])
def test_empty_manifest_is_an_error(tmp_path, doc):
    """A web build that emits no files must not silently produce a firmware without UI (only the
    CMake fallback path, with its warning, embeds the empty table)."""
    m = make_dist(tmp_path / 'dist', {}, doc)
    out = tmp_path / 'e2.c'
    r = generate(m, out)
    assert r.returncode == 1 and 'no files' in r.stderr and not out.exists()


def test_immutable_only_for_content_hashed_names(tmp_path):
    js = gz(APP_JS)
    files = {'index.html.gz': gz(INDEX), 'assets/app.js.gz': js, 'assets/app-5HQKP2ZB.js.gz': js,
             'assets/icons.svg.gz': gz(b'<svg/>')}
    entries = [{'path': '/', 'file': 'index.html.gz'},
               {'path': '/assets/app.js', 'file': 'assets/app.js.gz'},
               {'path': '/assets/app-5HQKP2ZB.js', 'file': 'assets/app-5HQKP2ZB.js.gz'},
               {'path': '/assets/icons.svg', 'file': 'assets/icons.svg.gz'}]
    m = make_dist(tmp_path / 'dist', files, {'files': entries})
    by = {a.path: a.immutable for a in gwa.load_assets(m)}
    assert by == {'/': False, '/assets/app.js': False, '/assets/app-5HQKP2ZB.js': True, '/assets/icons.svg': False}
    for i in (1, 3):
        doc = {'files': [dict(e, immutable=True) if j == i else e for j, e in enumerate(entries)]}
        m.write_text(json.dumps(doc))
        r = generate(m, tmp_path / 'x.c')
        assert r.returncode == 1 and 'content-hashed' in r.stderr, r.stderr
    for name in ('app.3f9a1c0d.js', 'app-5HQKP2ZB.js', 'x.0123456789abcdef0123.css'):
        assert gwa.is_content_hashed(f'/assets/{name}'), name
    for path in ('/assets/app.js', '/assets/app-settings.js', '/app.3f9a1c0d.js', '/assets/app.Settings1.js'):
        assert not gwa.is_content_hashed(path), path


def test_short_hash_token_is_a_name_hash_not_a_digest(tmp_path):
    """`hash` that is not 64 hex (e.g. esbuild's file-name hash) is accepted unverified; a 64-hex
    `hash` is verified like `sha256`; `sha256` itself must be 64 hex."""
    files = {'index.html.gz': gz(INDEX)}
    for h in ('3f9a1c0d', '5HQKP2ZB'):
        m = make_dist(tmp_path / h, files, {'files': [{'path': '/', 'hash': h}]})
        a = gwa.load_assets(m)[0]
        assert a.etag == '"' + hashlib.sha256(gz(INDEX)).hexdigest()[:16] + '"'
    m = make_dist(tmp_path / 'full', files, {'files': [{'path': '/', 'hash': hashlib.sha256(INDEX).hexdigest()}]})
    assert gwa.load_assets(m)[0].etag == '"' + hashlib.sha256(INDEX).hexdigest()[:16] + '"'
    m = make_dist(tmp_path / 'bad', files, {'files': [{'path': '/', 'hash': '0' * 64}]})
    with pytest.raises(gwa.ManifestError, match='sha256 matches neither'):
        gwa.load_assets(m)
    m = make_dist(tmp_path / 'short', files, {'files': [{'path': '/', 'sha256': '3f9a1c0d'}]})
    with pytest.raises(gwa.ManifestError, match='64 hex'):
        gwa.load_assets(m)


def test_build_web_manifest_shape(tmp_path):
    """tools/build_web.mjs: {"assets":[{path, file: plain, gz: gzip file, gz_size, size, etag}]};
    the .gz file is embedded as-is (its size is what total_gz counts)."""
    z = gzip.compress(INDEX, compresslevel=6, mtime=0)                    # not what gzip -9 here would give
    files = {'index.html': INDEX, 'index.html.gz': z}
    entry = {'path': '/', 'file': 'index.html', 'gz': 'index.html.gz', 'mime': 'text/html; charset=utf-8',
             'etag': '"44efe11404d9ad1f"', 'immutable': False, 'size': len(INDEX), 'gz_size': len(z)}
    m = make_dist(tmp_path / 'ok', files, {'version': 1, 'budget_gz': 65536, 'total_gz': len(z), 'assets': [entry]})
    (a,) = gwa.load_assets(m)
    assert a.gz == z and a.etag == '"44efe11404d9ad1f"'
    m = make_dist(tmp_path / 'mismatch', {'index.html': b'other', 'index.html.gz': z}, {'assets': [entry]})
    with pytest.raises(gwa.ManifestError, match='does not decompress'):
        gwa.load_assets(m)
    m = make_dist(tmp_path / 'notgz', {'index.html': INDEX, 'index.html.gz': INDEX},
                  {'assets': [dict(entry, gz_size=len(INDEX))]})
    with pytest.raises(gwa.ManifestError, match='not a gzip file'):
        gwa.load_assets(m)
    m = make_dist(tmp_path / 'size', files, {'assets': [dict(entry, gz_size=1)]})
    with pytest.raises(gwa.ManifestError, match='gzip size'):
        gwa.load_assets(m)


def test_fallback_file_is_equivalent_to_empty(tmp_path):
    fb = ROOT / 'components' / 'web' / 'fallback' / 'web_assets_fallback.c'
    _, count = compile_reader(tmp_path, fb)
    assert count == 'count=0'


def test_budget_gate(tmp_path):
    big = os.urandom(70 * 1024)                                             # incompressible
    m = make_dist(tmp_path / 'dist', {'index.html.gz': gz(big)}, {'files': [{'path': '/'}]})
    out = tmp_path / 'big.c'
    r = generate(m, out, '--budget', str(64 * 1024))
    assert r.returncode == 1 and 'budget' in r.stderr and not out.exists()
    assert generate(m, out).returncode == 0
    assert (tmp_path / 'webfs' / 'index.html.gz').read_bytes() == gz(big)
    assert 'static const uint8_t' not in out.read_text()


@pytest.mark.parametrize('mutate, needle', [
    (lambda e: e[0].update(sha256='0' * 64), 'sha256'),
    (lambda e: e[0].update(gz=1), 'gzip size'),
    (lambda e: e[0].update(size=1), 'uncompressed size'),
    (lambda e: e.append(dict(e[0])), 'duplicate'),
    (lambda e: e[0].update(path='/a b'), 'invalid URL path'),
    (lambda e: e[0].update(path='/assets/../x'), 'invalid URL path'),
    (lambda e: e[0].update(file='../outside.gz'), 'inside the dist'),
    (lambda e: e[0].update(file='missing.gz'), 'not found'),
    (lambda e: e[0].update(etag='W/"abc"'), 'strong'),
    (lambda e: e[0].update(etag='"a b"'), 'invalid ETag'),
    (lambda e: e[0].update(mime='text/html\r\nX: y'), 'invalid mime'),
    (lambda e: e[0].update(mime='nonsense'), 'invalid mime'),
    (lambda e: e[1].update(immutable=True), 'must not be immutable'),
    (lambda e: e[0].update(immutable='yes'), 'boolean'),
    (lambda e: e.pop(1), 'no entry for "/"'),
])
def test_manifest_errors(tmp_path, mutate, needle):
    manifest, _ = standard(tmp_path)
    doc = json.loads(manifest.read_text())
    doc.pop('total_gz')
    mutate(doc['files'])
    manifest.write_text(json.dumps(doc))
    out = tmp_path / 'x.c'
    r = generate(manifest, out)
    assert r.returncode == 1, r.stdout
    assert needle in r.stderr, r.stderr
    assert not out.exists()


def test_corrupt_gzip_and_total_mismatch(tmp_path):
    good = gz(INDEX)
    m = make_dist(tmp_path / 'd1', {'index.html.gz': good[:-6]}, {'files': [{'path': '/'}]})
    r = generate(m, tmp_path / 'a.c')
    assert r.returncode == 1 and 'corrupt gzip' in r.stderr
    m = make_dist(tmp_path / 'd2', {'index.html.gz': good}, {'files': [{'path': '/'}], 'total_gz': 3})
    r = generate(m, tmp_path / 'b.c')
    assert r.returncode == 1 and 'total_gz' in r.stderr
    (tmp_path / 'bad.json').write_text('{')
    r = generate(tmp_path / 'bad.json', tmp_path / 'c.c')
    assert r.returncode == 1


def test_c_string_escaping():
    assert gwa.c_string('a"b\\c') == r'"a\"b\\c"'
    assert gwa.c_string('??=') == r'"\077\077="'                          # no trigraphs
    assert gwa.c_string('é1') == r'"\303\2511"'                           # octal never swallows digits
    assert gwa.c_string('\n') == r'"\012"'


# ---------------------------------------------------------------- CMake hook (scratch repo layout)

NODE = shutil.which('node') or next(iter(sorted(Path.home().glob('.nvm/versions/node/v*/bin/node'), reverse=True)), None)
CMAKE = shutil.which('cmake', path=str(ROOT / '.venv' / 'bin')) or shutil.which('cmake')
NINJA = shutil.which('ninja', path=str(ROOT / '.venv' / 'bin')) or shutil.which('ninja')

FAKE_BUILD_WEB = r'''
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
rmSync('web/dist', { recursive: true, force: true });
mkdirSync('web/dist/assets', { recursive: true });
const js = readFileSync('web/src/main.js');
const h = createHash('sha256').update(js).digest('hex').slice(0, 8);
const out = [
  ['/', 'index.html.gz', 'text/html; charset=utf-8', readFileSync('web/index.html'), false],
  [`/assets/app.${h}.js`, `assets/app.${h}.js.gz`, 'text/javascript; charset=utf-8', js, true],
];
const files = out.map(([path, file, mime, raw, immutable]) => {
  const z = gzipSync(raw, { level: 9 });
  writeFileSync(`web/dist/${file}`, z);
  return { path, file, mime, immutable, sha256: createHash('sha256').update(z).digest('hex'), gz: z.length };
});
writeFileSync('web/dist/manifest.json', JSON.stringify({ version: 1, files }));
writeFileSync('web/build_count', String(Number(readFileSync('web/build_count', 'utf8') || 0) + 1));
'''

FAKE_PROJECT = r'''
cmake_minimum_required(VERSION 3.22)
project(gwhook C)
set_property(GLOBAL PROPERTY GW_PY "@PY@")
function(idf_build_get_property var prop)
  get_property(v GLOBAL PROPERTY GW_PY)
  set(${var} "${v}" PARENT_SCOPE)
endfunction()
add_subdirectory(components/web)
'''

FAKE_WEB_CMAKE = r'''
add_executable(reader reader.c)
target_include_directories(reader PRIVATE include)
target_compile_options(reader PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(reader PRIVATE WEB_FS_ROOT="${CMAKE_CURRENT_BINARY_DIR}/webfs")
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/gw_web_assets.cmake")
gw_web_assets(reader)
'''


def scratch_repo(tmp_path: Path, with_web=True, with_esbuild=True) -> Path:
    root = tmp_path / 'repo'
    (root / 'cmake').mkdir(parents=True)
    shutil.copy(HOOK, root / 'cmake' / HOOK.name)
    (root / 'tools').mkdir()
    shutil.copy(GEN, root / 'tools' / GEN.name)
    web_c = root / 'components' / 'web'
    shutil.copytree(ROOT / 'components' / 'web' / 'include', web_c / 'include')
    shutil.copytree(ROOT / 'components' / 'web' / 'fallback', web_c / 'fallback')
    (web_c / 'reader.c').write_text(READER_C)
    (web_c / 'CMakeLists.txt').write_text(FAKE_WEB_CMAKE)
    (root / 'CMakeLists.txt').write_text(FAKE_PROJECT.replace('@PY@', sys.executable))
    if with_web:
        (root / 'tools' / 'build_web.mjs').write_text(FAKE_BUILD_WEB)
        (root / 'web' / 'src').mkdir(parents=True)
        (root / 'web' / 'index.html').write_text('<!doctype html><title>t</title>')
        (root / 'web' / 'src' / 'main.js').write_text('console.log(1);\n')
        (root / 'web' / 'build_count').write_text('0')
    if with_esbuild:
        (root / 'node_modules' / 'esbuild').mkdir(parents=True)
        (root / 'node_modules' / 'esbuild' / 'package.json').write_text('{}')
    return root


def build_env(root: Path) -> dict:
    env = {**os.environ, 'NVM_BIN': str(Path(NODE).parent)} if NODE else dict(os.environ)
    env['TMPDIR'] = str(root.parent)          # must NOT matter: the lock lives next to web/dist
    return env


def ninja(root: Path):
    return subprocess.run([NINJA, '-C', str(root / 'build')], capture_output=True, text=True, env=build_env(root))


def cmake_build(root: Path, *defs):
    b = root / 'build'
    env = build_env(root)
    cfg = subprocess.run([CMAKE, '-G', 'Ninja', f'-DCMAKE_MAKE_PROGRAM={NINJA}', '-S', str(root), '-B', str(b), *defs],
                         capture_output=True, text=True, env=env)
    assert cfg.returncode == 0, cfg.stdout + cfg.stderr
    bld = subprocess.run([NINJA, '-C', str(b)], capture_output=True, text=True, env=env)
    return cfg, bld


def run_reader(root: Path):
    out = subprocess.run([str(root / 'build' / 'components' / 'web' / 'reader')], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout
    return out.stdout.splitlines()


needs_cmake = pytest.mark.skipif(not (CMAKE and NINJA), reason='cmake/ninja not available')


@needs_cmake
@pytest.mark.skipif(not NODE, reason='node not available')
def test_cmake_hook_builds_and_rebuilds_on_web_change(tmp_path):
    root = scratch_repo(tmp_path)
    cfg, bld = cmake_build(root)
    assert bld.returncode == 0, bld.stdout + bld.stderr
    assert 'web UI built with' in cfg.stdout
    lines = run_reader(root)
    assert lines[-1] == 'count=2' and lines[0].startswith('/\t')
    assert (root / 'web' / 'build_count').read_text() == '1'
    # one lock per source tree, independent of TMPDIR (every environment serialises on it)
    assert (root / 'web' / '.dist.lock').is_file()
    assert not list(tmp_path.glob('gw_web_*.lock'))
    # no change -> nothing rebuilt (the first ninja re-runs CMake once because web/dist appeared,
    # DECISIONS "G: CMake hook"; the configure-time lock file never causes another re-run)
    bld = ninja(root)
    assert bld.returncode == 0 and (root / 'web' / 'build_count').read_text() == '1'
    bld = ninja(root)
    assert bld.returncode == 0 and 'Re-running CMake' not in bld.stdout and 'no work to do' in bld.stdout, bld.stdout
    # edit a web source -> UI rebuilt, new hashed name in the table
    (root / 'web' / 'src' / 'main.js').write_text('console.log(2);\n')
    bld = ninja(root)
    assert bld.returncode == 0, bld.stdout + bld.stderr
    assert (root / 'web' / 'build_count').read_text() == '2'
    assert any('console.log(2)' in gzip.decompress(bytes.fromhex(l.split('\t')[5])).decode()
               for l in run_reader(root)[:-1])
    # a new file in an existing web/ directory is picked up (CONFIGURE_DEPENDS glob)
    (root / 'web' / 'src' / 'extra.js').write_text('//\n')
    bld = ninja(root)
    assert bld.returncode == 0 and (root / 'web' / 'build_count').read_text() == '3'


@needs_cmake
@pytest.mark.skipif(not NODE, reason='node not available')
def test_cmake_hook_warns_above_review_threshold(tmp_path):
    root = scratch_repo(tmp_path)
    (root / 'web' / 'src' / 'main.js').write_text('//' + os.urandom(300 * 1024).hex() + '\n')
    _, bld = cmake_build(root)
    assert bld.returncode == 0 and 'review threshold' in bld.stdout + bld.stderr


@needs_cmake
def test_cmake_hook_uses_prebuilt_dist_without_esbuild(tmp_path):
    root = scratch_repo(tmp_path, with_esbuild=False)
    make_dist(root / 'web' / 'dist', {'index.html.gz': gz(INDEX)}, {'files': [{'path': '/'}]})
    cfg, bld = cmake_build(root)
    assert bld.returncode == 0, bld.stdout + bld.stderr
    assert 'prebuilt' in cfg.stderr and 'npm ci' in cfg.stderr
    assert run_reader(root)[-1] == 'count=1'
    assert (root / 'web' / 'build_count').read_text() == '0'                # node build not run


@needs_cmake
@pytest.mark.parametrize('with_web, defs', [(False, ()), (True, ('-DGW_WEB_ASSETS=OFF',))])
def test_cmake_hook_fallback(tmp_path, with_web, defs):
    root = scratch_repo(tmp_path, with_web=with_web)
    cfg, bld = cmake_build(root, *defs)
    assert bld.returncode == 0, bld.stdout + bld.stderr
    assert 'empty fallback' in cfg.stderr
    assert run_reader(root)[-1] == 'count=0'


# ---------------------------------------------------------------- interop with stream D's real build


needs_web_build = pytest.mark.skipif(
    not (NODE and (ROOT / 'tools' / 'build_web.mjs').is_file() and (ROOT / 'node_modules' / 'esbuild').is_dir()),
    reason='tools/build_web.mjs (stream D) or node_modules/esbuild not available')


def real_web_build(tmp_path):
    """node tools/build_web.mjs --out <tmp>: never touches the shared web/dist (no lock needed)."""
    out = tmp_path / 'dist'
    env = {**os.environ, 'PATH': f'{Path(NODE).parent}{os.pathsep}{os.environ.get("PATH", "")}'}
    r = subprocess.run([NODE, 'tools/build_web.mjs', '--quiet', '--out', str(out)], cwd=ROOT,
                       capture_output=True, text=True, env=env, timeout=300)
    over_budget = r.returncode == 1 and 'exceeds' in r.stderr and (out / 'manifest.json').is_file()
    assert r.returncode == 0 or over_budget, r.stdout + r.stderr
    return out / 'manifest.json', r


@needs_web_build
def test_real_web_build_manifest_is_consumable(tmp_path):
    """build_web.mjs manifest -> generator -> compiled table (interop with stream D's real output;
    the budget is checked separately below)."""
    manifest, _ = real_web_build(tmp_path)
    out = tmp_path / 'web_assets.c'
    g = generate(manifest, out, '--budget', str(1024 * 1024))
    assert g.returncode == 0, g.stderr
    rows, count = compile_reader(tmp_path, out)
    paths = [x['path'] for x in rows]
    assert '/' in paths and int(count.split('=')[1]) == len(rows)
    declared = json.loads(manifest.read_text())
    assert sum(int(x['len']) for x in rows) == declared['total_gz']    # the .gz files were embedded as-is
    for x in rows:
        body = gzip.decompress(bytes.fromhex(x['hex']))
        assert body, x['path']
        assert (x['imm'] == '1') == (x['path'] not in ('/', '/favicon.svg')), x['path']
        assert (x['imm'] == '1') == gwa.is_content_hashed(x['path']), x['path']
    index = gzip.decompress(bytes.fromhex(rows[paths.index('/')]['hex'])).decode('utf-8')
    for ref in re.findall(r'(?:src|href)="(/assets/[^"]+)"', index):
        assert ref in paths, f'index.html references {ref}, not in the table'


@needs_web_build
def test_real_web_build_stages_compressed_files(tmp_path):
    """The production build succeeds and stages gzip bodies outside the metadata-only app table."""
    manifest, r = real_web_build(tmp_path)
    assert r.returncode == 0, r.stderr
    g = generate(manifest, tmp_path / 'web_assets.c')
    assert g.returncode == 0, g.stderr
    assert (tmp_path / 'webfs' / 'index.html.gz').is_file()
    assert 'static const uint8_t' not in (tmp_path / 'web_assets.c').read_text()
