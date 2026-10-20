#!/usr/bin/env python3
"""Validate a web build manifest, stage gzip files for LittleFS and emit a small C metadata table.

Accepts files/assets manifests from build_web.mjs, verifies gzip, hashes, sizes and cache policy,
then writes only compressed files and .asset-id to --fs-out (default: <out directory>/webfs).
The generated C contains paths, MIME types, ETags, lengths and a matching identity, never bodies.
256 KiB is a review warning; --budget optionally enforces an explicit hard limit. The actual
512 KiB LittleFS image capacity (including filesystem overhead) is enforced by build_web_fs.py.
--empty generates only a zero-entry table for API-only builds.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

BUDGET_GZ = 256 * 1024
MAX_PATH_LEN = 128           # well below CONFIG_HTTPD_MAX_URI_LEN=256
MAX_MIME_LEN = 100
MAX_ASSETS = 256
PATH_RE = re.compile(r'^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$')
ETAG_RE = re.compile(r'^"[\x21\x23-\x7e]{1,64}"$')
MIME_RE = re.compile(r'^[\x20-\x7e]+$')
HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')
# web_assets.h: content-hashed bundle files "/assets/<name>.<hash>.<ext>" (hex or esbuild base32 hash)
HASHED_NAME_RE = re.compile(r'^[^/]+[.-](?:[0-9a-f]{8,64}|[0-9A-Z]{8,64})\.[A-Za-z0-9]+$')

MIME_BY_EXT = {
    '.html': 'text/html', '.htm': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
    '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json',
    '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.ico': 'image/x-icon',
    '.woff2': 'font/woff2', '.txt': 'text/plain', '.map': 'application/json',
}
CHARSET_TYPES = ('text/', 'application/javascript', 'application/json', 'application/manifest+json',
                 'image/svg+xml')
NOT_IMMUTABLE = ('/', '/favicon.svg')


class ManifestError(Exception):
    """The manifest or a dist file is inconsistent; message names the entry."""


@dataclass(frozen=True)
class Asset:
    path: str
    mime: str
    etag: str
    gz: bytes
    immutable: bool


def _first(entry: dict, *keys, default=None):
    for k in keys:
        if k in entry and entry[k] is not None:
            return entry[k]
    return default


def _norm_url_path(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ManifestError(f'{where}: missing "path"')
    p = raw.strip()
    if not p.startswith('/'):
        p = '/' + p
    if p in ('/index.html', '/index.htm'):
        p = '/'
    if len(p) > MAX_PATH_LEN:
        raise ManifestError(f'{where}: path longer than {MAX_PATH_LEN}: {p!r}')
    if not PATH_RE.match(p) or any(seg in ('.', '..') for seg in p.split('/')):
        raise ManifestError(f'{where}: invalid URL path {p!r}')
    return p


def _dist_file(dist: Path, rel: str, where: str) -> Path | None:
    """rel resolved inside dist (error if it escapes), or None when it is not a file."""
    rp = PurePosixPath(rel)
    if rp.is_absolute() or '..' in rp.parts:
        raise ManifestError(f'{where}: file must stay inside the dist directory: {rel!r}')
    root = dist.resolve()
    f = (dist / rp).resolve()
    if root not in f.parents:
        raise ManifestError(f'{where}: file escapes the dist directory: {rel!r}')
    return f if f.is_file() else None


def _resolve_files(dist: Path, entry: dict, url_path: str, where: str) -> tuple[Path, Path | None, bool]:
    """(file to embed, plain counterpart to cross-check or None, file must already be gzip)."""
    gz_rel = next((entry[k] for k in ('gz', 'gz_file', 'gzfile') if isinstance(entry.get(k), str)), None)
    rel = _first(entry, 'file', 'out', 'dist')
    for name, v in (('gz', gz_rel), ('file', rel)):
        if v is not None and (not isinstance(v, str) or not v):
            raise ManifestError(f'{where}: "{name}" must be a non-empty string')
    if gz_rel is not None:                     # build_web.mjs: "file" = plain, "gz" = gzip file
        f = _dist_file(dist, gz_rel, where)
        if f is None:
            raise ManifestError(f'{where}: gzip file not found in {dist}: {gz_rel}')
        return f, (_dist_file(dist, rel, where) if rel else None), True
    if rel is not None:
        candidates = [rel]
    else:
        base = 'index.html' if url_path == '/' else url_path.lstrip('/')
        candidates = [base + '.gz', base]
    for c in candidates:
        f = _dist_file(dist, c, where)
        if f is not None:
            return f, None, False
    raise ManifestError(f'{where}: file not found in {dist}: {" or ".join(candidates)}')


def _mime(entry: dict, url_path: str, where: str) -> str:
    m = _first(entry, 'mime', 'type', 'content_type', 'contentType')
    if m is None:
        ext = '.html' if url_path == '/' else PurePosixPath(url_path).suffix.lower()
        m = MIME_BY_EXT.get(ext)
        if m is None:
            raise ManifestError(f'{where}: no "mime" and unknown extension {ext!r}')
    if not isinstance(m, str):
        raise ManifestError(f'{where}: "mime" must be a string')
    m = m.strip()
    if 'charset=' not in m.lower() and m.lower().startswith(CHARSET_TYPES):
        m += '; charset=utf-8'
    if not m or len(m) > MAX_MIME_LEN or not MIME_RE.match(m) or '/' not in m.split(';')[0]:
        raise ManifestError(f'{where}: invalid mime {m!r}')
    return m


def _gzip_body(f: Path, where: str, must_be_gzip: bool = False) -> tuple[bytes, bytes]:
    """(gzip body, uncompressed content). Plain files are compressed deterministically."""
    data = f.read_bytes()
    if must_be_gzip and data[:2] != b'\x1f\x8b':
        raise ManifestError(f'{where}: {f.name} is not a gzip file')
    if data[:2] == b'\x1f\x8b':
        try:
            plain = gzip.decompress(data)
        except (OSError, EOFError, zlib.error) as e:
            raise ManifestError(f'{where}: corrupt gzip file {f.name}: {e}') from None
        return data, plain
    return gzip.compress(data, compresslevel=9, mtime=0), data


def is_content_hashed(url_path: str) -> bool:
    """True for "/assets/<name>.<hash>.<ext>" (the only paths that may be served immutable)."""
    return url_path.startswith('/assets/') and bool(HASHED_NAME_RE.match(url_path.rsplit('/', 1)[-1]))


def _digest(entry: dict, where: str) -> str | None:
    """The declared SHA-256 (64 hex, lower case) or None. `hash` counts only when it is 64 hex."""
    h = entry.get('sha256')
    if h is not None:
        if not isinstance(h, str) or not HEX64_RE.match(h):
            raise ManifestError(f'{where}: "sha256" must be 64 hex digits')
        return h.lower()
    h = entry.get('hash')
    if h is not None and not isinstance(h, str):
        raise ManifestError(f'{where}: "hash" must be a string')
    return h.lower() if h and HEX64_RE.match(h) else None


def _etag(entry: dict, gz: bytes, where: str) -> str:
    e = _first(entry, 'etag', 'ETag')
    if e is None:
        e = f'"{(_digest(entry, where) or hashlib.sha256(gz).hexdigest())[:16]}"'
    if not isinstance(e, str):
        raise ManifestError(f'{where}: "etag" must be a string')
    e = e.strip()
    if e.startswith('W/'):
        raise ManifestError(f'{where}: ETag must be strong, got {e!r}')
    if not e.startswith('"'):
        e = f'"{e}"'
    if not ETAG_RE.match(e):
        raise ManifestError(f'{where}: invalid ETag {e!r}')
    return e


def _check_integrity(entry: dict, gz: bytes, plain: bytes, where: str) -> None:
    h = _digest(entry, where)
    if h is not None:
        if h not in (hashlib.sha256(gz).hexdigest(), hashlib.sha256(plain).hexdigest()):
            raise ManifestError(f'{where}: sha256 matches neither the gzip body nor its content')
    n = next((entry[k] for k in ('gz_size', 'size_gz', 'gzSize', 'gz', 'gzip', 'bytes')
              if entry.get(k) is not None and not (k in ('gz', 'gzip') and isinstance(entry[k], str))), None)
    if n is not None:
        if not isinstance(n, int) or isinstance(n, bool) or n != len(gz):
            raise ManifestError(f'{where}: gzip size {n!r} != actual {len(gz)}')
    s = _first(entry, 'size', 'raw_size', 'rawSize')
    if s is not None and (not isinstance(s, int) or isinstance(s, bool) or s != len(plain)):
        raise ManifestError(f'{where}: size {s!r} != uncompressed size {len(plain)}')


def load_assets(manifest_path: Path, dist: Path | None = None) -> list[Asset]:
    """Parse and verify the manifest; return the assets sorted in strcmp order."""
    try:
        doc = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManifestError(f'{manifest_path}: {e}') from None
    dist = dist or manifest_path.parent
    if isinstance(doc, dict):
        files = _first(doc, 'files', 'assets')
        if files is None:
            raise ManifestError(f'{manifest_path}: no "files" list')
    else:
        files = doc
    if not isinstance(files, list):
        raise ManifestError(f'{manifest_path}: "files" must be a list')
    if len(files) > MAX_ASSETS:
        raise ManifestError(f'{manifest_path}: {len(files)} files (max {MAX_ASSETS})')
    assets: dict[str, Asset] = {}
    for i, entry in enumerate(files):
        where = f'{manifest_path.name}: files[{i}]'
        if not isinstance(entry, dict):
            raise ManifestError(f'{where}: entry must be an object')
        path = _norm_url_path(_first(entry, 'path', 'url', 'route'), where)
        where = f'{where} ({path})'
        if path in assets:
            raise ManifestError(f'{where}: duplicate path')
        f, plain_f, must_be_gzip = _resolve_files(dist, entry, path, where)
        gz, plain = _gzip_body(f, where, must_be_gzip)
        if plain_f is not None and plain_f.read_bytes() != plain:
            raise ManifestError(f'{where}: {f.name} does not decompress to {plain_f.name}')
        _check_integrity(entry, gz, plain, where)
        hashed = is_content_hashed(path)
        immutable = _first(entry, 'immutable', default=hashed)
        if not isinstance(immutable, bool):
            raise ManifestError(f'{where}: "immutable" must be a boolean')
        if immutable and path in NOT_IMMUTABLE:
            raise ManifestError(f'{where}: must not be immutable (contract: web/web_assets.h)')
        if immutable and not hashed:
            raise ManifestError(f'{where}: immutable requires a content-hashed name '
                                '"/assets/<name>.<hash>.<ext>" (browsers would cache it for a year)')
        if len(gz) == 0 or len(gz) > 0xFFFFFFFF:
            raise ManifestError(f'{where}: bad gzip size {len(gz)}')
        assets[path] = Asset(path, _mime(entry, path, where), _etag(entry, gz, where), gz, immutable)
    if not assets:
        raise ManifestError(f'{manifest_path}: no files (empty web build); the empty table is only '
                            'written with --empty')
    if '/' not in assets:
        raise ManifestError(f'{manifest_path}: no entry for "/" (index.html)')
    total = sum(len(a.gz) for a in assets.values())
    declared = _first(doc, 'total_gz', 'totalGz', 'gz_total') if isinstance(doc, dict) else None
    if declared is not None and declared != total:
        raise ManifestError(f'{manifest_path}: total_gz {declared!r} != actual {total}')
    return sorted(assets.values(), key=lambda a: a.path.encode('utf-8'))


def c_string(s: str) -> str:
    """C string literal; octal escapes are always 3 digits so the next char cannot extend them."""
    out = []
    for b in s.encode('utf-8'):
        ch = chr(b)
        if ch in '"\\':
            out.append('\\' + ch)
        elif 0x20 <= b < 0x7f and ch != '?':   # '?' avoided: trigraphs
            out.append(ch)
        else:
            out.append(f'\\{b:03o}')
    return '"' + ''.join(out) + '"'


def render_c(assets: list[Asset], source: str, budget: int) -> str:
    total = sum(len(a.gz) for a in assets)
    lines = [
        f'/* Generated by tools/gen_web_assets.py from {source} - DO NOT EDIT.',
        f' * {len(assets)} files, {total} bytes gzip (review threshold {budget}).',
        ' * Contract: components/web/include/web/web_assets.h (sorted by path, strcmp order). */',
        '#include "web/web_assets.h"',
        '',
    ]
    if not assets:
        lines += ['const web_asset_t gw_web_assets[] = {{NULL, NULL, NULL, NULL, 0, false}};',
                  'const size_t gw_web_assets_count = 0;', 'const char gw_web_assets_id[] = "";', '']
        return '\n'.join(lines)
    lines += ['', 'const web_asset_t gw_web_assets[] = {']
    for a in assets:
        lines.append(f'    {{{c_string(a.path)}, {c_string(a.mime)}, {c_string(a.etag)}, {c_string(asset_file(a))}, '
                     f'{len(a.gz)}u, {"true" if a.immutable else "false"}}},')
    lines += ['};', f'const size_t gw_web_assets_count = {len(assets)}u;', '']
    lines.append(f'const char gw_web_assets_id[] = "GW_WEB_ID:{asset_id(assets)}";')
    return '\n'.join(lines)


def asset_file(asset: Asset) -> str:
    return ('index.html' if asset.path == '/' else asset.path.lstrip('/')) + '.gz'


def asset_id(assets: list[Asset]) -> str:
    h = hashlib.sha256()
    for a in assets:
        h.update(json.dumps([a.path, a.mime, a.etag, a.immutable], separators=(',', ':')).encode())
        h.update(a.gz)
    return h.hexdigest()


def write_filesystem(assets: list[Asset], out: Path) -> None:
    """Stage only validated gzip files; never place plaintext or the build manifest in LittleFS."""
    import shutil
    if out.exists():
        if any(out.iterdir()) and not (out / '.asset-id').is_file():
            raise ManifestError(f'refusing to clean {out}: not a previous web filesystem')
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for a in assets:
        target = out / asset_file(a)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(a.gz)
    (out / '.asset-id').write_text(f'GW_WEB_ID:{asset_id(assets)}', encoding='ascii')


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text, encoding='utf-8', newline='\n')
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--manifest', type=Path, help='web/dist/manifest.json')
    ap.add_argument('--dist', type=Path, help='directory the manifest paths are relative to '
                    '(default: the manifest directory)')
    ap.add_argument('--out', type=Path, required=True, help='C file to write')
    ap.add_argument('--fs-out', type=Path, help='LittleFS staging directory (default: <out directory>/webfs)')
    ap.add_argument('--budget', type=int, help='optional explicit hard gzip limit; default: warn above 256 KiB')
    ap.add_argument('--empty', action='store_true', help='write the empty table')
    args = ap.parse_args(argv)
    if args.empty:
        write_atomic(args.out, render_c([], '(none)', BUDGET_GZ))
        print(f'gen_web_assets: wrote empty table {args.out}')
        return 0
    if args.manifest is None:
        ap.error('--manifest is required unless --empty')
    try:
        assets = load_assets(args.manifest, args.dist)
    except ManifestError as e:
        print(f'gen_web_assets: error: {e}', file=sys.stderr)
        return 1
    total = sum(len(a.gz) for a in assets)
    if args.budget is not None and total > args.budget:
        print(f'gen_web_assets: error: web UI is {total} bytes gzip, over the {args.budget}-byte budget '
              '(DESIGN.md §11)', file=sys.stderr)
        for a in sorted(assets, key=lambda a: -len(a.gz)):
            print(f'  {len(a.gz):7d}  {a.path}', file=sys.stderr)
        return 1
    try:
        src = args.manifest.resolve().relative_to(Path(__file__).resolve().parents[1]).as_posix()
    except ValueError:
        src = args.manifest.name
    if total > BUDGET_GZ:
        print(f'gen_web_assets: warning: {total} bytes gzip exceeds the {BUDGET_GZ}-byte review threshold', file=sys.stderr)
    try:
        write_filesystem(assets, args.fs_out or args.out.parent / 'webfs')
    except (OSError, ManifestError) as e:
        print(f'gen_web_assets: error: {e}', file=sys.stderr)
        return 1
    write_atomic(args.out, render_c(assets, src, BUDGET_GZ))
    print(f'gen_web_assets: {len(assets)} files, {total} bytes gzip in LittleFS; metadata -> {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
