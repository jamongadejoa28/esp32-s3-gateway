"""Read actual LittleFS images back and test OTA packaging, limits and partition pairing."""
import ctypes
import gzip
import hashlib
import os
from pathlib import Path
import sys

from littlefs import LittleFS, UserContext
import pytest

from conftest import ROOT, CFLAGS, INCLUDE_FLAGS, cc

sys.path.insert(0, str(ROOT / 'tools'))
import build_web_fs
import gen_web_assets as assets
import package_ota


@pytest.fixture
def web_image(tmp_path):
    # Incompressible content deliberately exceeds the old 64 KiB artificial limit.
    bodies = [assets.Asset('/', 'text/html', '"index"', gzip.compress(os.urandom(70 * 1024)), False),
              assets.Asset('/assets/app.12345678.js', 'text/javascript', '"js"', gzip.compress(b'console.log(1)'), True)]
    stage = tmp_path / 'webfs'
    assets.write_filesystem(bodies, stage)
    return bodies, stage, build_web_fs.build(stage, package_ota.WEB_SIZE)


def test_littlefs_contains_only_compressed_files_and_identity(web_image):
    bodies, _, image = web_image
    assert len(image) == 0x80000
    fs = LittleFS(context=UserContext(buffer=bytearray(image)), block_size=4096,
                  block_count=128, name_max=64)
    with fs.open('/.asset-id', 'rb') as f:
        assert f.read() == f'GW_WEB_ID:{assets.asset_id(bodies)}'.encode()
    for asset in bodies:
        with fs.open('/' + assets.asset_file(asset), 'rb') as f:
            assert f.read() == asset.gz
    with pytest.raises(FileNotFoundError):
        fs.open('/index.html', 'rb')
    fs.unmount()


def fake_app(bodies):
    app = bytearray(4096)
    app[0] = 0xe9
    # Near a readback-buffer boundary to exercise the C uploader's overlap handling.
    app[3950:4025] = f'GW_WEB_ID:{assets.asset_id(bodies)}\0'.encode()
    return bytes(app)


def test_package_checks_both_hashes_and_pair_identity(web_image):
    bodies, _, image = web_image
    app = fake_app(bodies)
    packet = package_ota.package(app, image)
    magic, app_len, web_len, app_sha, web_sha = package_ota.HEADER.unpack_from(packet)
    assert (magic, app_len, web_len) == (package_ota.MAGIC, len(app), len(image))
    assert app_sha == hashlib.sha256(app).digest()
    assert web_sha == hashlib.sha256(image).digest()
    assert packet[80:80 + app_len] == app and packet[80 + app_len:] == image
    with pytest.raises(ValueError, match='do not match'):
        package_ota.package(bytes([0xe9]) + bytes(4095), image)
    with pytest.raises(ValueError, match='512 KiB'):
        package_ota.package(app, image[:-1])
    with pytest.raises(ValueError, match='2.5 MiB'):
        package_ota.package(app + bytes(package_ota.APP_LIMIT), image)


def test_actual_filesystem_capacity_is_enforced(tmp_path):
    stage = tmp_path / 'webfs'
    assets.write_filesystem([assets.Asset('/', 'text/html', '"x"',
                                          gzip.compress(os.urandom(550 * 1024)), False)], stage)
    from littlefs.errors import LittleFSError
    with pytest.raises(LittleFSError):
        build_web_fs.build(stage, 0x80000)


def test_c_header_parser_rejects_overflow_truncation_and_wrong_web_size(tmp_path, web_image):
    src = tmp_path / 'parser.c'
    src.write_text('#include "web/ota_package.h"\n'
                   'int valid(const unsigned char *h, size_t len) { return web_ota_header_valid(h, len); }\n')
    lib = tmp_path / 'parser.so'
    cc([*CFLAGS, *INCLUDE_FLAGS, '-shared', '-fPIC', str(src), '-o', str(lib)])
    parser = ctypes.CDLL(str(lib)).valid
    parser.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    bodies, _, image = web_image
    packet = package_ota.package(fake_app(bodies), image)
    assert parser(packet[:80], len(packet))
    assert not parser(packet[:80], len(packet) - 1)
    for offset in (8, 12):
        header = bytearray(packet[:80])
        header[offset:offset + 4] = b'\xff' * 4
        assert not parser(bytes(header), len(packet))
    assert not parser(b'x' * 80, len(packet))
    assert not parser(None, len(packet))
    assert not parser(packet[:80], 79)


def test_partition_layout_keeps_persistent_data_and_pairs_ui_with_each_app():
    parts = {}
    for line in (ROOT / 'partitions.csv').read_text().splitlines():
        if line.startswith('#') or not line.strip():
            continue
        name, kind, subtype, offset, size, *_ = [s.strip() for s in line.split(',')]
        parts[name] = (int(offset, 0), int(size, 0))
    assert parts['data'] == (0x620000, 0x9d0000)
    for index, start in enumerate((0x20000, 0x320000)):
        assert parts[f'ota_{index}'] == (start, package_ota.APP_LIMIT)
        assert parts[f'web_{index}'] == (start + package_ota.APP_LIMIT, package_ota.WEB_SIZE)
