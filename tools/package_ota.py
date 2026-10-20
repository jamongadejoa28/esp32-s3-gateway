#!/usr/bin/env python3
"""Package matching firmware and a LittleFS web image for streaming OTA."""
import argparse
import hashlib
from pathlib import Path
import struct

from littlefs import LittleFS, UserContext
from littlefs.errors import LittleFSError

MAGIC = b'GWOTA1\r\n'
HEADER = struct.Struct('<8sII32s32s')
APP_LIMIT = 0x280000
WEB_SIZE = 0x80000


def package(app: bytes, web: bytes) -> bytes:
    if not 288 <= len(app) <= APP_LIMIT or app[0] != 0xe9:
        raise ValueError('invalid application image or application exceeds the 2.5 MiB slot')
    if len(web) != WEB_SIZE:
        raise ValueError('web image must be exactly 512 KiB')
    fs = LittleFS(context=UserContext(buffer=bytearray(web)), mount=False,
                  block_size=4096, block_count=WEB_SIZE // 4096, name_max=64)
    fs.mount()
    with fs.open('/.asset-id', 'rb') as f:
        identity = f.read()
    fs.unmount()
    if len(identity) != 74 or not identity.startswith(b'GW_WEB_ID:') or identity + b'\0' not in app:
        raise ValueError('firmware and LittleFS web assets do not match; rebuild both together')
    return HEADER.pack(MAGIC, len(app), len(web), hashlib.sha256(app).digest(),
                       hashlib.sha256(web).digest()) + app + web


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--app', type=Path, required=True)
    ap.add_argument('--web', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    try:
        data = package(args.app.read_bytes(), args.web.read_bytes())
        args.out.write_bytes(data)
    except (OSError, ValueError, LittleFSError) as e:
        ap.exit(1, f'package_ota: {e}\n')
    print(f'OTA package: {len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()} -> {args.out}')


if __name__ == '__main__':
    main()
