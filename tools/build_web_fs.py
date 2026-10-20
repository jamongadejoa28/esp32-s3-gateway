#!/usr/bin/env python3
"""Create and verify a LittleFS web image using the locked littlefs-python dependency."""
import argparse
from pathlib import Path

from littlefs import LittleFS
from littlefs.errors import LittleFSError


def build(source: Path, size: int) -> bytes:
    if size <= 0 or size % 4096:
        raise ValueError('LittleFS size must be a positive multiple of 4096')
    if not (source / '.asset-id').is_file():
        raise ValueError('missing .asset-id; generate the web filesystem first')
    fs = LittleFS(block_size=4096, block_count=size // 4096, name_max=64)
    files = sorted(p for p in source.rglob('*') if p.is_file())
    for directory in sorted(p for p in source.rglob('*') if p.is_dir()):
        fs.mkdir(directory.relative_to(source).as_posix())
    for path in files:
        with fs.open('/' + path.relative_to(source).as_posix(), 'wb') as f:
            f.write(path.read_bytes())
    fs.unmount()
    image = bytes(fs.context.buffer)
    fs.mount()
    for path in files:
        with fs.open('/' + path.relative_to(source).as_posix(), 'rb') as f:
            if f.read() != path.read_bytes():
                raise ValueError(f'LittleFS verification failed: {path.name}')
    fs.unmount()
    return image


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--size', type=lambda s: int(s, 0), required=True)
    args = ap.parse_args()
    try:
        data = build(args.source, args.size)
        args.out.write_bytes(data)
    except (OSError, ValueError, LittleFSError) as e:
        ap.exit(1, f'build_web_fs: {e}\n')
    print(f'LittleFS web image: {len(data)} bytes -> {args.out}')


if __name__ == '__main__':
    main()
