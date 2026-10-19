#!/usr/bin/env python3
"""Flash the gateway firmware and open the serial monitor (MANUAL USE ONLY - touches the USB device).

This is the only project tool that opens a serial port, and only when run by a person with an
explicit port and confirmation:

    uv run --locked python tools/run_device.py --port /dev/ttyACM0 --yes [--no-flash] [--no-monitor]

Without BOTH --port and --yes it refuses and exits with status 2 before doing anything. There is no
default port and no port is read from settings, so tasks/scripts cannot reach a device by accident.
It never runs automatically (not from tests, CMake or the VS Code build task).
Steps: `idf.py -B <build> -p PORT flash` (unless --no-flash), then `idf.py -B <build> -p PORT monitor`
(unless --no-monitor). --dry-run prints the commands without touching the port.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0], epilog='Refuses without --port and --yes.')
    ap.add_argument('--port', help='serial port of the board, e.g. /dev/ttyACM0 (required, no default)')
    ap.add_argument('--yes', action='store_true', help='confirm that this may use the attached device (required)')
    ap.add_argument('--no', action='store_true', help='explicitly decline (the VS Code task default); exits 2')
    ap.add_argument('--build-dir', default='build', help='IDF build directory (default: build)')
    ap.add_argument('--no-flash', action='store_true', help='only open the monitor')
    ap.add_argument('--no-monitor', action='store_true', help='only flash')
    ap.add_argument('--baud', type=int, help='flash baud rate (idf.py -b)')
    ap.add_argument('--dry-run', action='store_true', help='print the commands and exit; touches nothing')
    return ap.parse_args(argv)


def commands(args) -> list[list[str]]:
    base = [sys.executable, str(ROOT / 'tools' / 'idf.py'), '-B', args.build_dir, '-p', args.port]
    if args.baud:
        base += ['-b', str(args.baud)]
    cmds = []
    if not args.no_flash:
        cmds.append([*base, 'flash'])
    if not args.no_monitor:
        cmds.append([*base, 'monitor'])
    return cmds


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.no:
        print('run_device.py: declined (--no); nothing was done.', file=sys.stderr)
        return 2
    missing = [flag for flag, ok in (('--port PORT', bool(args.port)), ('--yes', args.yes)) if not ok]
    if missing:
        print(f'run_device.py: refusing to touch a serial device without {" and ".join(missing)}.\n'
              'This tool flashes/monitors real hardware and is for manual use only; '
              'see docs/HW_TEST.md.', file=sys.stderr)
        return 2
    if args.no_flash and args.no_monitor:
        print('run_device.py: nothing to do (--no-flash and --no-monitor)', file=sys.stderr)
        return 2
    cmds = commands(args)
    if args.dry_run:
        for c in cmds:
            print(shlex.join(c))
        return 0
    if not os.path.exists(args.port):
        print(f'run_device.py: {args.port} does not exist', file=sys.stderr)
        return 2
    print(f'run_device.py: using {args.port} (flash={not args.no_flash}, monitor={not args.no_monitor})', flush=True)
    for c in cmds:
        rc = subprocess.call(c, cwd=ROOT)
        if rc:
            return rc
    return 0


if __name__ == '__main__':
    sys.exit(main())
