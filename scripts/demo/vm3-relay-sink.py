#!/usr/bin/env python3
"""Binary-safe bounded JSONL sink; it does not parse or alter EVE records."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
MAX_FILE_BYTES=128*1024*1024
MAX_TOTAL_BYTES=512*1024*1024
def storage_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.glob('eve-shadow.jsonl*') if path.is_file())
def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--max-file-bytes',type=int,default=MAX_FILE_BYTES)
    parser.add_argument('--max-total-bytes',type=int,default=MAX_TOTAL_BYTES)
    args=parser.parse_args()
    if args.max_file_bytes < 1 or args.max_total_bytes < args.max_file_bytes:
        parser.error('file and total byte caps are invalid')
    args.root.mkdir(parents=True,exist_ok=True)
    current=args.root/'eve-shadow.jsonl'
    out=current.open('ab')
    pending=b''
    try:
        for chunk in iter(lambda:sys.stdin.buffer.read(64*1024),b''):
            pending += chunk
            while b'\n' in pending:
                record, pending = pending.split(b'\n', 1)
                record += b'\n'
                if storage_bytes(args.root) + len(record) > args.max_total_bytes:
                    print('RELAY_STORAGE_CAP_REACHED: refusing further writes', file=sys.stderr)
                    return 75
                if current.stat().st_size and current.stat().st_size + len(record) > args.max_file_bytes:
                    out.flush(); out.close()
                    sequence = 1
                    while (args.root / f'eve-shadow.jsonl.{sequence}').exists():
                        sequence += 1
                    current.replace(args.root / f'eve-shadow.jsonl.{sequence}')
                    out=current.open('ab')
                out.write(record); out.flush()
        # A JSONL record without its newline is deliberately not published:
        # delivery is bounded to complete records and can be retried by the source.
    finally:
        out.close()
    return 0
if __name__=='__main__': raise SystemExit(main())
