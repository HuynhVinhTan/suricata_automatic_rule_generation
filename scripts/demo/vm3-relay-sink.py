#!/usr/bin/env python3
"""Binary-safe bounded JSONL sink; it does not parse or alter EVE records."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
MAX_FILE_BYTES=128*1024*1024
def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument('--root',type=Path,required=True); args=parser.parse_args()
    args.root.mkdir(parents=True,exist_ok=True); current=args.root/'eve-shadow.jsonl'; rotated=args.root/'eve-shadow.jsonl.1'; out=current.open('ab')
    try:
        for chunk in iter(lambda:sys.stdin.buffer.read(64*1024),b''):
            if current.stat().st_size+len(chunk)>MAX_FILE_BYTES:
                out.flush(); out.close(); rotated.unlink(missing_ok=True); current.replace(rotated); out=current.open('ab')
            out.write(chunk); out.flush()
    finally: out.close()
    return 0
if __name__=='__main__': raise SystemExit(main())
