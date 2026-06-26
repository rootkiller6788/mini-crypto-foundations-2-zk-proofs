#!/usr/bin/env python3
"""Build all source files for mini-interactive-proof-systems."""

import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)

def write_file(relpath, content):
    path = os.path.join(BASE, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    lines = content.count('\n')
    print(f"  WROTE {relpath}: {lines} lines")
    return lines

total_lines = 0
print("Building mini-interactive-proof-systems...")
print()
