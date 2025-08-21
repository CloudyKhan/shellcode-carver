#!/usr/bin/env python3

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path
from typing import List
from dataclasses import dataclass

class Config:
    MIN_SIZE = 32

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class TextExtractor:
    @staticmethod
    def _extract_from_arrays(content: str) -> List[bytes]:
        candidates = []
        array_blocks = re.findall(r'[\{\[](.*?)[\}\]]', content, flags=re.DOTALL)
        num_pattern = re.compile(r'(?:0x|\\x)([0-9a-fA-F]{1,2})|\b(\d{1,3})\b')
        for block in array_blocks:
            byte_values = []
            for match in num_pattern.finditer(block):
                hex_val, dec_val = match.groups()
                try:
                    if hex_val:
                        byte_values.append(int(hex_val, 16))
                    elif dec_val:
                        num = int(dec_val)
                        if 0 <= num <= 255:
                            byte_values.append(num)
                except ValueError:
                    continue
            if len(byte_values) >= Config.MIN_SIZE:
                candidates.append(bytes(byte_values))
        return candidates

    @staticmethod
    def _extract_from_base64(content: str) -> List[bytes]:
        candidates = []
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{32,}={0,2}')
        for m in b64_pattern.finditer(content):
            b64_str = m.group()
            if len(b64_str) % 4 != 0:
                b64_str += '=' * (4 - len(b64_str) % 4)
            try:
                data = base64.b64decode(b64_str)
                if len(data) >= Config.MIN_SIZE:
                    candidates.append(data)
            except Exception:
                continue
        return candidates

    @staticmethod
    def extract_all(content: str) -> List[bytes]:
        content = re.sub(r'//.*|#.*', '', content)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        results = []
        results.extend(TextExtractor._extract_from_arrays(content))
        results.extend(TextExtractor._extract_from_base64(content))
        unique, seen = [], set()
        for data in results:
            h = sha256(data)
            if h not in seen:
                unique.append(data)
                seen.add(h)
        return unique

@dataclass
class ShellcodeRegion:
    data: bytes
    sha256: str = ""

    def __post_init__(self):
        self.sha256 = sha256(self.data)

class ShellcodeCarver:
    def carve_file(self, filepath: Path) -> List[ShellcodeRegion]:
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []
        candidates = TextExtractor.extract_all(content)
        if not candidates:
            try:
                binary_content = filepath.read_bytes()
                if len(binary_content) >= Config.MIN_SIZE:
                    candidates.append(binary_content)
            except Exception:
                pass
        return [ShellcodeRegion(data=c) for c in candidates]

def main():
    parser = argparse.ArgumentParser(
        description="Definitive Shellcode Carver. Prints extracted shellcode as raw hex.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 carver.py malware.cs
  python3 carver.py malware.cs > shellcode.txt
"""
    )
    parser.add_argument('files', nargs='+', type=Path, help='Files to carve')
    args = parser.parse_args()

    carver = ShellcodeCarver()
    for filepath in args.files:
        if not filepath.exists():
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            continue
        regions = carver.carve_file(filepath)
        if regions:
            for region in regions:
                print(region.data.hex())
        elif 'malware' in str(filepath).lower():
            print(f"No shellcode found in {filepath}", file=sys.stderr)

if __name__ == '__main__':
    main()
