#!/usr/bin/env python3
import subprocess
import sys
import binwalk

def check_file_type(fp):
    print("🔍 Checking file type and debug info support...")
    try:
        out = subprocess.check_output(['file', fp], text=True)
        print(f"  file: {out.strip()}")
    except Exception as e:
        print(f"  file check failed: {e}")
    print()

def strings_analysis(fp):
    print("🔡 Running strings scan...")
    try:
        out = subprocess.check_output(['strings', '-n', '6', fp], text=True)
        lines = out.strip().splitlines()
        count = min(20, len(lines))
        print(f"  Found {len(lines)} printable strings, showing first {count}:")
        for s in lines[:count]:
            print(f"    - {s}")
    except Exception as e:
        print(f"  strings scan failed: {e}")
    print()

def binwalk_scan(fp):
    print("🧩 Binwalk signature + entropy scan...")
    scans = binwalk.scan(fp, signature=True, entropy=True, quiet=True, nplot=True)
    for module in scans:
        print(f"\n== {module.name} ==")
        for res in module.results:
            offset = hex(res.offset)
            size = res.size
            description = res.description
            print(f"  Offset: {offset}, Size: {size}, Description: {description}")
    print()

def main():
    if len(sys.argv) != 2:
        print("Usage: analyze_firmware.py <firmware.bin>")
        sys.exit(1)
    fp = sys.argv[1]
    check_file_type(fp)
    strings_analysis(fp)
    binwalk_scan(fp)

if __name__ == '__main__':
    main()
