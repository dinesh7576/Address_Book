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
    print(f"  strings scan success")
    print()

def binwalk_scan(firmware_path):
    # Run both signature and entropy scans quietly
    modules = binwalk.scan(firmware_path, signature=True, entropy=True, quiet=True)

    for module in modules:
        print(f"Module: {module.name}")
        for res in module.results:
            # Parse res.description to float if it's entropy, or just use description for signatures
            desc = res.description.strip()
            try:
                entropy = float(desc)
                # Use thresholds
                if entropy < 0.523:
                    status = "low entropy"
                elif entropy > 0.697:
                    status = "high entropy"
                else:
                    status = "moderate entropy"
                print(f"  Offset: 0x{res.offset:X}, Entropy: {entropy:.3f} -> {status}")
            except ValueError:
                # Not a numeric description – likely a signature
                print(f"  Offset: 0x{res.offset:X}, Signature: {desc}")
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
