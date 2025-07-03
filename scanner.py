#!/usr/bin/env python3
"""
shadowwatch - Linux kernel rootkit detection tool

This is the main entry point of the tool. It coordinates and runs all available modules.
"""

import os
import sys
from modules import check_syscall

def is_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0

def main():
    print("\n=== Shadowwatch Rootkit Scanner ===\n")

    if not is_root():
        print("[!] Please run this script as root.")
        sys.exit(1)

    print("[*] Running system integrity checks...\n")

    # Run the syscall table integrity check
    try:
        check_syscall.run()
    except Exception as e:
        print(f"[ERROR] check_syscall failed: {e}")

    print("\n[*] Scan completed. Review findings above.\n")

if __name__ == "__main__":
    main()
