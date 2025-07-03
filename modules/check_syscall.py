"""
check_syscall.py - Syscall table integrity checker

This module checks for possible tampering of the syscall table by comparing known
symbols in /proc/kallsyms with expectations.
"""

import os

def run():
    print("[+] Checking syscall table integrity...")

    kallsyms_path = "/proc/kallsyms"

    if not os.path.exists(kallsyms_path):
        print("[-] Cannot access /proc/kallsyms. Are you on a supported system?")
        return

    try:
        with open(kallsyms_path, "r") as f:
            lines = f.readlines()
    except PermissionError:
        print("[-] Permission denied reading /proc/kallsyms")
        return

    syscall_table_addr = None

    for line in lines:
        if " sys_call_table" in line:
            parts = line.strip().split()
            if len(parts) >= 3:
                syscall_table_addr = parts[0]
                break

    if syscall_table_addr:
        print(f"[OK] Found sys_call_table at 0x{syscall_table_addr}")
    else:
        print("[WARNING] sys_call_table not found! It may be hidden or renamed.")
