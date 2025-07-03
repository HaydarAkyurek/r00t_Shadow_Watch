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
        print("[-] Permission denied reading /proc/kallsyms. Try running with sudo.")
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

        # Basit bir kontrol: Adres 0x80000000'den küçükse uyarı ver (örnek)
        try:
            addr_int = int(syscall_table_addr, 16)
            if addr_int < 0x80000000:
                print("[WARNING] sys_call_table address is unusually low, possible tampering!")
            else:
                print("[INFO] sys_call_table address looks normal.")
        except ValueError:
            print("[ERROR] Could not parse syscall table address.")

    else:
        print("[WARNING] sys_call_table not found! It may be hidden or renamed.")

