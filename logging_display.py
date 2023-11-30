# logging_display.py

def err(x: str):
    print(f"[-] {x}")

def warn(x: str):
    print(f"[!] {x}")

def ok(x: str):
    print(f"[+] {x}")

def info(x: str):
    print(f"[*] {x}")

def dbg(x: str, debug: bool):
    if debug:
        print(f"[DBG] {x}")