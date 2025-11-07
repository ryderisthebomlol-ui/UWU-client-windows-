#!/usr/bin/env python3
# uwuconsole - with built-in tutorial (trigger: h\)
# Features: password gate, prompt ">", map command with IP/CIDR/range/hostname support

import os
import socket
import concurrent.futures
import time
import re
import ipaddress
import sys

PASSWORD = "2025"
PROMPT = "> "
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 139, 143,
    161, 162, 179, 389, 443, 445, 465, 514, 587, 631, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2095, 2096,
    3306, 3389, 3632, 4444, 5060, 5432, 5900, 5985, 6379, 8080, 8443
]
SOCKET_TIMEOUT = 0.5  # seconds per port
MAX_HOSTS = 1024      # refuse scanning networks larger than this

ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
range_re = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def show_welcome():
    clear_screen()
    print("Welcome To UWU Client. Type commands below:\n")

def show_help():
    clear_screen()
    help_text = r"""
UWU Client - Quick Tutorial
---------------------------

Commands
  h\    - Show this tutorial (also responds to: h, help, h/)
  cls   - Clear screen and show welcome message
  exit  - Quit the UWU Client
  map   - Network mapper. Usage examples below
  any OS command - You can run normal shell/Windows commands (e.g., dir, ping)

map usage examples
  > map
    Scans your local /24 network automatically (e.g., 192.168.x.1-254).

  > map 192.168.1.23
    Scan a single IPv4 host (checks the common port list).

  > map 192.168.1.0/24
    Scan a CIDR network. Supports common CIDR masks but will refuse networks > 1024 hosts.

  > map 192.168.1
    Shorthand for scanning 192.168.1.1-192.168.1.254 (a /24).

  > map 192.168.1.10-192.168.1.50
    Scan an explicit IP range.

  > map example.com
    Resolve the domain to IPv4 address(es) and scan each resolved IP.

Notes & tips
  - Scanning public hosts/networks you do NOT own may be illegal or flagged. Only scan targets you have permission to test.
  - You can cancel an ongoing scan with Ctrl+C.
  - The script scans a set of "common ports" (keeps it reasonably fast). Ask me if you want
    a custom port list or to save results to a file.
  - If a hostname resolves to multiple IPs (CDN/load-balancer), each IP will be scanned.
  - For very large scans (>1024 hosts) the script refuses to run — tell me if you want a confirmation override.

Examples (interactive)
  Enter password to access UWU Client: 2025
  Welcome To UWU Client. Type commands below:

  > map 8.8.8.8
  Scanning single host 8.8.8.8 ...
  [8.8.8.8] Open ports: 53

  > map example.com
  Scanning example.com -> targets: 93.184.216.34 ...
  [93.184.216.34] Open ports: 80, 443

  > cls
  (screen clears, welcome message printed)

If you'd like more help:
  - Ask for "save results to file" and I'll add `map ... > file.txt` support.
  - Ask for "custom ports" and I'll add `map target --ports 80,443,8080`.

Press Enter to return to the console.
"""
    print(help_text)
    input("")  # pause until user presses enter
    show_welcome()

def check_password():
    pwd = input("Enter password to access UWU Client: ")
    if pwd != PASSWORD:
        print("Access Denied.")
        sys.exit(1)

def get_local_ip():
    """Return the likely local IPv4 address for outbound traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            res = sock.connect_ex((ip, port))
            return res == 0
    except Exception:
        return False

def scan_host_ports(ip):
    open_ports = []
    for p in COMMON_PORTS:
        if scan_port(ip, p):
            open_ports.append(p)
    return (ip, open_ports)

def ips_from_cidr_or_shorthand(t):
    # Accept both full CIDR and 3-octet shorthand
    try:
        # if it's like "192.168.1" treat as 3-octet shorthand /24
        parts = t.split(".")
        if len(parts) == 3:
            base = ".".join(parts) + ".0/24"
            net = ipaddress.ip_network(base, strict=False)
        else:
            net = ipaddress.ip_network(t, strict=False)
        # limit size
        hosts = list(net.hosts())
        if len(hosts) > MAX_HOSTS:
            print(f"Network too large ({len(hosts)} hosts). Refusing to scan more than {MAX_HOSTS} hosts.")
            return []
        return [str(h) for h in hosts]
    except Exception:
        return []

def ips_from_range(t):
    m = range_re.match(t)
    if not m:
        return []
    try:
        a = ipaddress.ip_address(m.group(1))
        b = ipaddress.ip_address(m.group(2))
        if a.version != 4 or b.version != 4:
            return []
        if int(b) < int(a):
            return []
        count = int(b) - int(a) + 1
        if count > MAX_HOSTS:
            print(f"Range too large ({count} hosts). Refusing to scan more than {MAX_HOSTS} hosts.")
            return []
        return [str(ipaddress.ip_address(int(a) + i)) for i in range(count)]
    except Exception:
        return []

def ips_from_target(target):
    """
    Returns:
      - None -> caller should use local /24
      - []   -> invalid/unresolved/too-large (treated as error by caller)
      - list -> list of IP strings to scan
    """
    if not target:
        return None

    t = target.strip()

    # CIDR like 192.168.1.0/24 or shorthand 192.168.1
    if "/" in t or (t.count(".") == 2 and not t.endswith(".")):
        ips = ips_from_cidr_or_shorthand(t)
        return ips

    # IP range like 192.168.1.10-192.168.1.50
    if "-" in t:
        ips = ips_from_range(t)
        return ips

    # single IPv4
    if ip_re.match(t):
        parts = t.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return [t]
        return []

    # hostname: resolve to IPv4 addresses
    try:
        infos = socket.getaddrinfo(t, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []

def map_network(target_arg=None):
    print("Starting network map... (this may take a while)")
    start = time.time()

    # determine ips to scan
    if not target_arg:
        local_ip = get_local_ip()
        if not local_ip or local_ip.startswith("127."):
            print("Could not determine local IP. Aborting map.")
            return
        parts = local_ip.split(".")
        if len(parts) != 4:
            print("Unexpected local IP format:", local_ip)
            return
        base3 = ".".join(parts[:3]) + ".0/24"
        ips = ips_from_cidr_or_shorthand(base3)
        if not ips:
            print("Could not build local /24 targets. Aborting.")
            return
        print(f"Scanning local /24 based on {local_ip} ...")
    else:
        ips = ips_from_target(target_arg)
        if ips is None:
            print("Internal error parsing target. Aborting.")
            return
        if not ips:
            print(f"Could not resolve or parse target '{target_arg}'.")
            return
        if len(ips) == 1:
            print(f"Scanning single host {ips[0]} ...")
        else:
            print(f"Scanning {len(ips)} host(s): {', '.join(map(str, ips[:10]))}{'...' if len(ips)>10 else ''}")

    results = []
    # set workers proportional to #hosts
    max_workers = min(200, max(10, len(ips)))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(scan_host_ports, ip): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    ip, open_ports = fut.result()
                    if open_ports:
                        results.append((ip, open_ports))
                        print(f"[{ip}] Open ports: {', '.join(map(str, open_ports))}")
                except Exception:
                    # ignore per-host errors
                    pass
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        return

    elapsed = time.time() - start
    if not results:
        print("No open ports found on common ports across the scanned targets.")
    else:
        print("\nSummary:")
        for ip, ports in sorted(results):
            print(f"  {ip}: {', '.join(map(str, ports))}")
    print(f"\nNetwork map complete in {elapsed:.1f}s.")

def main_loop():
    while True:
        try:
            cmd = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not cmd:
            continue

        # normalize
        low = cmd.lower().strip()

        # tutorial triggers: exact h\ (user requested), plus common aliases
        if low in ("h\\", "h", "help", "h/"):
            show_help()
            continue

        if low == "cls":
            show_welcome()
        elif low == "exit":
            print("Goodbye.")
            break
        elif low.startswith("map"):
            parts = cmd.split(None, 1)
            arg = parts[1].strip() if len(parts) > 1 else None
            try:
                map_network(arg)
            except KeyboardInterrupt:
                print("\nScan cancelled.")
        else:
            # run as OS command
            try:
                os.system(cmd)
            except Exception as e:
                print("Error running command:", e)

if __name__ == "__main__":
    check_password()
    show_welcome()
    main_loop()