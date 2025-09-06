#!/usr/bin/env python3
"""
fast_scanner.py
Fast threaded TCP port scanner using threading + queue.

Usage examples:
    python3 fast_scanner.py -t 127.0.0.1 -p 1-1024 -n 200 -to 0.5 -o results.txt -b

IMPORTANT: Only scan hosts/networks you own or are authorized to test.
"""

import socket
import argparse
import threading
import queue
import time
from datetime import datetime

def worker(target, q, open_ports, timeout, do_banner, lock):
    while True:
        try:
            port = q.get_nowait()

        except:
            if queue.Empty:
                return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = ''

                if do_banner:
                    try:
                        s.settimeout(1.0)
                        banner = s.recv(1024).decode(errors="ignore").strip()

                    except Exception:
                        banner = ''
                with lock:
                    open_ports.append((port, banner))

        except Exception:
            pass

        finally:
            q.task_done()

def parse_ports(port_string):
    """
    Accepts:
      - single port: "80"
      - comma list: "22,80,443"
      - range: "1-1024"
      - mix: "22,80,8000-9000"
    Returns sorted list of ints.
    """

    ports = set()
    for parts in port_string.split(','):
        parts.strip()
        if '-' in parts:
            start, end = parts.split('-', 1)
            start = int(start); end = int(end)
            if start > end:
                start, end = end, start

            ports.update(range(start, end +1)) 

        else:
            if parts:
                ports.add(int(parts))


    return sorted(p for p in ports if 1<= p <= 65535) 



def main():
    parser = argparse.ArgumentParser(description='Fast TCP Port scanner. (Use wisely)')
    parser.add_argument('-t', '--target',  required=True, help="IP address or hostname")
    parser.add_argument('-p', '--ports', default='1-1024', help="{80, 80,443, 80,443,1000-2000}")
    parser.add_argument('-n', '--threads', type=int, default=100, help='Number of threads to sends per second')
    parser.add_argument('-to', '--timeout', type=float, default=0.5, help='Set timeout')
    parser.add_argument('-o', '--output', type=str, help='Optional for saving output to a file')
    parser.add_argument('-b', '--banner', action='store_true', help='Try to grab banners from open ports (short recv)')

    args = parser.parse_args()

    try:
        targetIP = socket.gethostbyname(args.target)
    except Exception as e:
        print(f"[!] Could not resolve target {args.target}: {e}")
        return

    try:
        ports = parse_ports(args.ports)
 
    except Exception:
        print(f"[-] Not valid ports to scan")    
        return
    
    q = queue.Queue()

    for port in ports:
        q.put(port)


    open_ports = []
    lock = threading.Lock()
    threads = []

    start = time.perf_counter()

    print(f"[+] Scanning {args.target} ({targetIP}) for {len(ports)} ports with {args.threads} threads...")

    for _ in range(args.threads):
        t = threading.Thread(target = worker, args=(targetIP,q , open_ports, args.timeout, args.banner, lock), daemon=True)
        t.start()

        threads.append(t)

    q.join()

    finish = time.perf_counter()

    duration = finish - start

    open_ports.sort(key=lambda x: x[0])

    if open_ports:
        print(f"\n[+] Open ports on {args.target}:")
        for port, banner in open_ports:
            if banner:
                print(f"  {port}/tcp  OPEN  banner: {banner}")
            else:
                print(f"  {port}/tcp  OPEN")
    else:
        print(f"\n[-] No open TCP ports found on {args.target} (within scanned range).")

    print(f"\nScan completed in {duration:.2f} seconds.")

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"Scan results for {args.target} ({targetIP})\n")
                f.write(f"Scanned ports: {args.ports}\n")
                f.write(f"Threads: {args.threads}, Timeout: {args.timeout}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
                if open_ports:
                    for port, banner in open_ports:
                        if banner:
                            f.write(f"{port}/tcp OPEN  banner: {banner}\n")
                        else:
                            f.write(f"{port}/tcp OPEN\n")
                else:
                    f.write("No open ports found.\n")
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results to {args.output}: {e}")

if __name__ == "__main__":
    main()     


