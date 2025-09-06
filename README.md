# fast_tcp_scanner
⚠️ **Disclaimer**  
This tool is for **educational and authorized security testing only**.  
Do not scan systems you don’t own or have explicit permission to test.  
Unauthorized scanning may be illegal.  

---

## 📖 About
`fast_scanner.py` is a **multi-threaded TCP port scanner** written in Python.  
It supports port ranges, banner grabbing, and saving results to a file.  

It is similar in concept to `nmap -p- -T4`, but implemented with Python’s `socket`, `threading`, and `queue` libraries for learning and lightweight scanning.  

---

## ⚙️ Features
- ✅ Fast scanning with multithreading  
- ✅ Supports single ports, ranges, and mixed lists (`22,80,8000-9000`)  
- ✅ Configurable thread count and timeouts  
- ✅ Optional **banner grabbing** (short recv)  
- ✅ Save results to file with metadata (host, timestamp, scanned ports)  

---

## 🚀 Installation
Clone this repo and run with Python 3:

```bash
git clone https://github.com/yourname/fast-scanner.git
cd fast-scanner
No extra dependencies required (only Python standard library).

▶️ Usage
Basic scan (default 1–1024 ports):
bash
Copy code
python3 fast_scanner.py -t 127.0.0.1
Scan specific port range:
bash
Copy code
python3 fast_scanner.py -t 192.168.1.10 -p 20-100
Scan mixed list of ports:
bash
Copy code
python3 fast_scanner.py -t scanme.nmap.org -p 22,80,443,8000-8100
Increase threads & decrease timeout (faster scan):
bash
Copy code
python3 fast_scanner.py -t 192.168.1.10 -p 1-65535 -n 300 -to 0.3
Save results to a file:
bash
Copy code
python3 fast_scanner.py -t 192.168.1.10 -p 1-1024 -o results.txt
Attempt banner grabbing:
bash
Copy code
python3 fast_scanner.py -t 192.168.1.10 -p 21,22,25,80,443 -b
📝 Example Output
sql
Copy code
[+] Scanning scanme.nmap.org (45.33.32.156) for 1024 ports with 200 threads...

[+] Open ports on scanme.nmap.org:
  22/tcp  OPEN  banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80/tcp  OPEN
  443/tcp OPEN

Scan completed in 2.45 seconds.
[+] Results saved to results.txt
🔧 Command-line Options
Flag	Description
-t, --target	Target IP or hostname (required)
-p, --ports	Ports to scan (default = 1-1024)
-n, --threads	Number of threads (default = 100)
-to, --timeout	Timeout per connection in seconds (default = 0.5)
-o, --output	Save scan results to a file
-b, --banner	Attempt to grab service banners
