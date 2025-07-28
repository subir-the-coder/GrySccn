# GryScan

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/b02638b0-d02b-48e2-8d14-bc7672f5ec4d" />


Advanced Reconnaissance Suite with WAF Bypass
# Gryscr - Advanced Reconnaissance Suite
![Banner](assets/banner.png)  <!-- Optional -->

A Python-based recon tool for bug bounty hunters and pentesters. Features:
- WAF detection & bypass
- CSP header analysis
- Subdomain enumeration
- Nuclei integration

# Core Requirements
requests==2.31.0
colorama==0.4.6
dnspython==2.4.2
pyOpenSSL==23.3.0

# Linux-Specific Tools (Must be installed via apt)
# sudo apt install -y subfinder httpx nuclei waybackurls wafw00f shodan jq ffuf

## 🐧 Linux-Specific Installation

```bash

# 1. Install Linux tools (Debian/Ubuntu)
sudo apt update && sudo apt install -y \
    subfinder \
    httpx \
    nuclei \
    waybackurls \
    wafw00f \
    shodan \
    jq \
    ffuf

# 2. Install Shodan CLI (if needed)
pip install shodan
shodan init YOUR_API_KEY

Warning
This tool requires Linux (Coded on Parrot OS)

Dependency on Linux-native tools (subfinder, nuclei)

POSIX-compliant shell commands

---

### Modify Code for Linux Validation**
Add this check at the start of your script (`gryscr.py`):

```python
import platform
import sys

def check_linux():
    if platform.system() != "Linux":
        print(f"{Fore.RED}[!] This tool requires Linux (Parrot OS/ Kali )
        print(f"{Fore.YELLOW}[!] Use Parrot Os VM for Windows/Mac{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    check_linux()  # Add this beore main to check()
    # ... if yes, code goes here ...

## Installation
```bash
git clone https://github.com/your-username/gryscr.git
pip install -r requirements.txt

python3 recon.py -u example.com
