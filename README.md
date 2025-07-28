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

## Installation
```bash
git clone https://github.com/your-username/gryscr.git
pip install -r requirements.txt

python3 gryscr.py -u example.com
