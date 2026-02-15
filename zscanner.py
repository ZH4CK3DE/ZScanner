"""
Title: ZScanner

Advanced web vulnerability scanner for authorized penetration testing 

Author: ZH4CK3DE
Twitter: @CITO_FR
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
import threading
from queue import Queue
from datetime import datetime
import logging
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from colorama import Fore, Style, init
import html as html_escape
import warnings
warnings.filterwarnings('ignore')

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zscanner.log'),
        logging.StreamHandler()
    ]
)

class ZScanner:
    def __init__(self, target_url, max_depth=3, max_threads=10, json_report=True, html_report=True):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.json_report = json_report
        self.html_report = html_report
        
        self.visited_urls = set()
        self.urls_to_visit = Queue()
        self.forms = []
        self.vulnerabilities = []
        self.emails = set()
        self.phone_numbers = set()
        self.api_keys = set()
        self.subdomains = set()
        
        # stats
        self.start_time = time.time()
        self.requests_sent = 0
        
        # headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
        }
        
        # SQLi payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "1' AND '1'='1' UNION SELECT NULL--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "1' UNION ALL SELECT NULL,NULL,NULL--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
            "<svg><script>alert&#40;1&#41;</script>",
            "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
            "<table background='javascript:alert(1)'>",
            "<object data='javascript:alert(1)'>"
        ]
        
        # LFI/RFI payloads
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "file:///etc/passwd"
        ]
        
        # command injection payloads
        self.cmd_payloads = [
            "; ls",
            "| ls",
            "& dir",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)"
        ]
        
        # db error patterns
        self.sql_errors = {
            'MySQL': [
                'SQL syntax.*MySQL',
                'Warning.*mysql_.*',
                'valid MySQL result',
                'MySqlClient\\.',
                'com\\.mysql\\.jdbc\\.exceptions',
                'MySqlException',
                'SQLSTATE\[HY000\]'
            ],
            'PostgreSQL': [
                'PostgreSQL.*ERROR',
                'Warning.*\\Wpg_.*',
                'valid PostgreSQL result',
                'Npgsql\\.',
                'PG::SyntaxError'
            ],
            'MSSQL': [
                'Driver.*SQL[-_ ]*Server',
                'OLE DB.*SQL Server',
                '(\\W|^)SQL Server.*Driver',
                'Warning.*mssql_.*',
                'Microsoft SQL Native Client error',
                'ODBC SQL Server Driver'
            ],
            'Oracle': [
                '\\bORA-[0-9][0-9][0-9][0-9]',
                'Oracle error',
                'Oracle.*Driver',
                'Warning.*\\Woci_.*',
                'Warning.*\\Wora_.*',
                'OracleException'
            ],
            'SQLite': [
                'SQLite/JDBCDriver',
                'SQLite.Exception',
                'System.Data.SQLite.SQLiteException',
                'Warning.*sqlite_.*',
                'SQLite error'
            ]
        }
        
        # security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'Enforces HTTPS',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME-sniffing protection',
            'Content-Security-Policy': 'XSS/injection mitigation',
            'X-XSS-Protection': 'Legacy XSS filter',
            'Referrer-Policy': 'Referrer leakage control',
            'Permissions-Policy': 'Feature policy',
            'X-Permitted-Cross-Domain-Policies': 'Cross-domain policy',
            'Cross-Origin-Embedder-Policy': 'COEP protection',
            'Cross-Origin-Opener-Policy': 'COOP protection',
            'Cross-Origin-Resource-Policy': 'CORP protection'
        }
        
        # common vuln paths to check
        self.common_paths = [
            '/admin',
            '/login',
            '/wp-admin',
            '/phpmyadmin',
            '/.git',
            '/.env',
            '/config',
            '/backup',
            '/api',
            '/debug',
            '/test'
        ]
        
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
    ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
      ███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
     ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}                        Made by ZH4CK3DE{Style.RESET_ALL}
{Fore.GREEN}              Advanced Web Vulnerability Scanner{Style.RESET_ALL}
{Fore.MAGENTA}                      Twitter: @CITO_FR{Style.RESET_ALL}

{Fore.RED}            [!] AUTHORIZED TESTING ONLY -> OBTAIN PERMISSION FIRST [!]{Style.RESET_ALL}

{Fore.CYAN}╭─────────────────────────────────────────────────────────────────────────────╮{Style.RESET_ALL}
{Fore.WHITE}│ [*] Target:      {self.target_url:<58}│{Style.RESET_ALL}
{Fore.WHITE}│ [*] Max Depth:   {self.max_depth:<58}│{Style.RESET_ALL}
{Fore.WHITE}│ [*] Threads:     {self.max_threads:<58}│{Style.RESET_ALL}
{Fore.WHITE}│ [*] JSON Report: {'Yes' if self.json_report else 'No':<58}│{Style.RESET_ALL}
{Fore.WHITE}│ [*] HTML Report: {'Yes' if self.html_report else 'No':<58}│{Style.RESET_ALL}
{Fore.WHITE}│ [*] Started:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<58}│{Style.RESET_ALL}
{Fore.CYAN}╰─────────────────────────────────────────────────────────────────────────────╯{Style.RESET_ALL}
"""
        print(banner)
        
    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return
            
        with self.lock:
            self.visited_urls.add(url)
            
        try:
            print(f"{Fore.BLUE}[*] crawling{Style.RESET_ALL} depth {depth}: {url}")
            response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            self.requests_sent += 1
            
            if response.status_code != 200:
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            self.extract_links(soup, url, depth)
            self.extract_forms(soup, url)
            self.find_sensitive_data(response.text, url)
            self.check_technologies(response)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"error crawling {url}: {str(e)}")
        except Exception as e:
            logging.error(f"unexpected error at {url}: {str(e)}")
            
    def extract_links(self, soup, current_url, depth):
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            
            if parsed.netloc == self.domain and full_url not in self.visited_urls:
                self.urls_to_visit.put((full_url, depth + 1))
                
    def extract_forms(self, soup, url):
        forms = soup.find_all('form')
        
        for form in forms:
            form_details = self.get_form_details(form, url)
            if form_details:
                with self.lock:
                    self.forms.append(form_details)
                print(f"{Fore.GREEN}[+] form found{Style.RESET_ALL} {form_details['action']} ({form_details['method']})")
                
    def get_form_details(self, form, url):
        try:
            action = form.get('action')
            action = urljoin(url, action) if action else url
            method = form.get('method', 'get').lower()
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
                    
            return {
                'action': action,
                'method': method,
                'inputs': inputs,
                'url': url
            }
            
        except Exception as e:
            logging.error(f"form extraction failed: {str(e)}")
            return None
    
    def check_technologies(self, response):
        """Detect technologies used on the website"""
        tech = []
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            tech.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if 'Server' in headers:
            tech.append(f"Server: {headers['Server']}")
            
        if tech:
            print(f"{Fore.CYAN}[i] Technologies: {', '.join(tech)}{Style.RESET_ALL}")
    
    def test_sql_injection(self, form_details):
        vulnerabilities_found = []
        url = form_details['action']
        
        for payload in self.sql_payloads:
            data = {}
            
            for input_field in form_details['inputs']:
                if input_field['type'] in ['text', 'search', 'email', 'password']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', 'test')
                    
            try:
                if form_details['method'] == 'post':
                    response = self.session.post(url, data=data, timeout=10, verify=False)
                else:
                    response = self.session.get(url, params=data, timeout=10, verify=False)
                
                self.requests_sent += 1
                    
                for db_type, error_patterns in self.sql_errors.items():
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'url': url,
                                'method': form_details['method'].upper(),
                                'payload': payload,
                                'database': db_type,
                                'form_url': form_details['url']
                            }
                            vulnerabilities_found.append(vuln)
                            print(f"{Fore.RED}[!] sqli detected - {db_type}{Style.RESET_ALL}")
                            break
                            
            except Exception as e:
                logging.error(f"sqli test error: {str(e)}")
                
        return vulnerabilities_found
        
    def test_xss(self, form_details):
        vulnerabilities_found = []
        url = form_details['action']
        
        for payload in self.xss_payloads:
            data = {}
            
            for input_field in form_details['inputs']:
                if input_field['type'] not in ['submit', 'button', 'image']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', 'test')
                    
            try:
                if form_details['method'] == 'post':
                    response = self.session.post(url, data=data, timeout=10, verify=False)
                else:
                    response = self.session.get(url, params=data, timeout=10, verify=False)
                
                self.requests_sent += 1
                    
                if payload in response.text:
                    if not self.is_payload_encoded(payload, response.text):
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'HIGH',
                            'url': url,
                            'method': form_details['method'].upper(),
                            'payload': payload,
                            'reflected': True,
                            'form_url': form_details['url']
                        }
                        vulnerabilities_found.append(vuln)
                        print(f"{Fore.RED}[!] xss detected (reflected){Style.RESET_ALL}")
                        
            except Exception as e:
                logging.error(f"xss test error: {str(e)}")
                
        return vulnerabilities_found
    
    def test_lfi(self, form_details):
        """Test for Local File Inclusion vulnerabilities"""
        vulnerabilities_found = []
        url = form_details['action']
        
        for payload in self.lfi_payloads:
            data = {}
            
            for input_field in form_details['inputs']:
                if input_field['type'] in ['text', 'search', 'file']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', 'test')
                    
            try:
                if form_details['method'] == 'post':
                    response = self.session.post(url, data=data, timeout=10, verify=False)
                else:
                    response = self.session.get(url, params=data, timeout=10, verify=False)
                
                self.requests_sent += 1
                
                # check for LFI indicators in response
                if 'root:' in response.text or '[extensions]' in response.text or 'for 16-bit app support' in response.text:
                    vuln = {
                        'type': 'Local File Inclusion (LFI)',
                        'severity': 'CRITICAL',
                        'url': url,
                        'method': form_details['method'].upper(),
                        'payload': payload,
                        'form_url': form_details['url']
                    }
                    vulnerabilities_found.append(vuln)
                    print(f"{Fore.RED}[!] lfi detected{Style.RESET_ALL}")
                    break
                    
            except Exception as e:
                logging.error(f"lfi test error: {str(e)}")
                
        return vulnerabilities_found
        
    def is_payload_encoded(self, payload, response):
        dangerous_chars = ['<', '>', '"', "'", '&']
        encoded_chars = ['&lt;', '&gt;', '&quot;', '&#39;', '&amp;']
        
        for char, encoded in zip(dangerous_chars, encoded_chars):
            if char in payload and encoded in response:
                return True
        return False
        
    def check_security_headers(self, url):
        try:
            print(f"\n{Fore.CYAN}╭─ security headers check{Style.RESET_ALL}")
            response = self.session.get(url, timeout=10, verify=False)
            self.requests_sent += 1
            headers = response.headers
            
            missing_headers = []
            present_headers = []
            
            for header, description in self.security_headers.items():
                if header in headers:
                    present_headers.append({
                        'header': header,
                        'value': headers[header],
                        'description': description
                    })
                    print(f"{Fore.GREEN}│ [+] {header}: {headers[header][:45]}...{Style.RESET_ALL}")
                else:
                    missing_headers.append({
                        'header': header,
                        'description': description
                    })
                    print(f"{Fore.YELLOW}│ [-] missing: {header} - {description}{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}╰{'─'*75}{Style.RESET_ALL}")
                    
            if missing_headers:
                vuln = {
                    'type': 'Missing Security Headers',
                    'severity': 'MEDIUM',
                    'url': url,
                    'missing_headers': missing_headers,
                    'present_headers': present_headers
                }
                self.vulnerabilities.append(vuln)
                
        except Exception as e:
            logging.error(f"header check failed: {str(e)}")
            
    def check_ssl_certificate(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            if parsed.scheme != 'https':
                print(f"{Fore.YELLOW}[!] no https detected{Style.RESET_ALL}")
                self.vulnerabilities.append({
                    'type': 'No HTTPS',
                    'severity': 'HIGH',
                    'url': url,
                    'description': 'Site does not enforce HTTPS'
                })
                return
                
            print(f"\n{Fore.CYAN}╭─ ssl certificate validation{Style.RESET_ALL}")
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expire = (expire_date - datetime.now()).days
                    
                    print(f"{Fore.GREEN}│ [+] ssl valid{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}│     issuer: {dict(x[0] for x in cert['issuer'])['organizationName']}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}│     expires: {cert['notAfter']} ({days_to_expire} days){Style.RESET_ALL}")
                    print(f"{Fore.CYAN}╰{'─'*75}{Style.RESET_ALL}")
                    
                    if days_to_expire < 30:
                        self.vulnerabilities.append({
                            'type': 'SSL Certificate Expiring Soon',
                            'severity': 'MEDIUM',
                            'url': url,
                            'days_remaining': days_to_expire,
                            'expire_date': cert['notAfter']
                        })
                        
        except ssl.SSLError as e:
            print(f"{Fore.RED}[!] ssl error: {str(e)}{Style.RESET_ALL}")
            self.vulnerabilities.append({
                'type': 'SSL Configuration Error',
                'severity': 'CRITICAL',
                'url': url,
                'error': str(e)
            })
        except Exception as e:
            logging.error(f"ssl check failed: {str(e)}")
    
    def check_common_files(self):
        """Check for commonly exposed files and directories"""
        print(f"\n{Fore.CYAN}╭─ checking common paths{Style.RESET_ALL}")
        
        for path in self.common_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False, verify=False)
                self.requests_sent += 1
                
                if response.status_code in [200, 301, 302, 403]:
                    print(f"{Fore.YELLOW}│ [!] found: {path} (HTTP {response.status_code}){Style.RESET_ALL}")
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Exposed Sensitive Path',
                            'severity': 'MEDIUM' if path not in ['/.git', '/.env'] else 'HIGH',
                            'url': url,
                            'path': path,
                            'status_code': response.status_code
                        })
                        
            except:
                pass
                
        print(f"{Fore.CYAN}╰{'─'*75}{Style.RESET_ALL}")
            
    def find_sensitive_data(self, content, url):
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?33|0)[1-9](?:\s?\d{2}){4}\b',
            'api_key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']'
        }
        
        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                if data_type == 'email':
                    self.emails.update(matches)
                elif data_type == 'phone':
                    self.phone_numbers.update(matches)
                elif data_type in ['api_key', 'aws_key', 'private_key', 'jwt', 'password']:
                    print(f"{Fore.RED}[!] {data_type.upper()} found at {url}{Style.RESET_ALL}")
                    self.vulnerabilities.append({
                        'type': f'Sensitive Data Exposure - {data_type.upper()}',
                        'severity': 'CRITICAL',
                        'url': url,
                        'data_type': data_type
                    })
                    
    def scan_url_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
            
        print(f"{Fore.BLUE}[*] testing url params: {url}{Style.RESET_ALL}")
        
        for param_name in params.keys():
            # SQLi tests
            for payload in self.sql_payloads[:5]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    response = self.session.get(test_url, params=test_params, timeout=10, verify=False)
                    self.requests_sent += 1
                    
                    for db_type, error_patterns in self.sql_errors.items():
                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection (URL Parameter)',
                                    'severity': 'CRITICAL',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'database': db_type
                                })
                                print(f"{Fore.RED}[!] sqli in param: {param_name}{Style.RESET_ALL}")
                                break
                except:
                    pass
                    
            # XSS tests
            for payload in self.xss_payloads[:5]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    response = self.session.get(test_url, params=test_params, timeout=10, verify=False)
                    self.requests_sent += 1
                    
                    if payload in response.text and not self.is_payload_encoded(payload, response.text):
                        self.vulnerabilities.append({
                            'type': 'XSS (URL Parameter)',
                            'severity': 'HIGH',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload
                        })
                        print(f"{Fore.RED}[!] xss in param: {param_name}{Style.RESET_ALL}")
                        break
                except:
                    pass
                    
    def run_scan(self):
        self.print_banner()
        
        print(f"\n{Fore.CYAN}╔═ PHASE 1: INFRASTRUCTURE & RECON ═══════════════════════════════╗{Style.RESET_ALL}\n")
        
        self.check_security_headers(self.target_url)
        self.check_ssl_certificate(self.target_url)
        self.check_common_files()
        
        print(f"\n{Fore.CYAN}╔═ PHASE 2: WEB CRAWLING & ENUMERATION ════════════════════════════════════╗{Style.RESET_ALL}\n")
        
        self.urls_to_visit.put((self.target_url, 0))
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            while not self.urls_to_visit.empty() or futures:
                while not self.urls_to_visit.empty() and len(futures) < self.max_threads:
                    url, depth = self.urls_to_visit.get()
                    future = executor.submit(self.crawl, url, depth)
                    futures.append(future)
                    
                if futures:
                    done, futures = set(), list(futures)
                    for future in as_completed(futures, timeout=1):
                        futures.remove(future)
                        break
                        
        print(f"\n{Fore.GREEN}[+] crawled {len(self.visited_urls)} pages{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] found {len(self.forms)} forms{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}╔═ PHASE 3: VULNERABILITY ASSESSMENT ══════════════════════════════════════╗{Style.RESET_ALL}\n")
        
        for url in list(self.visited_urls)[:50]:
            if '?' in url:
                self.scan_url_parameters(url)
                
        # test forms
        total_forms = len(self.forms)
        for idx, form in enumerate(self.forms, 1):
            print(f"\n{Fore.YELLOW}[{idx}/{total_forms}] testing {form['action']}{Style.RESET_ALL}")
            
            sql_vulns = self.test_sql_injection(form)
            self.vulnerabilities.extend(sql_vulns)
            
            xss_vulns = self.test_xss(form)
            self.vulnerabilities.extend(xss_vulns)
            
            lfi_vulns = self.test_lfi(form)
            self.vulnerabilities.extend(lfi_vulns)
            
            time.sleep(0.3)
            
        self.generate_report()
        
    def generate_report(self):
        elapsed_time = time.time() - self.start_time
        
        print(f"\n\n{Fore.CYAN}╔═ SCAN RESULTS ═══════════════════════════════════════════════════════════╗{Style.RESET_ALL}\n")
        
        critical_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'HIGH')
        medium_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'MEDIUM')
        
        print(f"{Fore.WHITE}[i] completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"[i] duration: {Fore.CYAN}{int(elapsed_time)}s{Style.RESET_ALL}")
        print(f"[i] requests sent: {Fore.CYAN}{self.requests_sent}{Style.RESET_ALL}")
        print(f"[i] urls crawled: {Fore.CYAN}{len(self.visited_urls)}{Style.RESET_ALL}")
        print(f"[i] forms tested: {Fore.CYAN}{len(self.forms)}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}[!] CRITICAL: {critical_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] HIGH: {high_count}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[!] MEDIUM: {medium_count}{Style.RESET_ALL}")
        print(f"\n[i] total vulnerabilities: {Fore.RED}{len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.emails:
            print(f"\n{Fore.YELLOW}[i] emails discovered: {len(self.emails)}{Style.RESET_ALL}")
        if self.phone_numbers:
            print(f"{Fore.YELLOW}[i] phone numbers found: {len(self.phone_numbers)}{Style.RESET_ALL}")
            
        if self.vulnerabilities:
            print(f"\n{Fore.CYAN}╔═ DETAILED FINDINGS ══════════════════════════════════════════════════════╗{Style.RESET_ALL}\n")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.YELLOW,
                    'MEDIUM': Fore.BLUE
                }.get(vuln.get('severity', 'MEDIUM'), Fore.WHITE)
                
                print(f"{severity_color}[{idx}] {vuln['type']} - {vuln.get('severity', 'MEDIUM')}{Style.RESET_ALL}")
                print(f"    url: {vuln.get('url', 'N/A')}")
                if 'payload' in vuln:
                    print(f"    payload: {vuln['payload']}")
                if 'parameter' in vuln:
                    print(f"    parameter: {vuln['parameter']}")
                if 'database' in vuln:
                    print(f"    database: {vuln['database']}")
                print()
                
        report_data = {
            'scan_info': {
                'scanner': 'ZScanner',
                'author': 'ZH4CK3DE',
                'twitter': '@CITO_FR',
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': int(elapsed_time),
                'requests_sent': self.requests_sent,
                'urls_crawled': len(self.visited_urls),
                'forms_found': len(self.forms)
            },
            'statistics': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'total': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities,
            'sensitive_data': {
                'emails': list(self.emails),
                'phone_numbers': list(self.phone_numbers)
            },
            'urls_scanned': list(self.visited_urls)
        }
        
        if self.json_report:
            self.save_json_report(report_data)
            
        if self.html_report:
            self.save_html_report(report_data)
            
        if not self.json_report and not self.html_report:
            print(f"\n{Fore.YELLOW}[i] no reports generated{Style.RESET_ALL}")
    
    def save_json_report(self, data):
        filename = f"zscanner_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[+] json report saved: {filename}{Style.RESET_ALL}")
    
    def save_html_report(self, data):
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZScanner - {html_escape.escape(data['scan_info']['target'])}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            padding: 40px 20px;
            color: #e4e4e7;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            animation: fadeIn 0.6s ease-in;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .header {{
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%);
            border-radius: 24px;
            padding: 60px 40px;
            text-align: center;
            box-shadow: 0 25px 70px rgba(139, 92, 246, 0.4);
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }}
        
        @keyframes rotate {{
            from {{ transform: rotate(0deg); }}
            to {{ transform: rotate(360deg); }}
        }}
        
        .header * {{ position: relative; z-index: 1; }}
        
        .header h1 {{ 
            font-size: 3.5em; 
            margin-bottom: 15px; 
            font-weight: 900;
            letter-spacing: -2px;
            text-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        
        .header .version {{
            font-size: 1.1em;
            opacity: 0.95;
            margin: 10px 0;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .header .author {{ 
            font-size: 1.2em; 
            margin: 15px 0;
            font-weight: 600;
        }}
        
        .header .target {{
            font-size: 1.2em;
            opacity: 0.95;
            margin-top: 25px;
            padding: 18px 35px;
            background: rgba(255,255,255,0.15);
            border-radius: 12px;
            display: inline-block;
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255,255,255,0.2);
            font-weight: 600;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 40px;
            border-radius: 20px;
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid rgba(255,255,255,0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366f1, #8b5cf6, #d946ef);
        }}
        
        .stat-card:hover {{ 
            transform: translateY(-12px) scale(1.02); 
            box-shadow: 0 25px 50px rgba(0,0,0,0.5);
            border-color: rgba(139, 92, 246, 0.5);
        }}
        
        .stat-label {{
            font-size: 0.95em;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 700;
            margin-bottom: 15px;
        }}
        
        .stat-number {{
            font-size: 4em;
            font-weight: 900;
            margin: 20px 0;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 4px 10px rgba(139, 92, 246, 0.3);
        }}
        
        .stat-number.critical {{ 
            background: linear-gradient(135deg, #ef4444, #dc2626);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stat-number.high {{ 
            background: linear-gradient(135deg, #f59e0b, #d97706);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stat-number.medium {{ 
            background: linear-gradient(135deg, #eab308, #ca8a04);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .content {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border-radius: 24px;
            padding: 50px;
            margin-bottom: 40px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }}
        
        .content h2 {{
            font-size: 2.2em;
            margin-bottom: 40px;
            color: #f1f5f9;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        
        .content h2:before {{
            content: '';
            width: 6px;
            height: 50px;
            background: linear-gradient(180deg, #6366f1, #8b5cf6, #d946ef);
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.5);
        }}
        
        .vulnerability {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border-left: 5px solid;
            padding: 35px;
            margin: 30px 0;
            border-radius: 16px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        
        .vulnerability:hover {{
            transform: translateX(12px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.4);
        }}
        
        .vulnerability.critical {{ 
            border-left-color: #ef4444;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.2);
        }}
        
        .vulnerability.high {{ 
            border-left-color: #f59e0b;
            box-shadow: 0 4px 15px rgba(245, 158, 11, 0.2);
        }}
        
        .vulnerability.medium {{ 
            border-left-color: #eab308;
            box-shadow: 0 4px 15px rgba(234, 179, 8, 0.2);
        }}
        
        .vulnerability h3 {{ 
            margin-bottom: 25px; 
            font-size: 1.5em;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 700;
        }}
        
        .vulnerability .detail {{
            margin: 18px 0;
            padding: 15px 0;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            display: flex;
            gap: 25px;
        }}
        
        .vulnerability .detail:last-child {{ border-bottom: none; }}
        
        .label {{ 
            font-weight: 800;
            min-width: 150px;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        
        .value {{
            flex: 1;
            color: #e2e8f0;
            word-break: break-all;
            font-weight: 500;
        }}
        
        .footer {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border-radius: 24px;
            padding: 50px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }}
        
        .footer p {{
            font-size: 1.2em;
            color: #cbd5e1;
            font-weight: 600;
        }}
        
        .footer .warning {{
            margin-top: 20px;
            color: #f59e0b;
            font-weight: 700;
            font-size: 1.1em;
        }}
        
        .footer .twitter {{
            margin-top: 15px;
            color: #1d9bf0;
            font-weight: 700;
            font-size: 1.1em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 10px 24px;
            border-radius: 25px;
            font-size: 0.85em;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }}
        
        .badge.critical {{ 
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }}
        
        .badge.high {{ 
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
        }}
        
        .badge.medium {{ 
            background: linear-gradient(135deg, #eab308, #ca8a04);
            color: #0a0e27;
        }}
        
        .code-block {{
            background: #0f172a;
            color: #38bdf8;
            padding: 15px 20px;
            border-radius: 10px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            border: 1px solid rgba(56, 189, 248, 0.3);
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.3);
        }}
        
        .info-section {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border-radius: 16px;
            padding: 30px;
            margin-top: 35px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        
        .info-section h3 {{
            color: #f59e0b;
            margin-bottom: 20px;
            font-size: 1.4em;
            font-weight: 700;
        }}
        
        .info-section p {{
            color: #cbd5e1;
            line-height: 1.9;
            font-size: 1.05em;
        }}
        
        .scan-stats {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
            padding: 25px;
            background: rgba(99, 102, 241, 0.1);
            border-radius: 12px;
        }}
        
        .scan-stat-item {{
            text-align: center;
        }}
        
        .scan-stat-item strong {{
            display: block;
            font-size: 0.9em;
            color: #94a3b8;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .scan-stat-item span {{
            font-size: 1.3em;
            color: #6366f1;
            font-weight: 700;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ZScanner Security Report</h1>
            <div class="author">made by ZH4CK3DE</div>
            <div class="target">{html_escape.escape(data['scan_info']['target'])}</div>
            <div class="scan-stats">
                <div class="scan-stat-item">
                    <strong>Scan Duration</strong>
                    <span>{data['scan_info']['duration_seconds']}s</span>
                </div>
                <div class="scan-stat-item">
                    <strong>Requests Sent</strong>
                    <span>{data['scan_info']['requests_sent']}</span>
                </div>
                <div class="scan-stat-item">
                    <strong>Completed</strong>
                    <span>{data['scan_info']['timestamp'][:10]}</span>
                </div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">URLs Crawled</div>
                <div class="stat-number">{data['scan_info']['urls_crawled']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Forms Tested</div>
                <div class="stat-number">{data['scan_info']['forms_found']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-number critical">{data['statistics']['critical']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-number high">{data['statistics']['high']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-number medium">{data['statistics']['medium']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Vulns</div>
                <div class="stat-number">{data['statistics']['total']}</div>
            </div>
        </div>
        
        <div class="content">
            <h2>Vulnerability Details</h2>
            
            {''.join([f'''
            <div class="vulnerability {v.get('severity', 'medium').lower()}">
                <h3>
                    <span>{html_escape.escape(v['type'])}</span>
                    <span class="badge {v.get('severity', 'MEDIUM').lower()}">{v.get('severity', 'MEDIUM')}</span>
                </h3>
                <div class="detail">
                    <span class="label">URL</span>
                    <span class="value">{html_escape.escape(v.get('url', 'N/A'))}</span>
                </div>
                {f'<div class="detail"><span class="label">Method</span><span class="value">{html_escape.escape(v.get("method", "N/A"))}</span></div>' if 'method' in v else ''}
                {f'<div class="detail"><span class="label">Payload</span><span class="value"><div class="code-block">{html_escape.escape(v.get("payload", "N/A"))}</div></span></div>' if 'payload' in v else ''}
                {f'<div class="detail"><span class="label">Parameter</span><span class="value"><div class="code-block">{html_escape.escape(v.get("parameter", "N/A"))}</div></span></div>' if 'parameter' in v else ''}
                {f'<div class="detail"><span class="label">Database</span><span class="value">{html_escape.escape(v.get("database", "N/A"))}</span></div>' if 'database' in v else ''}
                {f'<div class="detail"><span class="label">Path</span><span class="value">{html_escape.escape(v.get("path", "N/A"))}</span></div>' if 'path' in v else ''}
            </div>
            ''' for v in data['vulnerabilities']])}
            
            {f'''
            <div class="info-section">
                <h3>🔍 Information Disclosure</h3>
                {f'<p><strong>Emails found:</strong> {html_escape.escape(", ".join(data["sensitive_data"]["emails"]))}</p>' if data["sensitive_data"]["emails"] else ''}
                {f'<p><strong>Phone numbers found:</strong> {html_escape.escape(", ".join(data["sensitive_data"]["phone_numbers"]))}</p>' if data["sensitive_data"]["phone_numbers"] else ''}
            </div>
            ''' if data['sensitive_data']['emails'] or data['sensitive_data']['phone_numbers'] else ''}
        </div>
        
        <div class="footer">
            <p>ZScanner - made by ZH4CK3DE</p>
            <p class="twitter">Twitter: @CITO_FR</p>
            <p class="warning">[!] authorized testing only</p>
        </div>
    </div>
</body>
</html>
"""
        
        html_filename = f"zscanner_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"{Fore.GREEN}[+] html report saved: {html_filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='ZScanner - Advanced Web Vulnerability Scanner by ZH4CK3DE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python zscanner.py -u https://example.com
  python zscanner.py -u https://example.com -d 3 -t 10
  python zscanner.py --url https://testphp.vulnweb.com

features:
  ✓ SQL Injection Detection
  ✓ XSS (Cross-Site Scripting) Detection
  ✓ LFI (Local File Inclusion) Detection
  ✓ Security Headers Analysis
  ✓ SSL/TLS Certificate Validation
  ✓ Common Paths Enumeration
  ✓ Sensitive Data Detection
  ✓ HTML Reports
  ✓ JSON Reports

[!] WARNING: only scan targets you own or have explicit written permission to test.
    unauthorized scanning may be illegal in your jurisdiction.

made by ZH4CK3DE | Twitter: @CITO_FR
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='target url to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='max crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='thread count (default: 5)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] ERROR: url must start with http:// or https://{Style.RESET_ALL}")
        return
        
    # Legal disclaimer
    print(f"\n{Fore.WHITE}╔═══════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.WHITE}║                              LEGAL NOTICE                                 ║")
    print(f"{Fore.WHITE}╠═══════════════════════════════════════════════════════════════════════════╣")
    print(f"{Fore.RED}║                                                                           ║")
    print(f"{Fore.RED}║  this tool is for AUTHORIZED SECURITY TESTING ONLY.                       ║")
    print(f"{Fore.RED}║  obtain written permission before scanning any target.                    ║")
    print(f"{Fore.RED}║  unauthorized use may violate computer fraud laws.                        ║")
    print(f"{Fore.RED}║                                                                           ║")
    print(f"{Fore.RED}╚═══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    confirmation = input(f"{Fore.CYAN}do you have authorization to scan {args.url}? (yes/no): {Style.RESET_ALL}")
    
    if confirmation.lower() != 'yes':
        print(f"{Fore.RED}[!] scan aborted{Style.RESET_ALL}")
        return
    
    # Report preferences
    print(f"\n{Fore.CYAN}╭─ report options ─────────────────────────────────────────────────────────╮{Style.RESET_ALL}")
    json_choice = input(f"{Fore.CYAN}│ generate json report? (yes/no): {Style.RESET_ALL}").strip().lower()
    html_choice = input(f"{Fore.CYAN}│ generate html report? (yes/no): {Style.RESET_ALL}").strip().lower()
    print(f"{Fore.CYAN}╰──────────────────────────────────────────────────────────────────────────╯{Style.RESET_ALL}")
    
    json_report = json_choice == 'yes'
    html_report = html_choice == 'yes'
        
    try:
        scanner = ZScanner(
            target_url=args.url,
            max_depth=args.depth,
            max_threads=args.threads,
            json_report=json_report,
            html_report=html_report
        )
        scanner.run_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] scan interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] ERROR: {str(e)}{Style.RESET_ALL}")
        logging.error(f"fatal error: {str(e)}", exc_info=True)


if __name__ == '__main__':
    main()
