import requests
from bs4 import BeautifulSoup
import scapy.all as scapy
from termcolor import colored
import pyfiglet
import whois
import json
import os
from urllib.parse import urljoin

def display_banner():
    banner = pyfiglet.figlet_format("Sn1p3")
    print(colored(banner, "cyan"))

def load_vulnerabilities(paths_file):
    with open(paths_file, 'r') as file:
        data = json.load(file)
    return data

def detect_vulnerabilities(url, paths_file):
    data = load_vulnerabilities(paths_file)

    print(colored("Scanning for WebDav vulnerabilities:", "yellow"))
    for payload in data.get('webdav', []):
        full_url = url + payload
        try:
            response = requests.request('OPTIONS', full_url)
            if 'DAV' in response.headers:
                print(colored(f"WebDav vulnerability found at: {full_url}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

    print(colored("Scanning for XSS vulnerabilities:", "yellow"))
    for payload in data.get('xss', []):
        try:
            response = requests.get(url + payload)
            if payload in response.text:
                print(colored(f"XSS vulnerability found at: {url + payload}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

    print(colored("Scanning for SQL Injection vulnerabilities:", "yellow"))
    for payload in data.get('sql_injection', []):
        try:
            response = requests.get(url + payload)
            if "syntax" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
                print(colored(f"SQL Injection vulnerability found at: {url + payload}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

    print(colored("Scanning for IDOR vulnerabilities:", "yellow"))
    for payload in data.get('idor', []):
        full_url = url + payload
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                print(colored(f"IDOR vulnerability found at: {full_url}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

    print(colored("Scanning for XXE vulnerabilities:", "yellow"))
    for payload in data.get('xxe', []):
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(url, data=payload, headers=headers)
            if 'root' in response.text:
                print(colored(f"XXE vulnerability found at: {url}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url}: {e}", "red"))

    print(colored("Scanning for Index Of vulnerabilities:", "yellow"))
    for payload in data.get('index_of', []):
        full_url = url + payload
        try:
            response = requests.get(full_url)
            if 'Index of /' in response.text:
                print(colored(f"Index Of vulnerability found at: {full_url}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

    print(colored("Scanning for Command Injection vulnerabilities:", "yellow"))
    for payload in data.get('command_injection', []):
        try:
            response = requests.get(url + payload)
            if 'root' in response.text or 'bin' in response.text:
                print(colored(f"Command Injection vulnerability found at: {url + payload}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

    print(colored("Scanning for SSRF vulnerabilities:", "yellow"))
    for payload in data.get('ssrf', []):
        try:
            response = requests.get(url + payload)
            if 'localhost' in response.text or '127.0.0.1' in response.text:
                print(colored(f"SSRF vulnerability found at: {url + payload}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

    print(colored("Scanning for CSRF vulnerabilities:", "yellow"))
    for payload in data.get('csrf', []):
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.post(url, data=payload, headers=headers)
            if response.status_code == 200:
                print(colored(f"CSRF vulnerability found at: {url}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url}: {e}", "red"))

def gather_information(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Gather domains
        print(colored("Domains:", "yellow"))
        domains = soup.find_all('a')
        for domain in domains:
            print(colored(domain.get('href'), "cyan"))

        # Gather emails
        print(colored("Emails:", "yellow"))
        emails = set()
        for mail in soup(text=lambda text: text and "@" in text):
            emails.add(mail)
        for email in emails:
            print(colored(email, "cyan"))

        # Gather images
        print(colored("Images:", "yellow"))
        images = soup.find_all('img')
        for img in images:
            print(colored(img.get('src'), "cyan"))

        # Gather WHOIS information
        print(colored("WHOIS Information:", "yellow"))
        domain_info = whois.whois(url)
        print(colored(domain_info, "cyan"))

    except Exception as e:
        print(colored(f"Error gathering information: {e}", "red"))

def find_real_ip(url):
    try:
        answers = scapy.sr1(scapy.IP(dst=url)/scapy.ICMP(), timeout=2, verbose=0)
        if answers:
            print(colored(f"Real IP of the website: {answers.src}", "green"))
        else:
            print(colored("Could not find the real IP", "red"))
    except Exception as e:
        print(colored(f"Error finding real IP: {e}", "red"))

def exploit_vulnerabilities(url, paths_file):
    data = load_vulnerabilities(paths_file)

    exploit_webdav(url, data.get('webdav', []))
    exploit_xss(url, data.get('xss', []))
    exploit_sql_injection(url, data.get('sql_injection', []))
    exploit_idor(url, data.get('idor', []))
    exploit_xxe(url, data.get('xxe', []))
    exploit_index_of(url, data.get('index_of', []))
    exploit_command_injection(url, data.get('command_injection', []))
    exploit_ssrf(url, data.get('ssrf', []))
    exploit_csrf(url, data.get('csrf', []))

def exploit_webdav(url, payloads):
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.request('OPTIONS', full_url)
            if 'DAV' in response.headers:
                print(colored(f"Exploitable WebDav found at: {full_url}", "green"))
                # Example of exploitation: uploading a file
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

def exploit_xss(url, payloads):
    for payload in payloads:
        try:
            response = requests.get(url + payload)
            if payload in response.text:
                print(colored(f"Exploitable XSS found at: {url + payload}", "green"))
                # Example of exploitation: cookie stealing
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

def exploit_sql_injection(url, payloads):
    for payload in payloads:
        try:
            response = requests.get(url + payload)
            if "syntax" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
                print(colored(f"Exploitable SQL Injection found at: {url + payload}", "green"))
                # Example of exploitation: dumping database
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

def exploit_idor(url, payloads):
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                print(colored(f"Exploitable IDOR found at: {full_url}", "green"))
                # Example of exploitation: accessing unauthorized data
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

def exploit_xxe(url, payloads):
    for payload in payloads:
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(url, data=payload, headers=headers)
            if 'root' in response.text:
                print(colored(f"Exploitable XXE found at: {url}", "green"))
                # Example of exploitation: file read
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url}: {e}", "red"))

def exploit_index_of(url, payloads):
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.get(full_url)
            if 'Index of /' in response.text:
                print(colored(f"Exploitable Index Of found at: {full_url}", "green"))
                # Example of exploitation: accessing sensitive files
        except requests.RequestException as e:
            print(colored(f"Error connecting to {full_url}: {e}", "red"))

def exploit_command_injection(url, payloads):
    for payload in payloads:
        try:
            response = requests.get(url + payload)
            if 'root' in response.text or 'bin' in response.text:
                print(colored(f"Exploitable Command Injection found at: {url + payload}", "green"))
                # Example of exploitation: executing arbitrary commands
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

def exploit_ssrf(url, payloads):
    for payload in payloads:
        try:
            response = requests.get(url + payload)
            if 'localhost' in response.text or '127.0.0.1' in response.text:
                print(colored(f"Exploitable SSRF found at: {url + payload}", "green"))
                # Example of exploitation: internal network scanning
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url + payload}: {e}", "red"))

def exploit_csrf(url, payloads):
    for payload in payloads:
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.post(url, data=payload, headers=headers)
            if response.status_code == 200:
                print(colored(f"Exploitable CSRF found at: {url}", "green"))
                # Example of exploitation: performing actions on behalf of users
        except requests.RequestException as e:
            print(colored(f"Error connecting to {url}: {e}", "red"))

def main():
    display_banner()
    
    print(colored("Choose an option:", "cyan"))
    print("1. Detect Vulnerabilities")
    print("2. Gather Information")
    print("3. Find Real IP")
    print("4. Exploit Vulnerabilities")
    
    choice = input("Enter your choice: ")
    url = input("Enter the URL: ")
    paths_file = 'vulnerabilities.json'  # Path to your JSON file with vulnerabilities
    
    if choice == '1':
        detect_vulnerabilities(url, paths_file)
    elif choice == '2':
        gather_information(url)
    elif choice == '3':
        find_real_ip(url)
    elif choice == '4':
        exploit_vulnerabilities(url, paths_file)
    else:
        print(colored("Invalid choice", "red"))

if __name__ == "__main__":
    main()
