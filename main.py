import requests
import socket
import whois
import dns.resolver
import sys
import time
import nmap
from bs4 import BeautifulSoup
import threading
import concurrent.futures
import re
import ssl
import platform
import subprocess

def print_banner():
    print("""
    ╔══════════════════════════════════════╗
    ║        Domain Reconnaissance         ║
    ║        Passive Information          ║
    ║            Scanner                  ║
    ╚══════════════════════════════════════╝
    """)

def print_menu():
    print("\nAvailable Operations:")
    print("1. Basic Domain Information")
    print("2. DNS Records")
    print("3. SSL Certificate Information")
    print("4. HTTP Headers")
    print("5. Subdomain Enumeration")
    print("6. Email Addresses Finder")
    print("7. Technology Stack Detection")
    print("8. Domain History")
    print("9. Social Media Links")
    print("10. Related Domains")
    print("11. Port Scanner")
    print("12. Service Detection")
    print("13. OS Detection")
    print("14. Security Headers Check")
    print("15. Network Latency Test")

def get_basic_info(domain):
    try:
        print("\n[+] Getting Basic Domain Information...")
        w = whois.whois(domain)
        print(f"Domain Name: {domain}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {w.name_servers}")
    except Exception as e:
        print(f"[-] Error getting basic info: {str(e)}")

def get_dns_records(domain):
    try:
        print("\n[+] Getting DNS Records...")
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                print(f"\n{qtype} Records:")
                for rdata in answers:
                    print(f"  {rdata}")
            except dns.resolver.NoAnswer:
                print(f"  No {qtype} records found")
    except Exception as e:
        print(f"[-] Error getting DNS records: {str(e)}")

def get_ssl_info(domain):
    try:
        print("\n[+] Getting SSL Certificate Information...")
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
            print(f"Valid From: {cert['notBefore']}")
            print(f"Valid Until: {cert['notAfter']}")
    except Exception as e:
        print(f"[-] Error getting SSL info: {str(e)}")

def get_http_headers(domain):
    try:
        print("\n[+] Getting HTTP Headers...")
        response = requests.head(f"https://{domain}", timeout=5)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        print(f"[-] Error getting HTTP headers: {str(e)}")

def enumerate_subdomains(domain):
    try:
        print("\n[+] Enumerating Subdomains from DNS records...")
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SOA']
        found_subdomains = set()

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    if record_type == 'MX':
                        subdomain = str(answer.exchange).rstrip('.')
                        if domain in subdomain:
                            found_subdomains.add((subdomain, str(answer), record_type))
                    elif record_type == 'NS':
                        subdomain = str(answer).rstrip('.')
                        if domain in subdomain:
                            found_subdomains.add((subdomain, str(answer), record_type))
                    else:
                        subdomain = str(answer).rstrip('.')
                        if domain in subdomain and subdomain != domain:
                            found_subdomains.add((subdomain, str(answer), record_type))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                print(f"Error checking {record_type} records: {str(e)}")

        try:
            random_sub = f"random{int(time.time())}.{domain}"
            dns.resolver.resolve(random_sub, 'A')
            print("\n[!] Warning: Wildcard DNS detected. Results may contain false positives.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

        if found_subdomains:
            print("\nFound Subdomains:")
            for subdomain, ip, record_type in sorted(found_subdomains):
                print(f"  {subdomain} ({record_type}): {ip}")
        else:
            print("No subdomains found in DNS records")

    except Exception as e:
        print(f"[-] Error enumerating subdomains: {str(e)}")

def find_emails(domain):
    try:
        print("\n[+] Searching for email addresses...")
        emails = set() 
        
        dorks = [
            f'@{domain} email',
            f'@{domain} contact',
            f'@{domain} mail',
            f'site:{domain} mailto:',
            f'site:{domain} "email"',
            f'site:{domain} "contact"',
            f'"@{domain}" filetype:pdf',
            f'"@{domain}" filetype:doc',
            f'"@{domain}" filetype:txt',
            f'intext:"@{domain}"',
            f'inurl:"contact" site:{domain}',
            f'inurl:"about" site:{domain}'
        ]

        email_pattern = rf'[A-Za-z0-9._%+-]+@{domain}'
        
        for dork in dorks:
            try:
                print(f"Searching: {dork}")
                # Bing arama URL'i
                url = f'https://www.bing.com/search?q={dork}'
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                found_emails = re.findall(email_pattern, response.text)
                emails.update(found_emails)  
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Error in dork search '{dork}': {str(e)}")
                continue
        
        if emails:
            print("\nFound email addresses:")
            for email in sorted(emails):
                print(f"  {email}")
            print(f"\nTotal unique emails found: {len(emails)}")
        else:
            print("No email addresses found")
            
    except Exception as e:
        print(f"[-] Error in email search: {str(e)}")

def detect_tech_stack(domain):
    try:
        print("\n[+] Detecting technology stack...")
        response = requests.get(f"https://{domain}", timeout=10)
        headers = response.headers
        
        if 'Server' in headers:
            print(f"Web Server: {headers['Server']}")
            
        if 'X-Powered-By' in headers:
            print(f"Powered By: {headers['X-Powered-By']}")
            
        page_content = response.text.lower()
        if 'wordpress' in page_content:
            print("CMS: WordPress detected")
        elif 'drupal' in page_content:
            print("CMS: Drupal detected")
        elif 'joomla' in page_content:
            print("CMS: Joomla detected")
            
    except Exception as e:
        print(f"[-] Error detecting tech stack: {str(e)}")

def get_domain_history(domain):
    try:
        print("\n[+] Getting domain history...")
        w = whois.whois(domain)
        
        print("Registration History:")
        if isinstance(w.creation_date, list):
            print(f"Created on: {w.creation_date[0]}")
        else:
            print(f"Created on: {w.creation_date}")
            
        if w.registrar:
            print(f"Current Registrar: {w.registrar}")
            
        if w.updated_date:
            if isinstance(w.updated_date, list):
                print(f"Last Updated: {w.updated_date[0]}")
            else:
                print(f"Last Updated: {w.updated_date}")
                
    except Exception as e:
        print(f"[-] Error getting domain history: {str(e)}")

def find_social_media(domain):
    try:
        print("\n[+] Searching for social media links...")
        response = requests.get(f"https://{domain}", timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        social_platforms = {
            'facebook.com': 'Facebook',
            'twitter.com': 'Twitter',
            'linkedin.com': 'LinkedIn',
            'instagram.com': 'Instagram',
            'youtube.com': 'YouTube'
        }
        
        found_links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            for platform in social_platforms:
                if platform in href:
                    found_links.add(f"{social_platforms[platform]}: {href}")
                    
        if found_links:
            print("Found social media links:")
            for link in found_links:
                print(f"  {link}")
        else:
            print("No social media links found on the main page")
            
    except Exception as e:
        print(f"[-] Error finding social media links: {str(e)}")

def find_related_domains(domain):
    try:
        print("\n[+] Searching for related domains...")
        base_domain = domain.split('.')[-2]  # example.com -> example
        
        # Common TLDs to check
        tlds = ['.com', '.net', '.org', '.info', '.biz', '.co']
        
        print("Checking similar domain names:")
        for tld in tlds:
            try:
                related_domain = f"{base_domain}{tld}"
                ip = socket.gethostbyname(related_domain)
                print(f"  Found: {related_domain} ({ip})")
            except socket.gaierror:
                pass
                
    except Exception as e:
        print(f"[-] Error finding related domains: {str(e)}")

def port_scanner(domain):
    try:
        print("\n[+] Scanning common ports...")
        nm = nmap.PortScanner()
        result = nm.scan(domain, '20-25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080,8443')
        
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"Port {port}/{proto}: {state} ({service})")
    except Exception as e:
        print(f"[-] Error scanning ports: {str(e)}")

def detect_services(domain):
    try:
        print("\n[+] Detecting running services...")
        nm = nmap.PortScanner()
        # Service detection scan
        nm.scan(domain, arguments='-sV --version-intensity 5')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if 'product' in nm[host][proto][port]:
                        product = nm[host][proto][port]['product']
                        version = nm[host][proto][port]['version']
                        print(f"Port {port}: {product} {version}")
    except Exception as e:
        print(f"[-] Error detecting services: {str(e)}")

def detect_os(domain):
    try:
        print("\n[+] Attempting OS detection...")
        nm = nmap.PortScanner()
        nm.scan(domain, arguments='-O')
        
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    print(f"OS Match: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
    except Exception as e:
        print(f"[-] Error detecting OS: {str(e)}")

def check_security_headers(domain):
    try:
        print("\n[+] Checking security headers...")
        response = requests.head(f"https://{domain}", timeout=5)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'X-Frame-Options': 'Clickjacking protection not enabled',
            'X-Content-Type-Options': 'MIME-type sniffing protection not enabled',
            'Content-Security-Policy': 'CSP not enabled',
            'X-XSS-Protection': 'XSS protection not enabled'
        }
        
        for header, message in security_headers.items():
            if header in headers:
                print(f"{header}: {headers[header]}")
            else:
                print(f"[-] {message}")
    except Exception as e:
        print(f"[-] Error checking security headers: {str(e)}")

def test_network_latency(domain):
    try:
        print("\n[+] Testing network latency...")
        
        # Platform'a göre ping komutu
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', domain]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Ping sonuçlarını parse et
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if 'time=' in line.lower() or 'time<' in line.lower():
                    print(line.strip())
        else:
            print("[-] Host is not responding to ping")
            
    except Exception as e:
        print(f"[-] Error testing network latency: {str(e)}")

def main():
    print_banner()
    
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-16): ")
        
        if choice == '16':
            print("\nExiting...")
            sys.exit(0)
            
        if choice not in [str(i) for i in range(1, 16)]:
            print("\nInvalid choice! Please try again.")
            continue
            
        domain = input("\nEnter the domain name (e.g., example.com): ")
        
        if choice == '1':
            get_basic_info(domain)
        elif choice == '2':
            get_dns_records(domain)
        elif choice == '3':
            get_ssl_info(domain)
        elif choice == '4':
            get_http_headers(domain)
        elif choice == '5':
            enumerate_subdomains(domain)
        elif choice == '6':
            find_emails(domain)
        elif choice == '7':
            detect_tech_stack(domain)
        elif choice == '8':
            get_domain_history(domain)
        elif choice == '9':
            find_social_media(domain)
        elif choice == '10':
            find_related_domains(domain)
        elif choice == '11':
            port_scanner(domain)
        elif choice == '12':
            detect_services(domain)
        elif choice == '13':
            detect_os(domain)
        elif choice == '14':
            check_security_headers(domain)
        elif choice == '15':
            test_network_latency(domain)
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
