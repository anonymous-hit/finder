import requests
import nmap
import ssl
import socket
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import time

# Initialize colorama and rich
init(autoreset=True)
console = Console()

# Styled headers
def print_header():
    console.print(f"\n[bold blue]Website Vulnerability Finder[/bold blue]", style="bold white on black")
    console.print(f"[white]Find vulnerabilities and secure your website easily.[/white]\n")

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", "' UNION SELECT NULL, username, password FROM users --"]
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" in response.text or "mysql" in response.text:
            return True
    return False

# Function to check for XSS vulnerability
def check_xss(url):
    payloads = ["<script>alert(1)</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            return True
    return False

# Function to check for open ports
def check_open_ports(url):
    nm = nmap.PortScanner()
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    nm.scan(domain, '1-1024')
    open_ports = []
    for port in nm[domain]['tcp']:
        if nm[domain]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

# Function to check for SSL/TLS issues
def check_ssl_tls(url):
    try:
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
        connection.connect((url, 443))
        ssl_info = connection.getpeercert()
        return ssl_info
    except Exception as e:
        return str(e)

# Function to check for outdated libraries
def check_outdated_libraries(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    outdated_libraries = []
    for script in soup.find_all('script'):
        if 'jquery' in script.get('src', ''):
            outdated_libraries.append('jQuery')
    return outdated_libraries

# Perform a full scan
def perform_scan(url):
    vulnerabilities = []
    console.print(f"[cyan]Scanning {url}...[/cyan]")

    # SQL Injection Check
    if check_sql_injection(url):
        vulnerabilities.append({"name": "SQL Injection", "severity": "High", "description": "Potential SQL injection vulnerability found in URL parameters."})

    # XSS Check
    if check_xss(url):
        vulnerabilities.append({"name": "Cross-Site Scripting (XSS)", "severity": "Medium", "description": "Possible XSS vulnerability in URL parameters."})

    # Open Ports Check
    open_ports = check_open_ports(url)
    if open_ports:
        vulnerabilities.append({"name": "Open Ports", "severity": "Low", "description": f"Open ports detected: {', '.join(map(str, open_ports))}."})

    # SSL/TLS Check
    ssl_info = check_ssl_tls(url)
    if isinstance(ssl_info, str):
        vulnerabilities.append({"name": "SSL/TLS Vulnerability", "severity": "Medium", "description": ssl_info})
    else:
        vulnerabilities.append({"name": "SSL/TLS Configuration", "severity": "Low", "description": "SSL/TLS configuration seems secure."})

    # Outdated Libraries Check
    outdated_libraries = check_outdated_libraries(url)
    if outdated_libraries:
        vulnerabilities.append({"name": "Outdated Libraries", "severity": "Medium", "description": f"Detected outdated libraries: {', '.join(outdated_libraries)}."})

    return vulnerabilities

# Display vulnerabilities
def display_vulnerabilities(vulnerabilities):
    console.print("\n[bold white on blue] Vulnerability Report [/bold white on blue]\n")
    for vuln in vulnerabilities:
        color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}[vuln["severity"]]
        severity = f"{color}{vuln['severity']}{Style.RESET_ALL}"
        console.print(f"[bold]{vuln['name']}[/bold] - [severity {vuln['severity']}]")
        print(f"  Severity: {severity}")
        print(f"  Description: {vuln['description']}\n")

# Main function
def main():
    print_header()
    url = input(Fore.BLUE + "Enter the website URL to scan: " + Style.RESET_ALL)
    console.print(f"\n[cyan]Scanning {url}...[/cyan]")
    vulnerabilities = perform_scan(url)
    display_vulnerabilities(vulnerabilities)
    console.print("[green]Scan complete![/green]")

if __name__ == "__main__":
    main()