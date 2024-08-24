import requests
import re

# Define a list of common vulnerabilities to scan for
vulnerabilities = [
    {"name": "SQL Injection", "pattern": r"sql syntax|mysql error|database error"},
    {"name": "Cross-Site Scripting (XSS)", "pattern": r"<script>|</script>|javascript:"},
    {"name": "Cross-Site Request Forgery (CSRF)", "pattern": r"csrf token|csrf protection"},
    {"name": "Remote File Inclusion (RFI)", "pattern": r"file inclusion|remote file inclusion"},
    {"name": "Local File Inclusion (LFI)", "pattern": r"file inclusion|local file inclusion"}
]

def scan_vulnerabilities(domain):
    # Send a GET request to the domain
    response = requests.get(domain)

    # Check for vulnerabilities in the response headers
    for vulnerability in vulnerabilities:
        pattern = vulnerability["pattern"]
        if re.search(pattern, response.headers["Server"]):
            print(f"Possible {vulnerability['name']} vulnerability detected in Server header")

    # Check for vulnerabilities in the response body
    for vulnerability in vulnerabilities:
        pattern = vulnerability["pattern"]
        if re.search(pattern, response.text):
            print(f"Possible {vulnerability['name']} vulnerability detected in response body")

# Define the domain to scan
domain = "https//example.com"

# Scan for vulnerabilities
scan_vulnerabilities(domain)
