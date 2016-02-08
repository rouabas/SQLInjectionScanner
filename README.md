# SQLInjectionScanner
SQL Injection Vulnerability Scanner for a given URL written in Python

The Simple SQL Injection Vulnerability Scanner helps
    to find SQL injection vulnerabilities within a website. It is basic and intended for educational use
## Usage example:
sqli_scanner.py -u \"http://site.com/test.php?id=x\"
Options:
  * -u <URL>              (starts the scanner)
  * --help                (displays this text)
  * --about                (displays this text)

## Features:
  - Scan a single URL per time
  - Detect SQL injection vulnerabilities within a website with parameters
  - User agent for web requests
  - Easy to use, everything is automated
  - Error handling for http requests
  - Display a short scan report
  - Check if the provided URL is reachable
