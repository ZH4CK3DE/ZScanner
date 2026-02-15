# ZScanner

<img width="821" height="500" alt="image" src="https://github.com/user-attachments/assets/a34e1462-984d-4830-bf32-9cd647c6221b" />



Advanced web vulnerability scanner for security professionals and penetration testers.

## Features

- **SQL Injection Detection** - Tests for SQLi vulnerabilities across multiple databases (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Cross-Site Scripting (XSS)** - Detects reflected XSS vulnerabilities
- **Local File Inclusion (LFI)** - Identifies path traversal vulnerabilities
- **Security Headers Analysis** - Audits HTTP security headers configuration
- **SSL/TLS Validation** - Checks certificate validity and expiration
- **Common Path Enumeration** - Scans for exposed sensitive files and directories
- **Sensitive Data Detection** - Identifies leaked credentials, API keys, and tokens
- **Multi-threaded Scanning** - Fast concurrent testing
- **HTML & JSON Reports** - Beautiful, detailed vulnerability reports

## Installation

```bash
git clone https://github.com/ZH4CK3DE/ZScanner.git
cd ZScanner
pip install -r requirements.txt
```

## Requirements

```
requests
beautifulsoup4
colorama
```
## Usage

# Basic scan
```python zscanner.py -u https://example.com/```

# Advanced options
```python zscanner.py -u https://example.com -d 3 -t 10```

## Help
```python zscanner.py -h```

## Options

-u, --url - **Target URL to scan (required)**

-d, --depth - **Maximum crawl depth (default: 2)**
    
-t, --threads - **Number of threads (default: 5)**

## Report Generation

During scan initialization, you'll be prompted to choose report formats:

  - JSON report

  - HTML report
