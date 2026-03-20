# 🔥Attack Surface Recon Pipeline🔥

A Python-based reconnaissance automation pipeline for authorized external attack surface discovery and asset inventory collection.

## Overview

The Attack Surface Recon Pipeline helps identify externally exposed assets for a target domain by automating reconnaissance workflows such as subdomain enumeration, DNS resolution, HTTP/HTTPS probing, and common port scanning.

Findings are normalized and stored in JSON and SQLite, with optional Markdown reporting for analysis and documentation.

This project was built as a hands-on security engineering portfolio project to demonstrate:

- Python application development
- modular tool design
- asynchronous network workflows
- structured data modeling
- security automation for defensive use cases

## Features

- Single domain input
- Batch domain input from file
- Passive subdomain enumeration
- DNS resolution
- Common port scanning
- HTTP/HTTPS probing
- JSON output
- SQLite storage
- Markdown reporting

## Tech Stack

- Python 3.11+
- Typer
- Rich
- httpx
- dnspython
- SQLAlchemy
- Pydantic
- asyncio

## Use Cases

- External asset inventory
- Attack surface visibility
- Security validation for owned domains
- Reconnaissance automation for defensive workflows
- Security tooling portfolio demonstration

## Ethical Use Notice

This tool is intended strictly for authorized reconnaissance, defensive security validation, and asset inventory collection.

Do not use this tool against systems, domains, or infrastructure that you do not own or do not have explicit permission to assess.

## Project Structure

```text
attack-surface-recon/
├── README.md
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── Dockerfile
├── docs/
├── src/
├── tests/
└── examples/
```

## Installation

git clone https://github.com/yourusername/attack-surface-recon.git

cd attack-surface-recon

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt


## Usage

Scan a single domain:
python -m src.main scan-domain example.com

Scan multiple domains from a file:
python -m src.main scan-file domains.txt


## Example Output

The pipeline collects and normalizes findings such as:
- discovered subdomains
- resolved IP addresses
- open common ports
- detected HTTP/HTTPS services
- generated JSON records
- stored SQLite findings
- Markdown summary reports

output/findings.json
output/recon.db
output/report.md


## Architecture Flow

```text
Target Domain
   ↓
Subdomain Enumeration
   ↓
DNS Resolution
   ↓
Port Scanning
   ↓
HTTP/HTTPS Probing
   ↓
Normalization + Storage
   ↓
JSON / SQLite / Markdown Report
```

## Disclaimer

This project is for educational and defensive security purposes only.
Users are responsible for ensuring all usage is authorized and lawful.
