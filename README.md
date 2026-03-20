# Attack Surface Recon Pipeline

A Python-based reconnaissance automation pipeline for authorized external attack surface discovery.

## Overview

The Attack Surface Recon Pipeline enumerates subdomains, resolves DNS, probes HTTP/HTTPS services, scans common ports, and stores normalized findings in JSON and SQLite.

This project is designed as a professional security tooling portfolio project to demonstrate:

- Python engineering
- modular architecture
- asynchronous network workflows
- structured data modeling
- security automation pipelines

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

## Ethical Use Notice

This tool is intended for authorized reconnaissance, defensive security validation, and asset inventory collection.

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
