# Security Scanner API

Flask API for security scanning tools on Kali Linux.

## Setup

```bash
pip install flask
python f.py
```

Server runs on `http://127.0.0.1:5000`

## Endpoints

### WAF Detection
```
GET /wafcheck?domain=example.com
```

### Network Mapping
```
GET /netmap?domain=example.com&type=1    # Lite scan
GET /netmap?domain=example.com&type=2    # Deep scan
```

### Vulnerability Scanning
```
GET /nuclei?domain=example.com
```

### Directory Enumeration
```
GET /drb?domain=example.com
```

### Web Technology Detection
```
GET /whtweb?domain=example.com
```

## Requirements

- Kali Linux with tools: `wafw00f`, `nmap`, `nuclei`, `dirb`, `whatweb`
- Python 3 with Flask

All responses are JSON formatted with 4-space indentation.