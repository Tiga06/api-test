# Security Scanner API

Asynchronous Flask API for security scanning tools on Kali Linux with job management and comprehensive tool integration.

## Setup

```bash
pip install -r requirements.txt
python f.py
```

Server runs on `http://127.0.0.1:5000`

## Common API Contract

### Start Scan
```bash
POST /scan
Content-Type: application/json

{
  "tool": "nuclei",
  "target": "example.com",
  "params": {"type": "1"}
}
```

### Check Status
```bash
GET /status/{job_id}
```

### Get Results
```bash
GET /results/{job_id}
```

### Cancel Scan
```bash
POST /cancel/{job_id}
```

## Supported Tools

- **wafw00f** - WAF Detection
- **nmap** - Network Mapping (params: type=1|2)
- **nuclei** - Vulnerability Scanning
- **dirb** - Directory Enumeration
- **whatweb** - Web Technology Detection
- **nikto** - Web Vulnerability Scanner
- **masscan** - Port Scanner (params: ports, rate)
- **sslscan** - SSL/TLS Security Scanner (params: port)
- **httpx** - HTTP Probing & Host Verification (params: screenshot, include_response, follow_redirects)
- **gvm** - OpenVAS Vulnerability Scanner (no timeout - runs until completion)

## Management Endpoints

- `GET /jobs` - List all jobs
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

## Features

- **Asynchronous Processing** - Non-blocking scans
- **Job Management** - Track scan progress
- **Concurrent Limits** - Max 5 simultaneous scans
- **Target Validation** - Scope registry checks
- **Health Monitoring** - Built-in metrics
- **Complete Scans** - GVM scans run until completion without timeout

## Requirements

- Kali Linux with security tools installed
- Python 3.8+ with Flask and python-gvm
- OpenVAS/GVM configured with user 'admeen:admin123'
- All responses are JSON formatted with 4-space indentation
