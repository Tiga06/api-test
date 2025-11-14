# Security Scanner API

Asynchronous Flask API for security scanning tools on Kali Linux with job management and comprehensive tool integration.

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and set your credentials:

```bash
# Authentication (REQUIRED for production)
REQUIRE_AUTH=true
API_KEY=your-generated-api-key-here

# GVM/OpenVAS Credentials
GVM_USERNAME=admin
GVM_PASSWORD=your-gvm-password

# CORS Configuration
ALLOWED_ORIGIN=https://compani.com

# Debug Mode (disable in production)
FLASK_DEBUG=false
```

### 3. Generate Secure API Key

```bash
# Generate a secure API key
openssl rand -hex 32

# Or use Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Load Environment Variables & Start Server

```bash
# Load .env file
export $(cat .env | xargs)

# Start the server
python f.py
```

Server runs on `http://0.0.0.0:5000`

## Common API Contract

### Start Scan
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "tool": "nuclei",
    "target": "example.com",
    "params": {}
  }'
```

### Check Status
```bash
curl -X GET http://localhost:5000/status/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

### Get Results
```bash
curl -X GET http://localhost:5000/results/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

### Cancel Scan
```bash
curl -X POST http://localhost:5000/cancel/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

## Supported Tools

- **wafw00f** - WAF Detection
- **nmap** - Network Mapping (params: type=1|2)
- **nuclei** - Vulnerability Scanning (params: severity, tags, exclude_tags, templates, exclude_templates, rate_limit, concurrency, timeout, retries, follow_redirects, include_all, passive, automatic_scan)
- **dirb** - Directory Enumeration
- **whatweb** - Web Technology Detection
- **nikto** - Web Vulnerability Scanner
- **masscan** - Port Scanner (params: ports, rate)
- **sslscan** - SSL/TLS Security Scanner (params: port)
- **httpx** - HTTP Probing & Host Verification (params: status_code, title, tech_detect, ip, cdn, method, websocket, cname, asn, content_length, response_time, web_server, follow_redirects, include_response, screenshot, probe, threads, rate_limit, timeout, retries, match_code, filter_code)
- **gvm** - OpenVAS Vulnerability Scanner (no timeout - runs until completion)

## Management Endpoints

- `GET /jobs` - List all jobs
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

## Features

- **Asynchronous Processing** - Non-blocking scans
- **Job Management** - Track scan progress
- **Concurrent Limits** - Max 5 simultaneous scans
- **Enhanced Security** - SSRF protection, injection detection, timing-attack resistant auth
- **Target Validation** - Comprehensive validation with metadata IP blocking
- **Health Monitoring** - Built-in metrics
- **Complete Scans** - GVM scans run until completion without timeout

## Security Features

- **Timing-Attack Resistant Authentication** - Uses `hmac.compare_digest()` for secure API key comparison
- **Enhanced SSRF Protection** - Blocks AWS/Azure/Alibaba metadata IPs and private networks
- **Injection Detection** - Detects shell metacharacters, command injection, and newline attacks
- **API Key-Based Ownership** - Jobs tracked by API key hash (not IP) for better security
- **Comprehensive Security Headers** - Referrer-Policy, Permissions-Policy, CSP, and more
- **Audit Logging** - All security events logged to audit.log
- **Rate Limiting** - 100 requests per hour per IP
- **Input Validation** - Strict validation on all user inputs

## Requirements

- Kali Linux with security tools installed
- Python 3.8+ with Flask and python-gvm
- OpenVAS/GVM configured and running (credentials set via environment variables)
- All responses are JSON formatted with 4-space indentation

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REQUIRE_AUTH` | No | `false` | Enable API key authentication |
| `API_KEY` | Yes (if auth enabled) | None | API key for authentication |
| `GVM_USERNAME` | Yes (for GVM scans) | `admin` | OpenVAS/GVM username |
| `GVM_PASSWORD` | Yes (for GVM scans) | `admin` | OpenVAS/GVM password |
| `ALLOWED_ORIGIN` | No | `https://compani.com` | CORS allowed origin |
| `FLASK_DEBUG` | No | `false` | Enable Flask debug mode |
