# Security Scanner API - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Authentication](#authentication)
4. [Common API Workflow](#common-api-workflow)
5. [Core Endpoints](#core-endpoints)
6. [Security Tools](#security-tools)
7. [Management Endpoints](#management-endpoints)
8. [Error Handling](#error-handling)
9. [Examples](#examples)

---

## Overview

The Security Scanner API is an asynchronous Flask-based REST API that provides access to popular security scanning tools on Kali Linux. It features job management and comprehensive JSON responses.

**Base URL:** `http://127.0.0.1:5000`

**Key Features:**
- Asynchronous processing (non-blocking scans)
- Job tracking with unique IDs
- Concurrent scan limits (max 5 simultaneous)
- Clean JSON responses with 4-space indentation
- Health monitoring and metrics

---

## Getting Started

### Installation
```bash
# setup
pip install -r requirements.txt

# Start the server
python f.py
```

### Basic Usage
```bash
# Start a scan
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"tool": "nuclei", "target": "example.com"}'

# Check status
curl http://127.0.0.1:5000/status/{job_id}

# Get results
curl http://127.0.0.1:5000/results/{job_id}
```

---

## Authentication

### Concurrent Scans
- **Maximum:** 5 simultaneous scans
- **Error Response:** Returns 429 when limit exceeded

### Error Responses
```json
{
    "error": "Maximum concurrent scans reached",
    "active_scans": 5,
    "max_allowed": 5
}
```

---

## Common API Workflow

### 1. Start a Scan
**POST** `/scan`

**Request Body:**
```json
{
    "tool": "tool_name",
    "target": "domain.com",
    "params": {
        "optional": "parameters"
    }
}
```

**Response (202 Accepted):**
```json
{
    "job_id": "uuid-string",
    "status": "queued",
    "tool": "tool_name",
    "target": "domain.com",
    "message": "Scan started",
    "estimated_time": "120 seconds"
}
```

### 2. Monitor Progress
**GET** `/status/{job_id}`

**Response:**
```json
{
    "job_id": "uuid-string",
    "tool": "tool_name",
    "target": "domain.com",
    "status": "running",
    "created_at": "2024-01-01T12:00:00Z",
    "started_at": "2024-01-01T12:00:05Z"
}
```

**Status Values:**
- `queued` - Waiting to start
- `running` - Currently executing
- `completed` - Finished successfully
- `failed` - Error occurred
- `cancelled` - Manually cancelled

### 3. Get Results
**GET** `/results/{job_id}`

**Response (200 OK):**
```json
{
    "job_id": "uuid-string",
    "tool": "tool_name",
    "target": "domain.com",
    "status": "completed",
    "result": {
        "tool-specific": "data"
    },
    "completed_at": "2024-01-01T12:05:00Z"
}
```

---

## Core Endpoints

### POST /scan
Start a new security scan.

**Parameters:**
- `tool` (required): Tool name from supported list
- `target` (required): Domain, IP, or URL to scan
- `params` (optional): Tool-specific parameters

**Example:**
```bash
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "params": {"type": "1"}
  }'
```

### GET /status/{job_id}
Check scan progress and status.

**Response Fields:**
- `job_id`: Unique identifier
- `tool`: Scanner used
- `target`: Target being scanned
- `status`: Current status
- `created_at`: Job creation time
- `started_at`: Scan start time (if running/completed)
- `completed_at`: Completion time (if finished)
- `error`: Error message (if failed)

### GET /results/{job_id}
Retrieve completed scan results.

**Requirements:**
- Job must have `status: "completed"`
- Returns 400 error if scan not completed

### POST /cancel/{job_id}
Cancel a running or queued scan.

**Response:**
```json
{
    "job_id": "uuid-string",
    "status": "cancelled",
    "message": "Job cancelled successfully"
}
```

---

## Security Tools

### 1. WAF Detection (wafw00f)
Detects Web Application Firewalls.

**Usage:**
```json
{
    "tool": "wafw00f",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "wafw00f",
    "target": "example.com",
    "command": "wafw00f example.com -o /tmp/output.json",
    "data": {
        "detected": true,
        "firewall": "Cloudflare",
        "manufacturer": "Cloudflare Inc."
    }
}
```

### 2. Network Mapping (nmap)
Port scanning and service detection.

**Parameters:**
- `type`: "1" (lite scan) or "2" (deep scan)

**Usage:**
```json
{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "params": {"type": "1"}
}
```

**Output:**
```json
{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "scan_type": "lite",
    "command": "nmap -T4 -F scanme.nmap.org",
    "result": "Nmap scan report for scanme.nmap.org..."
}
```

### 3. Vulnerability Scanning (nuclei)
Template-based vulnerability detection.

**Usage:**
```json
{
    "tool": "nuclei",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "nuclei",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "nuclei -u http://example.com -j",
    "results": [
        {
            "template-id": "tech-detect",
            "info": {"name": "Technology Detection"},
            "matched-at": "http://example.com",
            "extracted-results": ["nginx/1.18.0"]
        }
    ],
    "total_findings": 1
}
```

### 4. Directory Enumeration (dirb)
Discovers hidden directories and files.

**Usage:**
```json
{
    "tool": "dirb",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "dirb",
    "target": "example.com",
    "target_url": "http://example.com/",
    "command": "dirb http://example.com/",
    "found_items": [
        "http://example.com/admin/ (CODE:403|SIZE:1234)",
        "DIRECTORY: http://example.com/images/"
    ],
    "total_found": 2
}
```

### 5. Web Technology Detection (whatweb)
Identifies web technologies and frameworks.

**Usage:**
```json
{
    "tool": "whatweb",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "whatweb",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "whatweb --color=never --log-json=/tmp/output.json http://example.com",
    "results": [
        {
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {
                "HTTPServer": ["nginx/1.18.0"],
                "Title": ["Example Domain"]
            }
        }
    ],
    "total_results": 1
}
```

### 6. Web Vulnerability Scanner (nikto)
Comprehensive web server vulnerability assessment.

**Usage:**
```json
{
    "tool": "nikto",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "nikto",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "nikto -h http://example.com -Format json -output /tmp/output.json",
    "results": {
        "host": "example.com",
        "port": "80",
        "vulnerabilities": [
            {
                "id": "000001",
                "method": "GET",
                "uri": "/",
                "message": "Server may leak inodes via ETags"
            }
        ]
    }
}
```

### 7. Port Scanner (masscan)
High-speed port scanning.

**Parameters:**
- `ports`: Port range (default: "0-65535")
- `rate`: Scan rate (default: "1000")

**Usage:**
```json
{
    "tool": "masscan",
    "target": "scanme.nmap.org",
    "params": {
        "ports": "80,443,8080",
        "rate": "1000"
    }
}
```

**Output:**
```json
{
    "tool": "masscan",
    "target": "scanme.nmap.org",
    "resolved_ip": "45.33.32.156",
    "ports_scanned": "80,443,8080",
    "scan_rate": "1000",
    "command": "masscan -p 80,443,8080 --rate 1000 -oJ /tmp/output.json --open 45.33.32.156",
    "results": [
        {
            "ip": "45.33.32.156",
            "port": 80,
            "protocol": "tcp",
            "status": "open"
        }
    ],
    "total_open_ports": 1
}
```

### 8. SSL/TLS Security Scanner (sslscan)
SSL/TLS configuration analysis.

**Parameters:**
- `port`: Target port (default: "443")

**Usage:**
```json
{
    "tool": "sslscan",
    "target": "example.com",
    "params": {"port": "443"}
}
```

**Output:**
```json
{
    "tool": "sslscan",
    "target": "example.com",
    "port": "443",
    "command": "sslscan --xml=/tmp/output.xml example.com:443",
    "results": {
        "host": "example.com",
        "port": "443",
        "protocols": [
            {"type": "tls", "version": "1.2", "enabled": true},
            {"type": "tls", "version": "1.3", "enabled": true}
        ],
        "ciphers": [
            {
                "status": "preferred",
                "sslversion": "TLSv1.3",
                "bits": "128",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "strength": "strong"
            }
        ],
        "vulnerabilities": {
            "heartbleed": {"vulnerable": false},
            "compression": {"supported": false}
        },
        "certificate": {
            "subject": "CN=example.com",
            "issuer": "CN=DigiCert"
        }
    },
    "total_protocols": 2,
    "total_ciphers": 15
}
```

### 9. HTTP Probing & Host Verification (httpx)
Comprehensive HTTP/HTTPS probing with technology detection.

**Parameters:**
- `screenshot`: Take screenshots (boolean)
- `include_response`: Include full HTTP response (boolean)
- `follow_redirects`: Follow redirect chains (boolean)

**Usage:**
```json
{
    "tool": "httpx",
    "target": "example.com",
    "params": {
        "screenshot": false,
        "follow_redirects": true
    }
}
```

**Output:**
```json
{
    "tool": "httpx",
    "target": "example.com",
    "command": "httpx -json -probe -status-code -title -tech-detect -ip -cdn -method -websocket -cname -asn -silent -follow-redirects -l /tmp/input.txt",
    "results": [
        {
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["nginx", "HTML"],
            "cdn": false,
            "host": "93.184.216.34",
            "webserver": "nginx/1.18.0",
            "method": "GET",
            "time": "245ms",
            "content_length": 1256,
            "words": 298,
            "lines": 47
        }
    ],
    "summary": {
        "total_hosts": 1,
        "live_hosts": 1,
        "technologies": ["nginx", "HTML"],
        "status_codes": {"200": 1},
        "cdn_providers": [],
        "web_servers": ["nginx/1.18.0"]
    }
}
```

---

## Management Endpoints

### GET /jobs
List all scan jobs with optional filtering.

**Query Parameters:**
- `limit`: Number of jobs to return (default: 50)
- `status`: Filter by status (queued, running, completed, failed, cancelled)

**Example:**
```bash
curl "http://127.0.0.1:5000/jobs?limit=10&status=completed"
```

**Response:**
```json
{
    "total_jobs": 150,
    "active_scans": 2,
    "jobs": [
        {
            "job_id": "uuid-1",
            "tool": "nuclei",
            "target": "example.com",
            "status": "completed",
            "created_at": "2024-01-01T12:00:00Z"
        }
    ]
}
```

### GET /health
Health check endpoint for monitoring.

**Response:**
```json
{
    "status": "healthy",
    "active_scans": 2,
    "total_jobs": 150,
    "supported_tools": [
        "wafw00f", "nmap", "nuclei", "dirb", 
        "whatweb", "nikto", "masscan", "sslscan", "httpx"
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### GET /metrics
Prometheus-style metrics for monitoring systems.

**Response (text/plain):**
```
# HELP active_scans Current number of active scans
# TYPE active_scans gauge
active_scans 2

# HELP total_jobs Total number of jobs in memory
# TYPE total_jobs gauge
total_jobs 150

# HELP jobs_by_status Number of jobs by status
# TYPE jobs_by_status gauge
jobs_by_status{status="completed"} 120
jobs_by_status{status="running"} 2
jobs_by_status{status="failed"} 5
```

---

## Error Handling

### Common HTTP Status Codes
- **200 OK** - Request successful
- **202 Accepted** - Scan started (async)
- **400 Bad Request** - Invalid parameters
- **404 Not Found** - Job not found
- **429 Too Many Requests** - Rate limit exceeded
- **500 Internal Server Error** - Server error

### Error Response Format
```json
{
    "error": "Error description",
    "details": "Additional context (optional)"
}
```

### Common Errors

**Invalid Tool:**
```json
{
    "error": "Invalid tool",
    "supported_tools": ["wafw00f", "nmap", "nuclei", "dirb", "whatweb", "nikto", "masscan", "sslscan", "httpx"]
}
```

**Rate Limit Exceeded:**
```json
{
    "error": "Maximum concurrent scans reached",
    "active_scans": 5,
    "max_allowed": 5
}
```

**Job Not Found:**
```json
{
    "error": "Job not found"
}
```

**Scan Not Completed:**
```json
{
    "error": "Scan not completed",
    "status": "running"
}
```

---

## Examples

### Complete Workflow Example

```bash
# 1. Start a comprehensive scan
RESPONSE=$(curl -s -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "httpx",
    "target": "example.com",
    "params": {"follow_redirects": true}
  }')

# Extract job ID
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Started scan with job ID: $JOB_ID"

# 2. Monitor progress
while true; do
    STATUS=$(curl -s http://127.0.0.1:5000/status/$JOB_ID | jq -r '.status')
    echo "Current status: $STATUS"
    
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        break
    fi
    
    sleep 5
done

# 3. Get results
if [ "$STATUS" = "completed" ]; then
    curl -s http://127.0.0.1:5000/results/$JOB_ID | jq '.'
else
    echo "Scan failed"
fi
```

### Batch Scanning Multiple Targets

```bash
#!/bin/bash
TARGETS=("example.com" "google.com" "github.com")
JOB_IDS=()

# Start all scans
for target in "${TARGETS[@]}"; do
    response=$(curl -s -X POST http://127.0.0.1:5000/scan \
      -H "Content-Type: application/json" \
      -d "{\"tool\": \"httpx\", \"target\": \"$target\"}")
    
    job_id=$(echo $response | jq -r '.job_id')
    JOB_IDS+=($job_id)
    echo "Started scan for $target: $job_id"
done

# Wait for all to complete
for job_id in "${JOB_IDS[@]}"; do
    while true; do
        status=$(curl -s http://127.0.0.1:5000/status/$job_id | jq -r '.status')
        if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
            break
        fi
        sleep 2
    done
    echo "Job $job_id completed with status: $status"
done
```

### Python Client Example

```python
import requests
import time
import json

class SecurityScannerClient:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
    
    def start_scan(self, tool, target, params=None):
        """Start a new scan"""
        payload = {
            "tool": tool,
            "target": target,
            "params": params or {}
        }
        
        response = requests.post(f"{self.base_url}/scan", json=payload)
        return response.json()
    
    def get_status(self, job_id):
        """Get scan status"""
        response = requests.get(f"{self.base_url}/status/{job_id}")
        return response.json()
    
    def get_results(self, job_id):
        """Get scan results"""
        response = requests.get(f"{self.base_url}/results/{job_id}")
        return response.json()
    
    def wait_for_completion(self, job_id, timeout=300):
        """Wait for scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_data = self.get_status(job_id)
            status = status_data.get('status')
            
            if status in ['completed', 'failed', 'cancelled']:
                return status_data
            
            time.sleep(5)
        
        raise TimeoutError(f"Scan {job_id} did not complete within {timeout} seconds")

# Usage example
client = SecurityScannerClient()

# Start a nuclei scan
scan_response = client.start_scan("nuclei", "example.com")
job_id = scan_response['job_id']

print(f"Started scan: {job_id}")

# Wait for completion
final_status = client.wait_for_completion(job_id)
print(f"Scan completed with status: {final_status['status']}")

# Get results if successful
if final_status['status'] == 'completed':
    results = client.get_results(job_id)
    print(json.dumps(results, indent=2))
```

---

## Best Practices

### 1. Job Management
- Store job IDs for later reference
- Implement proper error handling for failed scans
- Use the `/jobs` endpoint to track scan history

### 2. Target Validation
- Ensure you have permission to scan targets
- Use proper domain names or IP addresses
- Be aware of scope restrictions

### 3. Resource Management
- Don't start too many concurrent scans (max 5)
- Cancel unnecessary scans to free resources
- Monitor system health via `/health` endpoint

### 4. Security Considerations
- Run the API in a controlled environment
- Implement proper network security
- Log and monitor API usage
- Validate all inputs before scanning

---

This documentation provides comprehensive coverage of all API endpoints, tools, parameters, and usage examples. Users can reference specific sections based on their needs and experience level.