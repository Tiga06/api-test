from flask import Flask, request, jsonify
import subprocess
import json
import os
import tempfile
import re
import socket
import logging
import threading
import uuid
import time
import hmac
import hashlib
from datetime import datetime
from collections import OrderedDict


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Audit logger for security events
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('audit.log')
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

app = Flask(__name__)

# Security configuration
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size
API_KEY = os.environ.get('API_KEY', None)  # Set via environment variable
REQUIRE_AUTH = os.environ.get('REQUIRE_AUTH', 'false').lower() == 'true'

def require_api_key(f):
    """Decorator to require API key authentication with timing-attack resistance"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH:
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                audit_logger.warning(f"Unauthorized access attempt from {request.remote_addr} to {request.path}")
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
            
            # Timing-attack resistant comparison
            provided_hash = hashlib.sha256(api_key.encode()).hexdigest()
            stored_hash = hashlib.sha256(API_KEY.encode()).hexdigest() if API_KEY else ''
            
            if not hmac.compare_digest(provided_hash, stored_hash):
                audit_logger.warning(f"Unauthorized access attempt from {request.remote_addr} to {request.path}")
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
            
            # Store API key hash for ownership tracking
            request.api_key_hash = provided_hash[:8]
        return f(*args, **kwargs)
    return decorated_function

# Job management
scan_jobs = OrderedDict()
job_owners = {}  # Track job ownership by API key hash
MAX_JOBS_HISTORY = 1000
MAX_CONCURRENT_SCANS = 5
active_scans = {"count": 0, "lock": threading.Lock()}

def get_owner_id():
    """Get current owner ID (API key hash or IP)"""
    if REQUIRE_AUTH and hasattr(request, 'api_key_hash'):
        return request.api_key_hash
    return request.remote_addr

def check_job_access(job_id):
    """Check if current user has access to job"""
    if job_id not in job_owners:
        return False
    return job_owners[job_id] == get_owner_id() or not REQUIRE_AUTH

# Rate limiting per IP
ip_request_counts = {}
ip_lock = threading.Lock()
MAX_REQUESTS_PER_IP_PER_HOUR = 100

def check_rate_limit(ip):
    """Check if IP has exceeded rate limit"""
    with ip_lock:
        current_time = time.time()
        if ip not in ip_request_counts:
            ip_request_counts[ip] = []
        
        # Remove requests older than 1 hour
        ip_request_counts[ip] = [t for t in ip_request_counts[ip] if current_time - t < 3600]
        
        if len(ip_request_counts[ip]) >= MAX_REQUESTS_PER_IP_PER_HOUR:
            return False
        
        ip_request_counts[ip].append(current_time)
        return True

# Tool registry
SUPPORTED_TOOLS = {
    'wafw00f': {'timeout': 120, 'description': 'WAF Detection'},
    'nmap': {'timeout': 600, 'description': 'Network Mapping'},
    'nuclei': {'timeout': None, 'description': 'Vulnerability Scanning'},
    'dirb': {'timeout': None, 'description': 'Directory Enumeration'},
    'whatweb': {'timeout': 60, 'description': 'Web Technology Detection'},
    'nikto': {'timeout': 1800, 'description': 'Web Vulnerability Scanner'},
    'masscan': {'timeout': 300, 'description': 'Port Scanner'},
    'sslscan': {'timeout': 120, 'description': 'SSL/TLS Security Scanner'},
    'httpx': {'timeout': 60, 'description': 'HTTP Probing & Host Verification'},
    'gvm': {'timeout': 3600, 'description': 'OpenVAS Vulnerability Scanner'}
}

def clean_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def validate_target(target):
    """Validate target with enhanced SSRF protection and injection detection"""
    if not target or len(target) > 253:
        return False, "Invalid target format"
    
    # Character validation - allow only safe characters
    safe_pattern = r'^[a-zA-Z0-9.\-:/]+$'
    if not re.match(safe_pattern, target):
        return False, "Invalid characters in target"
    
    # Injection pattern detection
    injection_patterns = [
        r'[;|&`$()\\<>]',  # Shell metacharacters
        r'(?:^|\s)(?:cat|rm|chmod|wget|curl|exec|eval|bash|sh|cmd)\b',  # Commands
        r'(?:\r\n|\n|\r)',  # Newlines
    ]
    for pattern in injection_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return False, "Injection attempt detected"
    
    # Enhanced SSRF protection
    import ipaddress
    
    # Metadata service IPs
    METADATA_IPS = ['169.254.169.254', '168.63.169.254', '100.100.100.200']
    
    # Extract host (remove port if present)
    target_host = target.split(':')[0]
    
    # Check if target is an IP
    try:
        ip = ipaddress.ip_address(target_host)
        
        # Block private IPs
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False, "SSRF Protection: Private/internal IP not allowed"
        
        # Block metadata services
        if str(ip) in METADATA_IPS:
            return False, "SSRF Protection: Metadata service blocked"
    
    except ValueError:
        # Not an IP, check DNS resolution
        try:
            resolved = socket.gethostbyname(target_host)
            resolved_ip = ipaddress.ip_address(resolved)
            
            # Check if resolves to private IP
            if resolved_ip.is_private or resolved_ip.is_loopback:
                return False, "SSRF Protection: Domain resolves to private IP"
            
            # Check if resolves to metadata service
            if resolved in METADATA_IPS:
                return False, "SSRF Protection: Domain resolves to metadata service"
        
        except (socket.gaierror, socket.error):
            pass  # DNS resolution failed, allow it
    
    return True, "Valid target"

def cleanup_old_jobs():
    """Remove old jobs to prevent memory overflow"""
    if len(scan_jobs) > MAX_JOBS_HISTORY:
        for _ in range(100):
            if scan_jobs:
                scan_jobs.popitem(last=False)

def run_scan_async(job_id, tool, scan_function, *args, **kwargs):
    """Execute scan in background thread"""
    with active_scans["lock"]:
        active_scans["count"] += 1
    
    try:
        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        logger.info(f"Starting {tool} scan for job {job_id}")
        
        result = scan_function(*args, **kwargs)
        
        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["result"] = result
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.info(f"Completed {tool} scan for job {job_id}")
        
    except Exception as e:
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = "Scan failed - check server logs for details"
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.error(f"Failed {tool} scan for job {job_id}: {str(e)}")
        logger.exception("Full error details:")
    finally:
        with active_scans["lock"]:
            active_scans["count"] -= 1

# Common API Contract Endpoints

@app.route('/scan', methods=['POST'])
@require_api_key
def create_scan():
    """Common scan endpoint - POST /scan"""
    # Validate content type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    # Rate limiting
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({
            "error": "Rate limit exceeded",
            "message": f"Maximum {MAX_REQUESTS_PER_IP_PER_HOUR} requests per hour allowed"
        }), 429
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON payload required"}), 400
    
    # Validate only expected fields to prevent mass assignment
    allowed_fields = {'tool', 'target', 'params'}
    if not set(data.keys()).issubset(allowed_fields):
        return jsonify({"error": "Invalid fields in request"}), 400
    
    tool = data.get('tool')
    target = data.get('target')
    params = data.get('params', {})
    
    # Validate params is a dictionary
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object"}), 400
    
    if not tool or tool not in SUPPORTED_TOOLS:
        return jsonify({
            "error": "Invalid tool", 
            "supported_tools": list(SUPPORTED_TOOLS.keys())
        }), 400
    
    if not target:
        return jsonify({"error": "Target parameter required"}), 400
    
    # Validate target
    is_valid, message = validate_target(target)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Check concurrent scan limit
    if active_scans["count"] >= MAX_CONCURRENT_SCANS:
        return jsonify({
            "error": "Maximum concurrent scans reached",
            "active_scans": active_scans["count"],
            "max_allowed": MAX_CONCURRENT_SCANS
        }), 429
    
    # Create job
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "job_id": job_id,
        "tool": tool,
        "target": target,
        "params": params,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "result": None
    }
    job_owners[job_id] = get_owner_id()  # Track ownership
    cleanup_old_jobs()
    
    # Start scan based on tool
    scan_function = get_scan_function(tool)
    if not scan_function:
        return jsonify({"error": "Tool not implemented"}), 500
    
    thread = threading.Thread(
        target=run_scan_async, 
        args=(job_id, tool, scan_function, target, params)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "tool": tool,
        "target": target,
        "message": f"{tool} scan started",
        "estimated_time": f"{SUPPORTED_TOOLS[tool]['timeout'] or 'variable'} seconds"
    }), 202

@app.route('/status/<job_id>', methods=['GET'])
@require_api_key
def get_job_status(job_id):
    """Get scan status - GET /status/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id].copy()
    return jsonify(job), 200

@app.route('/results/<job_id>', methods=['GET'])
@require_api_key
def get_job_results(job_id):
    """Get scan results - GET /results/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id]
    if job["status"] != "completed":
        return jsonify({
            "error": "Scan not completed",
            "status": job["status"]
        }), 400
    
    return jsonify({
        "job_id": job_id,
        "tool": job["tool"],
        "target": job["target"],
        "status": job["status"],
        "result": job["result"],
        "completed_at": job["completed_at"]
    }), 200

@app.route('/cancel/<job_id>', methods=['POST'])
@require_api_key
def cancel_job(job_id):
    """Cancel scan - POST /cancel/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id]
    if job["status"] in ["completed", "failed", "cancelled"]:
        return jsonify({"error": f"Cannot cancel {job['status']} job"}), 400
    
    scan_jobs[job_id]["status"] = "cancelled"
    scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
    
    return jsonify({
        "job_id": job_id,
        "status": "cancelled",
        "message": "Job cancelled successfully"
    }), 200

@app.route('/jobs', methods=['GET'])
@require_api_key
def list_jobs():
    """List all jobs"""
    limit = request.args.get('limit', 50, type=int)
    status_filter = request.args.get('status')
    
    jobs_list = []
    for job_id, job in list(scan_jobs.items())[-limit:]:
        if status_filter and job["status"] != status_filter:
            continue
        jobs_list.append({
            "job_id": job_id,
            "tool": job["tool"],
            "target": job["target"],
            "status": job["status"],
            "created_at": job["created_at"]
        })
    
    return jsonify({
        "total_jobs": len(scan_jobs),
        "active_scans": active_scans["count"],
        "jobs": jobs_list
    }), 200

@app.route('/health', methods=['GET'])
@require_api_key
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "active_scans": active_scans["count"],
        "total_jobs": len(scan_jobs),
        "supported_tools": list(SUPPORTED_TOOLS.keys()),
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/metrics', methods=['GET'])
@require_api_key
def metrics():
    """Prometheus-style metrics"""
    metrics_data = f"""# HELP active_scans Current number of active scans
# TYPE active_scans gauge
active_scans {active_scans["count"]}

# HELP total_jobs Total number of jobs in memory
# TYPE total_jobs gauge
total_jobs {len(scan_jobs)}

# HELP jobs_by_status Number of jobs by status
# TYPE jobs_by_status gauge
"""
    
    status_counts = {}
    for job in scan_jobs.values():
        status = job["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    
    for status, count in status_counts.items():
        metrics_data += f'jobs_by_status{{status="{status}"}} {count}\n'
    
    return metrics_data, 200, {'Content-Type': 'text/plain'}

# Scan Functions

def get_scan_function(tool):
    """Get scan function by tool name"""
    functions = {
        'wafw00f': run_wafw00f,
        'nmap': run_nmap,
        'nuclei': run_nuclei,
        'dirb': run_dirb,
        'whatweb': run_whatweb,
        'nikto': run_nikto,
        'masscan': run_masscan,
        'sslscan': run_sslscan,
        'httpx': run_httpx,
        'gvm': run_gvm
    }
    return functions.get(tool)

def run_wafw00f(target, params):
    """WAF detection scan"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

        # Command is already using list format which prevents shell injection
        command = ['wafw00f', target, '-o', output_path]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['wafw00f']['timeout']
        )

        with open(output_path, 'r') as f:
            data = json.load(f)
        os.remove(output_path)

        return {
            "tool": "wafw00f",
            "target": target,
            "command": " ".join(command),
            "data": data
        }
    except Exception as e:
        return {"error": str(e)}

def run_nmap(target, params):
    """Network mapping scan"""
    try:
        scan_type = params.get('type', '1')
        if scan_type == '1':
            command = ['nmap', '-T4', '-F', target]
            timeout = 120
        else:
            command = ['nmap', '-A', '-T3', '-p-', target]
            timeout = 600

        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=timeout
        )

        return {
            "tool": "nmap",
            "target": target,
            "scan_type": "lite" if scan_type == '1' else "deep",
            "command": " ".join(command),
            "result": result.stdout
        }
    except Exception as e:
        return {"error": str(e)}

def run_nuclei(target, params):
    """Vulnerability scanning with optional parameters"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        command = ['nuclei', '-u', target_url, '-j']
        
        # Severity filter: critical, high, medium, low, info, unknown
        severity = params.get('severity')
        if severity:
            valid_severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
            if isinstance(severity, str):
                severity = [s.strip().lower() for s in severity.split(',')]
            elif not isinstance(severity, list):
                severity = [str(severity).lower()]
            
            # Validate severities
            severity = [s for s in severity if s in valid_severities]
            if severity:
                command.extend(['-severity', ','.join(severity)])
        
        # Tags filter (e.g., 'cve', 'owasp', 'xss', 'sqli')
        tags = params.get('tags')
        if tags:
            if isinstance(tags, list):
                tags = ','.join(tags)
            command.extend(['-tags', str(tags)])
        
        # Exclude tags
        exclude_tags = params.get('exclude_tags')
        if exclude_tags:
            if isinstance(exclude_tags, list):
                exclude_tags = ','.join(exclude_tags)
            command.extend(['-exclude-tags', str(exclude_tags)])
        
        # Templates to use (specific template paths or IDs)
        templates = params.get('templates')
        if templates:
            if isinstance(templates, list):
                for template in templates:
                    command.extend(['-t', str(template)])
            else:
                command.extend(['-t', str(templates)])
        
        # Exclude templates
        exclude_templates = params.get('exclude_templates')
        if exclude_templates:
            if isinstance(exclude_templates, list):
                for template in exclude_templates:
                    command.extend(['-exclude', str(template)])
            else:
                command.extend(['-exclude', str(exclude_templates)])
        
        # Rate limit (requests per second)
        rate_limit = params.get('rate_limit')
        if rate_limit:
            command.extend(['-rate-limit', str(rate_limit)])
        
        # Concurrency (parallel templates)
        concurrency = params.get('concurrency')
        if concurrency:
            command.extend(['-c', str(concurrency)])
        
        # Timeout (seconds)
        timeout = params.get('timeout')
        if timeout:
            command.extend(['-timeout', str(timeout)])
        
        # Retries
        retries = params.get('retries')
        if retries:
            command.extend(['-retries', str(retries)])
        
        # Follow redirects
        if params.get('follow_redirects', False):
            command.append('-follow-redirects')
        
        # Include all matched results
        if params.get('include_all', False):
            command.append('-include-all')
        
        # Passive scan only
        if params.get('passive', False):
            command.append('-passive')
        
        # Automatic scan (uses default templates)
        if params.get('automatic_scan', False):
            command.append('-as')
        
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        nuclei_results = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        nuclei_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        # Calculate severity summary
        severity_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0
        }
        
        for result_item in nuclei_results:
            severity_level = result_item.get('info', {}).get('severity', 'unknown').lower()
            if severity_level in severity_summary:
                severity_summary[severity_level] += 1

        return {
            "tool": "nuclei",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": nuclei_results,
            "total_findings": len(nuclei_results),
            "severity_summary": severity_summary
        }
    except Exception as e:
        return {"error": str(e)}

def run_dirb(target, params):
    """Directory enumeration"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}/'
        else:
            target_url = target if target.endswith('/') else f'{target}/'

        command = ['dirb', target_url]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        found_items = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('+ ') and '(CODE:' in line:
                found_items.append(line[2:])
            elif '==> DIRECTORY:' in line:
                dir_path = line.split('==> DIRECTORY: ')[1].strip()
                found_items.append(f"DIRECTORY: {dir_path}")

        return {
            "tool": "dirb",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "found_items": found_items,
            "total_found": len(found_items)
        }
    except Exception as e:
        return {"error": str(e)}

def run_whatweb(target, params):
    """Web technology detection"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            json_output_path = tmp_file.name

        command = ['whatweb', '--color=never', '--log-json=' + json_output_path, target_url]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['whatweb']['timeout']
        )

        whatweb_results = []
        try:
            with open(json_output_path, 'r') as f:
                for line in f:
                    if line.strip():
                        whatweb_results.append(json.loads(line))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

        return {
            "tool": "whatweb",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": whatweb_results,
            "total_results": len(whatweb_results)
        }
    except Exception as e:
        return {"error": str(e)}

def run_nikto(target, params):
    """Web vulnerability scanning"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            json_output_path = tmp_file.name

        command = ['nikto', '-h', target_url, '-Format', 'json', '-output', json_output_path]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['nikto']['timeout']
        )

        nikto_results = {}
        try:
            with open(json_output_path, 'r') as f:
                nikto_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            nikto_results = {"scan_details": "No JSON output generated"}
        finally:
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

        return {
            "tool": "nikto",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": nikto_results
        }
    except Exception as e:
        return {"error": str(e)}

def run_masscan(target, params):
    """Port scanning"""
    try:
        ports = params.get('ports', '0-65535')
        rate = params.get('rate', '1000')
        
        # Resolve hostname to IP
        resolved_ip = target
        try:
            socket.inet_aton(target)
        except socket.error:
            resolved_ip = socket.gethostbyname(target)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

        command = ['masscan', '-p', ports, '--rate', rate, '-oJ', output_path, '--open', resolved_ip]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['masscan']['timeout']
        )

        scan_results = []
        try:
            with open(output_path, 'r') as f:
                content = f.read()
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if line and line not in ['{', '}']:
                        if line.endswith(','):
                            line = line[:-1]
                        try:
                            scan_results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

        open_ports = []
        for item in scan_results:
            if 'ports' in item:
                for port_info in item['ports']:
                    open_ports.append({
                        'ip': item.get('ip', resolved_ip),
                        'port': port_info.get('port'),
                        'protocol': port_info.get('proto', 'tcp'),
                        'status': port_info.get('status', 'open')
                    })

        return {
            "tool": "masscan",
            "target": target,
            "resolved_ip": resolved_ip,
            "ports_scanned": ports,
            "scan_rate": rate,
            "command": " ".join(command),
            "results": open_ports,
            "total_open_ports": len(open_ports)
        }
    except Exception as e:
        return {"error": str(e)}

def run_sslscan(target, params):
    """SSL/TLS security scanning"""
    try:
        import xml.etree.ElementTree as ET
        
        port = params.get('port', '443')
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp_file:
            xml_output_path = tmp_file.name

        command = ['sslscan', '--xml=' + xml_output_path, f'{target}:{port}']
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['sslscan']['timeout']
        )

        # Parse XML and convert to JSON
        ssl_results = {}
        try:
            tree = ET.parse(xml_output_path)
            root = tree.getroot()
            
            # Extract SSL test results
            ssltest = root.find('ssltest')
            if ssltest is not None:
                ssl_results = {
                    'host': ssltest.get('host'),
                    'port': ssltest.get('port'),
                    'protocols': [],
                    'ciphers': [],
                    'vulnerabilities': {},
                    'certificate': {}
                }
                
                # Extract protocols
                for protocol in ssltest.findall('protocol'):
                    ssl_results['protocols'].append({
                        'type': protocol.get('type'),
                        'version': protocol.get('version'),
                        'enabled': protocol.get('enabled') == '1'
                    })
                
                # Extract ciphers
                for cipher in ssltest.findall('cipher'):
                    ssl_results['ciphers'].append({
                        'status': cipher.get('status'),
                        'sslversion': cipher.get('sslversion'),
                        'bits': cipher.get('bits'),
                        'cipher': cipher.get('cipher'),
                        'strength': cipher.get('strength')
                    })
                
                # Extract vulnerabilities
                heartbleed = ssltest.find('heartbleed')
                if heartbleed is not None:
                    ssl_results['vulnerabilities']['heartbleed'] = {
                        'vulnerable': heartbleed.get('vulnerable') == '1',
                        'sslversion': heartbleed.get('sslversion')
                    }
                
                compression = ssltest.find('compression')
                if compression is not None:
                    ssl_results['vulnerabilities']['compression'] = {
                        'supported': compression.get('supported') == '1'
                    }
                
                renegotiation = ssltest.find('renegotiation')
                if renegotiation is not None:
                    ssl_results['vulnerabilities']['renegotiation'] = {
                        'supported': renegotiation.get('supported') == '1',
                        'secure': renegotiation.get('secure') == '1'
                    }
                
                # Extract certificate info
                cert = ssltest.find('certificate')
                if cert is not None:
                    ssl_results['certificate'] = {
                        'subject': cert.get('subject', ''),
                        'issuer': cert.get('issuer', ''),
                        'signature-algorithm': cert.get('signature-algorithm', ''),
                        'key-strength': cert.get('key-strength', ''),
                        'before': cert.get('before', ''),
                        'after': cert.get('after', '')
                    }
        
        except (ET.ParseError, FileNotFoundError):
            ssl_results = {"scan_details": "Failed to parse XML output"}
        finally:
            if os.path.exists(xml_output_path):
                os.remove(xml_output_path)

        return {
            "tool": "sslscan",
            "target": target,
            "port": port,
            "command": " ".join(command),
            "results": ssl_results,
            "total_protocols": len(ssl_results.get('protocols', [])),
            "total_ciphers": len(ssl_results.get('ciphers', []))
        }
    except Exception as e:
        return {"error": str(e)}

def run_httpx(target, params):
    """HTTP probing and host verification"""
    try:
        # Build httpx command with comprehensive probing
        command = [
            'httpx', '-json', '-probe', '-status-code', '-title', 
            '-tech-detect', '-ip', '-cdn', '-method', '-websocket',
            '-cname', '-asn', '-silent'
        ]
        
        # Add optional parameters
        if params.get('screenshot'):
            command.extend(['-screenshot'])
        if params.get('include_response'):
            command.extend(['-include-response'])
        if params.get('follow_redirects'):
            command.extend(['-follow-redirects'])
        
        # Create temporary input file for target
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(target)
            input_path = tmp_file.name
        
        # Add input file to command
        command.extend(['-l', input_path])
        
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['httpx']['timeout']
        )
        
        # Clean up input file
        if os.path.exists(input_path):
            os.remove(input_path)
        
        # Parse JSON output
        httpx_results = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        httpx_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        # Extract summary information
        summary = {
            'total_hosts': len(httpx_results),
            'live_hosts': len([r for r in httpx_results if not r.get('failed', True)]),
            'technologies': [],
            'status_codes': {},
            'cdn_providers': [],
            'web_servers': []
        }
        
        for result_item in httpx_results:
            # Collect technologies
            if 'tech' in result_item:
                summary['technologies'].extend(result_item['tech'])
            
            # Count status codes
            if 'status_code' in result_item:
                status = str(result_item['status_code'])
                summary['status_codes'][status] = summary['status_codes'].get(status, 0) + 1
            
            # Collect CDN providers
            if result_item.get('cdn') and 'cdn_name' in result_item:
                cdn = result_item['cdn_name']
                if cdn not in summary['cdn_providers']:
                    summary['cdn_providers'].append(cdn)
            
            # Collect web servers
            if 'webserver' in result_item:
                server = result_item['webserver']
                if server not in summary['web_servers']:
                    summary['web_servers'].append(server)
        
        # Remove duplicates from technologies
        summary['technologies'] = list(set(summary['technologies']))
        
        return {
            "tool": "httpx",
            "target": target,
            "command": " ".join(command),
            "results": httpx_results,
            "summary": summary
        }
    except Exception as e:
        return {"error": str(e)}

def run_gvm(target, params):
    """OpenVAS vulnerability scanning via GVM - merged from openvas_flask_api.py"""
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
        from gvm.errors import GvmError
        import xml.etree.ElementTree as ET
        
        # Get credentials from environment or use defaults (should be configured externally)
        username = os.environ.get('GVM_USERNAME', 'admin')
        password = os.environ.get('GVM_PASSWORD', 'admin')
        
        # Connection parameters
        use_tls = params.get('use_tls', False)
        host = params.get('host', 'localhost')
        port = params.get('port', 9390)
        socket_path = params.get('socket_path', '/run/gvmd/gvmd.sock')
        
        # Choose connection type
        if use_tls:
            connection = TLSConnection(hostname=host, port=port)
        else:
            # Check for socket existence
            possible_sockets = [
                socket_path,
                '/var/run/gvmd.sock',
                '/tmp/gvmd.sock',
                '/run/gvm/gvmd.sock'
            ]
            
            socket_found = None
            for sock_path in possible_sockets:
                if os.path.exists(sock_path):
                    socket_found = sock_path
                    break
            
            if not socket_found:
                return {
                    "error": "GVM socket not found",
                    "checked_paths": possible_sockets,
                    "solution": "Ensure OpenVAS/GVM is running: sudo systemctl start gvmd"
                }
            
            connection = UnixSocketConnection(path=socket_found)
        
        transform = EtreeTransform()
        
        # Retry connection logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with Gmp(connection=connection, transform=transform) as gmp:
                    # Authenticate
                    gmp.authenticate(username, password)
                    
                    # Test connection with a simple command
                    gmp.get_version()
                    
                    # Connection successful, proceed with scan
                    return _perform_gvm_scan(gmp, target, params)
                    
            except (GvmError, ConnectionError, OSError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"GVM connection failed after {max_retries} attempts: {str(e)}")
                    return {
                        "error": "GVM connection failed - check server logs for details",
                        "type": "connection_error"
                    }
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
                
    except ImportError:
        return {
            "error": "python-gvm library not installed",
            "solution": "Run: pip install python-gvm"
        }
    except Exception as e:
        logger.error(f"OpenVAS scan failed: {str(e)}")
        return {
            "error": "OpenVAS scan failed - check server logs for details"
        }

def _perform_gvm_scan(gmp, target, params):
    """Perform the actual GVM scan after connection is established"""
    try:
        
        # Create target with port range
        target_name = f"API_Target_{target}_{int(time.time())}"
        target_response = gmp.create_target(
            name=target_name,
            hosts=[target],
            port_range="1-65535",
            comment=f"API scan for {target}"
        )
            
        # Extract target_id from XML response
        target_id = target_response.get('id')
        if not target_id:
            # Look for ID in child elements
            for child in target_response:
                if child.get('id'):
                    target_id = child.get('id')
                    break
        
        if not target_id:
            return {
                "error": "Failed to create target - no target_id returned",
                "xml_tag": target_response.tag,
                "xml_attribs": dict(target_response.attrib),
                "child_count": len(target_response)
            }
            
        # Get scan config - prefer lighter scans for API
        configs = gmp.get_scan_configs()
        config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # Full and fast fallback
        
        # Try to find a lighter config first
        for config in configs.xpath('config'):
            config_name = config.find('name')
            if config_name is not None:
                name = config_name.text
                if 'Discovery' in name or 'Host Discovery' in name:
                    config_id = config.get('id')
                    break
                elif 'Full and fast' in name:
                    config_id = config.get('id')
        
        # Get default scanner
        scanners = gmp.get_scanners()
        scanner_id = scanners.xpath('scanner')[0].get('id')
        
        # Create task
        task_name = f"API_Scan_{target}_{int(time.time())}"
        task_response = gmp.create_task(
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Automated scan for {target}"
        )
        
        # Extract task_id from XML response
        task_id = task_response.get('id')
        if not task_id:
            # Look for ID in child elements
            for child in task_response:
                if child.get('id'):
                    task_id = child.get('id')
                    break
        
        if not task_id:
            return {
                "error": "Failed to create task - no task_id returned",
                "target_id": target_id,
                "xml_tag": task_response.tag
            }
        
        # Start scan
        start_response = gmp.start_task(task_id=task_id)
        
        # Extract report_id from XML response
        report_id = start_response.get('id')
        if not report_id:
            # Look for ID in child elements
            for child in start_response:
                if child.get('id'):
                    report_id = child.get('id')
                    break
        if not report_id:
            report_id = 'unknown'
        
        # Wait for completion without timeout
        wait_interval = 10
        last_progress = '0'
        
        while True:
            task_status = gmp.get_task(task_id)
            status_elem = task_status.find('status')
            status = status_elem.text if status_elem is not None else 'Unknown'
            progress = task_status.find('progress')
            progress_text = progress.text if progress is not None else '0'
            
            # Log progress for debugging
            if progress_text != last_progress:
                logger.info(f"GVM scan progress: {progress_text}% (status: {status})")
                last_progress = progress_text
            
            if status in ['Done', 'Stopped', 'Interrupted']:
                break
                
            time.sleep(wait_interval)
        
        # Get results
        if status == 'Done':
            # Get latest report
            reports = gmp.get_reports(task_id=task_id)
            if reports.xpath('report'):
                report_id = reports.xpath('report')[0].get('id')
                report = gmp.get_report(report_id=report_id)
                
                # Parse vulnerabilities
                vulnerabilities = []
                report_elem = report.find('report')
                
                if report_elem is not None:
                    for result in report_elem.xpath('.//result'):
                        vuln = {
                            'name': result.find('name').text if result.find('name') is not None else 'Unknown',
                            'host': result.find('host').text if result.find('host') is not None else target,
                            'port': result.find('port').text if result.find('port') is not None else 'N/A',
                            'severity': result.find('severity').text if result.find('severity') is not None else '0.0',
                            'threat': result.find('threat').text if result.find('threat') is not None else 'Unknown',
                            'description': result.find('description').text if result.find('description') is not None else 'No description available'
                        }
                        vulnerabilities.append(vuln)
                
                # Calculate severity counts
                high_count = len([v for v in vulnerabilities if float(v['severity']) >= 7.0])
                medium_count = len([v for v in vulnerabilities if 4.0 <= float(v['severity']) < 7.0])
                low_count = len([v for v in vulnerabilities if 0.1 <= float(v['severity']) < 4.0])
                
                # Cleanup
                try:
                    gmp.delete_task(task_id=task_id)
                    gmp.delete_target(target_id=target_id)
                except:
                    pass  # Ignore cleanup errors
                
                return {
                    "tool": "gvm",
                    "target": target,
                    "task_name": task_name,
                    "task_id": task_id,
                    "report_id": report_id,
                    "scan_status": status,
                    "vulnerabilities": vulnerabilities,
                    "summary": {
                        "total_vulnerabilities": len(vulnerabilities),
                        "high_severity": high_count,
                        "medium_severity": medium_count,
                        "low_severity": low_count
                    }
                }
            else:
                return {"error": "No report generated"}
        else:
            # Cleanup incomplete scan
            try:
                gmp.delete_task(task_id=task_id)
                gmp.delete_target(target_id=target_id)
            except:
                pass
            return {
                "error": f"Scan completed with status: {status}",
                "status": status
            }
    except GvmError as e:
        return {
            "error": f"GVM Error: {str(e)}",
            "type": "gvm_error"
        }
    except Exception as e:
        return {
            "error": f"OpenVAS scan failed: {str(e)}"
        }

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # CORS - only allow https://company.com
    allowed_origin = os.environ.get('ALLOWED_ORIGIN', 'https://company.com')
    response.headers['Access-Control-Allow-Origin'] = allowed_origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Allow-Credentials'] = 'false'
    
    return response

if __name__ == '__main__':
    # Validate configuration
    if REQUIRE_AUTH and not API_KEY:
        logger.error("CRITICAL: REQUIRE_AUTH=true but API_KEY not set!")
        logger.error("Set API_KEY environment variable or disable authentication")
        exit(1)
    
    # Disable debug mode in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    # Startup info
    logger.info("="*60)
    logger.info("Security Scanner API - Starting...")
    logger.info("="*60)
    logger.info(f"Authentication: {'ENABLED' if REQUIRE_AUTH else 'DISABLED'}")
    logger.info(f"CORS Origin: {os.environ.get('ALLOWED_ORIGIN', 'https://company.com')}")
    logger.info(f"Debug Mode: {debug_mode}")
    logger.info(f"Enhanced SSRF Protection: ENABLED")
    logger.info(f"Injection Detection: ENABLED")
    logger.info(f"Timing-Attack Protection: ENABLED")
    logger.info("="*60)
    
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=debug_mode)
