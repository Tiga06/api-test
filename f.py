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
from datetime import datetime
from collections import OrderedDict


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)



# Job management
scan_jobs = OrderedDict()
MAX_JOBS_HISTORY = 1000
MAX_CONCURRENT_SCANS = 5
active_scans = {"count": 0, "lock": threading.Lock()}

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
    'httpx': {'timeout': 60, 'description': 'HTTP Probing & Host Verification'}
}

def clean_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def validate_target(target):
    """Validate target against scope registry"""
    # Basic validation - extend with actual registry check
    if not target or len(target) > 253:
        return False, "Invalid target format"
    
    # Block private IPs and localhost
    try:
        import ipaddress
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback:
            return False, "Private/localhost targets not allowed"
    except:
        pass  # Not an IP, continue with domain validation
    
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
        scan_jobs[job_id]["error"] = str(e)
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.error(f"Failed {tool} scan for job {job_id}: {str(e)}")
    finally:
        with active_scans["lock"]:
            active_scans["count"] -= 1

# Common API Contract Endpoints

@app.route('/scan', methods=['POST'])
def create_scan():
    """Common scan endpoint - POST /scan"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON payload required"}), 400
    
    tool = data.get('tool')
    target = data.get('target')
    params = data.get('params', {})
    
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
def get_job_status(job_id):
    """Get scan status - GET /status/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = scan_jobs[job_id].copy()
    return jsonify(job), 200

@app.route('/results/<job_id>', methods=['GET'])
def get_job_results(job_id):
    """Get scan results - GET /results/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
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
def cancel_job(job_id):
    """Cancel scan - POST /cancel/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
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
        'httpx': run_httpx
    }
    return functions.get(tool)

def run_wafw00f(target, params):
    """WAF detection scan"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

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
    """Vulnerability scanning"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        command = ['nuclei', '-u', target_url, '-j']
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

        return {
            "tool": "nuclei",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": nuclei_results,
            "total_findings": len(nuclei_results)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
