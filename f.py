from flask import Flask, request, jsonify
import subprocess
import json
import os
import tempfile
import re

app = Flask(__name__)

def clean_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.route('/wafcheck', methods=['GET'])
def wafcheck():
    domain = request.args.get('domain')

    if not domain:
        return jsonify({"error": "Please provide a domain parameter"}), 400

    try:
        # Create a temporary file for JSON output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

        # Run wafw00f and store JSON output in file
        subprocess.run(
            ['wafw00f', domain, '-o', output_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Read JSON from file
        with open(output_path, 'r') as f:
            data = json.load(f)

        # Clean up the temp file
        os.remove(output_path)

        return app.response_class(
            response=json.dumps(data, indent=4),
            status=200,
            mimetype='application/json'
        )

    except json.JSONDecodeError:
        return app.response_class(
            response=json.dumps({"error": "Failed to parse wafw00f output as JSON"}, indent=4),
            status=500,
            mimetype='application/json'
        )
    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=4),
            status=500,
            mimetype='application/json'
        )

# --- NMAP Endpoint ---
@app.route('/netmap', methods=['GET'])
def netmap():
    domain = request.args.get('domain')
    scan_type = request.args.get('type')

    if not domain:
        return app.response_class(
            response=json.dumps({"error": "Please provide a domain parameter"}, indent=4),
            status=400,
            mimetype='application/json'
        )
    if not scan_type or scan_type not in ['1', '2']:
        return app.response_class(
            response=json.dumps({"error": "Please provide scan type: 1 (lite) or 2 (deep)"}, indent=4),
            status=400,
            mimetype='application/json'
        )

    try:
        # Define command based on scan type
        if scan_type == '1':
            command = ['nmap', '-T4', '-F', domain]  # Lite scan
        else:
            command = ['nmap', '-A', '-T3', '-p-', domain]  # Deep scan

        # Execute nmap
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.stderr:
            return app.response_class(
                response=json.dumps({"error": result.stderr}, indent=4),
                status=500,
                mimetype='application/json'
            )

        # Prepare structured JSON response
        output = {
            "domain": domain,
            "scan_type": "lite" if scan_type == '1' else "deep",
            "command_executed": " ".join(command),
            "result": result.stdout
        }

        return app.response_class(
            response=json.dumps(output, indent=4),
            status=200,
            mimetype='application/json'
        )

    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=4),
            status=500,
            mimetype='application/json'
        )

@app.route('/nuclei', methods=['GET'])
def nuclei():
    domain = request.args.get('domain')

    if not domain:
        return app.response_class(
            response=json.dumps({"error": "Please provide a domain parameter"}, indent=4),
            status=400,
            mimetype='application/json'
        )

    try:
        # Add protocol if not present
        if not domain.startswith(('http://', 'https://')):
            target_url = f'http://{domain}'
        else:
            target_url = domain

        # Run nuclei scan with JSONL output
        command = ['nuclei', '-u', target_url, '-j']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse nuclei JSONL output
        nuclei_results = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        nuclei_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        output = {
            "domain": domain,
            "target_url": target_url,
            "command_executed": " ".join(command),
            "results": nuclei_results,
            "total_findings": len(nuclei_results),
            "stderr": result.stderr if result.stderr else None
        }

        return app.response_class(
            response=json.dumps(output, indent=4),
            status=200,
            mimetype='application/json'
        )

    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=4),
            status=500,
            mimetype='application/json'
        )

@app.route('/drb', methods=['GET'])
def drb():
    domain = request.args.get('domain')

    if not domain:
        return app.response_class(
            response=json.dumps({"error": "Please provide a domain parameter"}, indent=4),
            status=400,
            mimetype='application/json'
        )

    try:
        # Add http:// if not present
        if not domain.startswith(('http://', 'https://')):
            target_url = f'http://{domain}/'
        else:
            target_url = domain if domain.endswith('/') else f'{domain}/'

        # Run dirb scan with timeout
        command = ['dirb', target_url]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)

        # Parse dirb output to extract found directories and files
        found_items = []
        lines = result.stdout.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('+ ') and '(CODE:' in line:
                found_items.append(line[2:])  # Remove '+ ' prefix
            elif '==> DIRECTORY:' in line:
                dir_path = line.split('==> DIRECTORY: ')[1].strip()
                found_items.append(f"DIRECTORY: {dir_path}")

        output = {
            "domain": domain,
            "target_url": target_url,
            "command_executed": " ".join(command),
            "found_items": found_items,
            "total_found": len(found_items),
            "scan_completed": "END_TIME:" in result.stdout,
            "raw_output": result.stdout[:2000] + "..." if len(result.stdout) > 2000 else result.stdout
        }

        return app.response_class(
            response=json.dumps(output, indent=4),
            status=200,
            mimetype='application/json'
        )

    except subprocess.TimeoutExpired:
        return app.response_class(
            response=json.dumps({"error": "Dirb scan timed out after 5 minutes"}, indent=4),
            status=500,
            mimetype='application/json'
        )
    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=4),
            status=500,
            mimetype='application/json'
        )

@app.route('/whtweb', methods=['GET'])
def whtweb():
    domain = request.args.get('domain')

    if not domain:
        return app.response_class(
            response=json.dumps({"error": "Please provide a domain parameter"}, indent=4),
            status=400,
            mimetype='application/json'
        )

    try:
        # Add protocol if not present
        if not domain.startswith(('http://', 'https://')):
            target_url = f'http://{domain}'
        else:
            target_url = domain

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            json_output_path = tmp_file.name

        # Run whatweb with JSON output and no color
        command = ['whatweb', '--color=never', '--log-json=' + json_output_path, target_url]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)

        # Read JSON output from file
        whatweb_results = []
        try:
            with open(json_output_path, 'r') as f:
                for line in f:
                    if line.strip():
                        whatweb_results.append(json.loads(line))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            # Clean up temp file
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

        # Clean ANSI codes from stdout and stderr
        clean_stdout = clean_ansi_codes(result.stdout) if result.stdout else None
        clean_stderr = clean_ansi_codes(result.stderr) if result.stderr else None
        
        output = {
            "domain": domain,
            "target_url": target_url,
            "command_executed": " ".join(command),
            "results": whatweb_results,
            "total_results": len(whatweb_results),
            "readable_output": clean_stdout,
            "stderr": clean_stderr
        }

        return app.response_class(
            response=json.dumps(output, indent=4),
            status=200,
            mimetype='application/json'
        )

    except subprocess.TimeoutExpired:
        return app.response_class(
            response=json.dumps({"error": "Whatweb scan timed out"}, indent=4),
            status=500,
            mimetype='application/json'
        )
    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=4),
            status=500,
            mimetype='application/json'
        )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
