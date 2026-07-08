"""
Real-world SSRF (Server-Side Request Forgery) test cases for Kunlun-M scanner.
Simulates a Flask application with URL fetching / webhook proxy endpoints.
"""

import re
import requests
from flask import Blueprint, request, jsonify

proxy_bp = Blueprint('proxy', __name__)

# Whitelist of allowed internal services
ALLOWED_INTERNAL_HOSTS = [
    'api.internal.local',
    'metrics.internal.local',
    'health.internal.local',
]


# ---------------------------------------------------------------------------
# VULN 1: SSRF via requests.get with user-controlled URL
# ---------------------------------------------------------------------------
@proxy_bp.route('/api/proxy/fetch', methods=['GET'])
def fetch_url():
    """URL fetcher / proxy endpoint."""
    url = request.args.get('url', '')
    # VULN: User-controlled URL passed directly to requests.get
    # Attacker can supply: url="http://169.254.169.254/latest/meta-data/" (AWS metadata)
    # or url="http://localhost:6379/" (Redis) or url="file:///etc/passwd"
    resp = requests.get(url, timeout=10)
    return jsonify({'status_code': resp.status_code, 'body': resp.text[:2000]})


# ---------------------------------------------------------------------------
# VULN 2: SSRF via requests.post with user-controlled URL in webhook
# ---------------------------------------------------------------------------
@proxy_bp.route('/api/webhooks/dispatch', methods=['POST'])
def dispatch_webhook():
    """Dispatch a webhook to a user-specified endpoint."""
    target_url = request.form.get('callback_url', '')
    payload = request.form.get('payload', '')
    headers = {'Content-Type': 'application/json'}
    # VULN: User-controlled callback URL with no validation
    # Attacker can supply: callback_url="http://169.254.169.254/latest/meta-data/iam/"
    resp = requests.post(target_url, data=payload, headers=headers, timeout=10)
    return jsonify({'status_code': resp.status_code})


# ---------------------------------------------------------------------------
# VULN 3: SSRF via requests.get with partially constructed URL
# ---------------------------------------------------------------------------
@proxy_bp.route('/api/proxy/screenshot', methods=['GET'])
def screenshot_url():
    """Take a screenshot of a webpage (simulated)."""
    domain = request.args.get('domain', '')
    path = request.args.get('path', '/')
    # VULN: User controls domain, enabling internal network scanning
    # Attacker can supply: domain="169.254.169.254", path="/latest/meta-data/"
    url = f'http://{domain}{path}'
    resp = requests.get(url, timeout=15)
    return jsonify({'status_code': resp.status_code, 'body_length': len(resp.text)})


# ---------------------------------------------------------------------------
# SAFE 1: URL whitelist check before making request
# ---------------------------------------------------------------------------
@proxy_bp.route('/api/internal/service', methods=['GET'])
def query_internal_service():
    """Query an internal service by name."""
    service_name = request.args.get('service', '')
    # SAFE: Only allowed internal hostnames are accepted
    if service_name not in ALLOWED_INTERNAL_HOSTS:
        return jsonify({'error': 'Service not allowed'}), 403
    url = f'http://{service_name}:8080/health'
    resp = requests.get(url, timeout=5)
    return jsonify({'status': resp.json()})


# ---------------------------------------------------------------------------
# SAFE 2: Origin/protocol validation with regex
# ---------------------------------------------------------------------------
@proxy_bp.route('/api/proxy/external', methods=['POST'])
def fetch_external():
    """Fetch an external resource with strict origin validation."""
    url = request.form.get('url', '')
    # SAFE: Validate that URL uses HTTPS and points to a public domain
    if not re.match(r'^https://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/', url):
        return jsonify({'error': 'Invalid URL: must be HTTPS with a public domain'}), 400
    parsed = requests.utils.urlparse(url)
    # Block private/internal IP ranges
    hostname = parsed.hostname
    if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|localhost)', hostname):
        return jsonify({'error': 'Private/internal addresses are not allowed'}), 403
    resp = requests.get(url, timeout=10)
    return jsonify({'status_code': resp.status_code})
