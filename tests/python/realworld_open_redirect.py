"""
Real-world open redirect test cases for Kunlun-M scanner.
Simulates a Flask application with login/redirect flows.
"""

from urllib.parse import urlparse, urljoin
from flask import Blueprint, request, redirect, jsonify, url_for

auth_bp = Blueprint('auth', __name__)

# Whitelist of allowed redirect destinations
ALLOWED_REDIRECT_DOMAINS = [
    'app.example.com',
    'dashboard.example.com',
    'docs.example.com',
]


# ---------------------------------------------------------------------------
# VULN 1: redirect with user-controlled URL from query parameter
# ---------------------------------------------------------------------------
@auth_bp.route('/login', methods=['POST'])
def login():
    """Handle user login and redirect to next page."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    next_url = request.args.get('next', '/')
    # VULN: User-controlled URL used directly in redirect
    # Attacker crafts link: /login?next=https://evil.com/phishing
    # After successful login, user is redirected to attacker's phishing page
    return redirect(next_url)


# ---------------------------------------------------------------------------
# VULN 2: redirect with user-controlled URL from POST body
# ---------------------------------------------------------------------------
@auth_bp.route('/auth/callback', methods=['POST'])
def oauth_callback():
    """OAuth callback with redirect URL."""
    redirect_uri = request.form.get('redirect_uri', '/')
    # VULN: User-controlled redirect_uri passed directly to redirect
    # Attacker posts: redirect_uri=https://attacker.com/steal-token
    return redirect(redirect_uri)


# ---------------------------------------------------------------------------
# VULN 3: 302 redirect with user-controlled Location header
# ---------------------------------------------------------------------------
@auth_bp.route('/auth/continue', methods=['GET'])
def continue_auth():
    """Continue authentication flow to external provider."""
    target = request.args.get('target', '')
    # VULN: User-controlled target used in redirect
    # Attacker uses: /auth/continue?target=https://evil.com
    from flask import make_response
    resp = make_response('', 302)
    resp.headers['Location'] = target
    return resp


# ---------------------------------------------------------------------------
# SAFE 1: Relative redirect only (URL starts with /)
# ---------------------------------------------------------------------------
@auth_bp.route('/auth/logout', methods=['POST'])
def logout():
    """Handle user logout with safe redirect."""
    next_page = request.form.get('next', '/')
    # SAFE: Ensure redirect is relative (starts with /, no protocol)
    if not next_page.startswith('/'):
        next_page = '/'
    return redirect(next_page)


# ---------------------------------------------------------------------------
# SAFE 2: Domain whitelist validation before redirect
# ---------------------------------------------------------------------------
@auth_bp.route('/auth/sso/return', methods=['GET'])
def sso_return():
    """SSO return endpoint with redirect validation."""
    return_to = request.args.get('return_to', '/dashboard')
    # SAFE: Validate redirect destination against whitelist
    parsed = urlparse(return_to)
    if parsed.hostname and parsed.hostname not in ALLOWED_REDIRECT_DOMAINS:
        return_to = '/dashboard'
    return redirect(return_to)
