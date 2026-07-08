"""
Real-world expression injection test cases for Kunlun-M scanner.
Simulates a Flask application with dynamic log querying, configuration, and eval-like endpoints.
"""

import string
from flask import Blueprint, request, jsonify

config_bp = Blueprint('config', __name__)


# ---------------------------------------------------------------------------
# VULN 1: str.format() with user-controlled format string
# ---------------------------------------------------------------------------
@config_bp.route('/api/logs/query', methods=['GET'])
def query_logs():
    """Query application logs with a user-specified format."""
    format_str = request.args.get('format', '{timestamp} - {level} - {message}')
    log_entry = {'timestamp': '2026-01-15T10:30:00', 'level': 'ERROR', 'message': 'Connection failed'}
    # VULN: User-controlled format string passed to str.format()
    # Attacker can inject: format="{0.__class__.__init__.__globals__}"
    # or: format="{log_entry.__class__.__init__.__globals__['os'].system('id')}"
    try:
        result = format_str.format(log_entry=log_entry, **log_entry)
    except (KeyError, IndexError, AttributeError) as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'result': result})


# ---------------------------------------------------------------------------
# VULN 2: string.Template with user-controlled template
# ---------------------------------------------------------------------------
@config_bp.route('/api/config/preview', methods=['POST'])
def preview_config():
    """Preview a configuration template with user-specified pattern."""
    template_str = request.form.get('template', '${hostname}')
    values = {'hostname': 'web-server-01', 'port': '8080', 'env': 'production'}
    # VULN: User-controlled template string — Template.safe_substitute is used
    # but the template itself can contain malicious format specifiers
    # Attacker can explore attributes: template="${values.__class__.__init__.__globals__}"
    from string import Template
    tmpl = Template(template_str)
    try:
        result = tmpl.substitute(values)
    except (KeyError, ValueError) as e:
        result = tmpl.safe_substitute(values)
    return jsonify({'preview': result})


# ---------------------------------------------------------------------------
# VULN 3: str.format_map with user-controlled format string and data
# ---------------------------------------------------------------------------
@config_bp.route('/api/notifications/render', methods=['POST'])
def render_notification():
    """Render a notification message from template."""
    template = request.form.get('template', '')
    data = request.get_json(silent=True) or {}
    # VULN: Both template and data are user-controlled in format_map
    # Attacker crafts a template that accesses internal attributes
    try:
        result = template.format_map(data)
    except (KeyError, IndexError, AttributeError) as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'rendered': result})


# ---------------------------------------------------------------------------
# SAFE 1: Server-controlled format string with user data as values
# ---------------------------------------------------------------------------
@config_bp.route('/api/greeting', methods=['GET'])
def greeting():
    """Generate a greeting message."""
    name = request.args.get('name', 'Guest')
    # SAFE: Format string is server-controlled, user only provides data values
    message = 'Hello, {}! Welcome to our service.'.format(name)
    return jsonify({'greeting': message})


# ---------------------------------------------------------------------------
# SAFE 2: Server-controlled template with no user input
# ---------------------------------------------------------------------------
@config_bp.route('/api/system/status', methods=['GET'])
def system_status():
    """Get system status page (server-controlled template)."""
    # SAFE: Template is entirely server-controlled
    uptime = 86400
    status = 'healthy'
    template = 'System has been {} for {} seconds and is {}.'
    result = template.format('running', uptime, status)
    return jsonify({'message': result})
