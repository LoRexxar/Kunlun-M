"""
Real-world SSTI (Server-Side Template Injection) test cases for Kunlun-M scanner.
Simulates a Flask application with dynamic template rendering for email / page builders.
"""

import json
from flask import Blueprint, request, jsonify, render_template

templates_bp = Blueprint('templates', __name__)


# ---------------------------------------------------------------------------
# VULN 1: render_template_string with user-controlled template content
# ---------------------------------------------------------------------------
@templates_bp.route('/api/email/preview', methods=['POST'])
def preview_email():
    """Preview an email template with user-provided content."""
    template_content = request.form.get('template', '')
    # VULN: User-controlled string passed directly to render_template_string
    # Attacker can inject: template="{{ config['SECRET_KEY'] }}" or
    # template="{{ ''.__class__.__mro__[1].__subclasses__() }}"
    from flask import render_template_string
    rendered = render_template_string(template_content)
    return jsonify({'preview': rendered})


# ---------------------------------------------------------------------------
# VULN 2: Jinja2 Environment.Template with user input
# ---------------------------------------------------------------------------
@templates_bp.route('/api/pages/render', methods=['POST'])
def render_custom_page():
    """Render a custom page from user-provided template source."""
    data = request.get_json()
    template_source = data.get('source', '')
    # VULN: User-controlled template source compiled and rendered directly
    # Attacker can inject Jinja2 sandbox escapes to execute code
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_source)
    rendered = template.render()
    return jsonify({'html': rendered})


# ---------------------------------------------------------------------------
# VULN 3: render_template_string with partially user-controlled template
# ---------------------------------------------------------------------------
@templates_bp.route('/api/reports/generate', methods=['GET'])
def generate_report():
    """Generate a report with user-specified title."""
    title = request.args.get('title', 'Report')
    db = request.args.get('db', 'main')
    # VULN: User input interpolated into template string before rendering
    # Attacker can inject: title="{{config}}" to leak Flask config
    from flask import render_template_string
    template = f'''
    <html><head><title>{title}</title></head>
    <body><h1>Report from {db}</h1></body></html>
    '''
    rendered = render_template_string(template)
    return jsonify({'html': rendered})


# ---------------------------------------------------------------------------
# SAFE 1: render_template with named variables (server-side template file)
# ---------------------------------------------------------------------------
@templates_bp.route('/api/users/<username>/profile', methods=['GET'])
def user_profile(username):
    """Render user profile using a server-side template file."""
    db = get_user_data(username)  # hypothetical helper
    # SAFE: render_template loads a file from the templates directory
    # and passes user data as named variables — no template injection possible
    return render_template('user_profile.html', user=db, title='User Profile')


def get_user_data(username):
    return {'username': username, 'email': f'{username}@example.com'}


# ---------------------------------------------------------------------------
# SAFE 2: render_template_string with only server-controlled values
# ---------------------------------------------------------------------------
@templates_bp.route('/api/system/info', methods=['GET'])
def system_info():
    """Show system information page."""
    from flask import render_template_string
    # SAFE: Template string is entirely server-controlled; no user input in template
    version = '2.5.1'
    status = 'operational'
    template = '<html><body><h1>System v{{ version }}</h1><p>Status: {{ status }}</p></body></html>'
    return render_template_string(template, version=version, status=status)
