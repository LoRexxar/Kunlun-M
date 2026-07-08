"""
Real-world insecure deserialization test cases for Kunlun-M scanner.
Simulates a Flask application with session/cache/import endpoints.
"""

import json
import pickle
from flask import Blueprint, request, jsonify

import_bp = Blueprint('import', __name__)


# ---------------------------------------------------------------------------
# VULN 1: pickle.loads with user-controlled serialized data
# ---------------------------------------------------------------------------
@import_bp.route('/api/import/session', methods=['POST'])
def import_session():
    """Import a user session from serialized data."""
    serialized_data = request.data
    # VULN: User-controlled data deserialized with pickle — allows arbitrary code execution
    # Attacker can craft a malicious pickle payload that executes os.system("id")
    try:
        session_data = pickle.loads(serialized_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'imported': str(session_data)})


# ---------------------------------------------------------------------------
# VULN 2: pickle.load from user-uploaded file
# ---------------------------------------------------------------------------
@import_bp.route('/api/import/cache', methods=['POST'])
def import_cache():
    """Import cache data from uploaded file."""
    uploaded_file = request.files.get('cache_file')
    if not uploaded_file:
        return jsonify({'error': 'No file uploaded'}), 400
    # VULN: User-uploaded file contents deserialized with pickle
    # Attacker uploads a file containing a malicious pickle payload
    file_content = uploaded_file.read()
    try:
        cache_data = pickle.loads(file_content)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'keys': list(cache_data.keys())})


# ---------------------------------------------------------------------------
# VULN 3: pickle.loads with base64-encoded user data
# ---------------------------------------------------------------------------
@import_bp.route('/api/import/settings', methods=['POST'])
def import_settings():
    """Import application settings from a base64-encoded pickle blob."""
    import base64
    encoded = request.form.get('settings', '')
    # VULN: Base64-decoded user input fed directly into pickle.loads
    # Attacker base64-encodes a malicious pickle and submits it
    raw_data = base64.b64decode(encoded)
    try:
        settings = pickle.loads(raw_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'settings': settings})


# ---------------------------------------------------------------------------
# SAFE 1: json.loads for structured data import
# ---------------------------------------------------------------------------
@import_bp.route('/api/import/config', methods=['POST'])
def import_config():
    """Import application configuration from JSON."""
    json_data = request.data
    # SAFE: json.loads only parses data structures — cannot execute code
    try:
        config = json.loads(json_data)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400
    return jsonify({'config': config})


# ---------------------------------------------------------------------------
# SAFE 2: pickle.loads with fixed/internally-generated data only
# ---------------------------------------------------------------------------
@import_bp.route('/api/export/state', methods=['GET'])
def export_state():
    """Export current application state (internally generated)."""
    # SAFE: Data is generated server-side, not from user input
    state = {'version': '1.0', 'items': [1, 2, 3]}
    serialized = pickle.dumps(state)
    return jsonify({'data': serialized.hex()})
