"""
Real-world XXE (XML External Entity) injection test cases for Kunlun-M scanner.
Simulates a Flask application with XML import/API integration endpoints.
"""

from flask import Blueprint, request, jsonify

xml_bp = Blueprint('xml', __name__)


# ---------------------------------------------------------------------------
# VULN 1: ElementTree.parse with user-uploaded XML file
# ---------------------------------------------------------------------------
@xml_bp.route('/api/import/xml', methods=['POST'])
def import_xml_file():
    """Import data from an uploaded XML file."""
    uploaded_file = request.files.get('xml_file')
    if not uploaded_file:
        return jsonify({'error': 'No file uploaded'}), 400
    # VULN: User-uploaded XML parsed without disabling external entities
    # Attacker uploads XML with: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    import xml.etree.ElementTree as ET
    import io
    tree = ET.parse(io.BytesIO(uploaded_file.read()))
    root = tree.getroot()
    return jsonify({'root_tag': root.tag, 'children': len(root)})


# ---------------------------------------------------------------------------
# VULN 2: ElementTree.fromstring with user-controlled XML string
# ---------------------------------------------------------------------------
@xml_bp.route('/api/xml/parse', methods=['POST'])
def parse_xml_string():
    """Parse an XML string submitted by the user."""
    xml_string = request.form.get('xml_data', '')
    # VULN: User-controlled XML parsed directly, no entity protection
    # Attacker submits XML containing: <!ENTITY xxe SYSTEM "file:///etc/shadow">
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_string)
    return jsonify({'tag': root.tag, 'text': root.text})


# ---------------------------------------------------------------------------
# VULN 3: XML parsing from request body with user-controlled content
# ---------------------------------------------------------------------------
@xml_bp.route('/api/webhooks/xml', methods=['POST'])
def xml_webhook():
    """Process incoming XML webhook payload."""
    xml_payload = request.data
    # VULN: Raw request body parsed as XML without entity restrictions
    # Attacker sends XML with external entity pointing to cloud metadata
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_payload.decode('utf-8'))
    event_type = root.find('event').text if root.find('event') is not None else 'unknown'
    return jsonify({'event': event_type})


# ---------------------------------------------------------------------------
# SAFE 1: Using defusedxml to safely parse user XML
# ---------------------------------------------------------------------------
@xml_bp.route('/api/import/safe_xml', methods=['POST'])
def safe_import_xml():
    """Safely import XML using defusedxml."""
    xml_string = request.form.get('xml_data', '')
    # SAFE: defusedxml disables dangerous features including external entities
    try:
        import defusedxml.ElementTree as ET
        root = ET.fromstring(xml_string)
        return jsonify({'tag': root.tag, 'text': root.text})
    except Exception as e:
        return jsonify({'error': f'XML parsing blocked: {e}'}), 400


# ---------------------------------------------------------------------------
# SAFE 2: Server-generated XML only (no user input)
# ---------------------------------------------------------------------------
@xml_bp.route('/api/export/xml', methods=['GET'])
def export_xml():
    """Generate XML response from server data."""
    import xml.etree.ElementTree as ET
    # SAFE: XML is constructed server-side, not from user input
    root = ET.Element('response')
    child = ET.SubElement(root, 'status')
    child.text = 'ok'
    return jsonify({'xml': ET.tostring(root, encoding='unicode')})
