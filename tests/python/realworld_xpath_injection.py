"""
Real-world XPath injection test cases for Kunlun-M scanner.
Simulates a Flask application that queries XML documents using XPath.
"""

from flask import Blueprint, request, jsonify
from lxml import etree

xpath_bp = Blueprint('xpath', __name__)


def get_product_catalog():
    """Return an in-memory product catalog XML tree."""
    xml_str = '''
    <catalog>
        <product id="1">
            <name>Laptop</name>
            <category>electronics</category>
            <price>999</price>
        </product>
        <product id="2">
            <name>Desk Chair</name>
            <category>furniture</category>
            <price>250</price>
        </product>
        <product id="3">
            <name>Widget</name>
            <category>electronics</category>
            <price>50</price>
        </product>
    </catalog>
    '''
    return etree.fromstring(xml_str.encode())


# ---------------------------------------------------------------------------
# VULN 1: XPath injection via string concatenation in find
# ---------------------------------------------------------------------------
@xpath_bp.route('/api/products/search', methods=['GET'])
def search_products():
    """Search products by name using XPath."""
    query = request.args.get('q', '')
    root = get_product_catalog()
    # VULN: User input concatenated into XPath expression
    # Attacker can inject: q="]//*|//*["
    # or: q="Laptop' or 1=1 or 'a'='a" to bypass filters
    xpath_expr = f"//product[name='{query}']"
    results = root.xpath(xpath_expr)
    products = [{'name': p.find('name').text, 'price': p.find('price').text} for p in results]
    return jsonify({'products': products})


# ---------------------------------------------------------------------------
# VULN 2: XPath injection via string formatting in count query
# ---------------------------------------------------------------------------
@xpath_bp.route('/api/products/count', methods=['GET'])
def count_products():
    """Count products matching a category filter."""
    category = request.args.get('category', 'electronics')
    root = get_product_catalog()
    # VULN: User-controlled category concatenated into XPath
    # Attacker injects: category="electronics] | /catalog/product[price/text()='999 | /"
    xpath_expr = f"count(//product[category='{category}'])"
    count = root.xpath(xpath_expr)
    return jsonify({'count': count})


# ---------------------------------------------------------------------------
# VULN 3: XPath injection via f-string in complex query
# ---------------------------------------------------------------------------
@xpath_bp.route('/api/products/filter', methods=['POST'])
def filter_products():
    """Filter products with a user-specified XPath predicate."""
    predicate = request.form.get('predicate', 'true()')
    root = get_product_catalog()
    # VULN: Entire user-controlled predicate inserted into XPath
    # Attacker submits: predicate="1=1] | //*| /*[1=1"
    xpath_expr = f"//product[{predicate}]"
    results = root.xpath(xpath_expr)
    products = [{'name': p.find('name').text} for p in results]
    return jsonify({'products': products})


# ---------------------------------------------------------------------------
# SAFE 1: Using lxml XPath variables for safe parameterization
# ---------------------------------------------------------------------------
@xpath_bp.route('/api/products/lookup', methods=['GET'])
def lookup_product():
    """Look up a product by ID safely using XPath variables."""
    product_id = request.args.get('id', '1')
    root = get_product_catalog()
    # SAFE: XPath variable binding prevents injection
    results = root.xpath("//product[@id=$pid]", pid=product_id)
    if results:
        p = results[0]
        return jsonify({'name': p.find('name').text, 'price': p.find('price').text})
    return jsonify({'error': 'Product not found'}), 404


# ---------------------------------------------------------------------------
# SAFE 2: Server-side XPath with only internal data
# ---------------------------------------------------------------------------
@xpath_bp.route('/api/products/summary', methods=['GET'])
def product_summary():
    """Get product summary (server-controlled query)."""
    root = get_product_catalog()
    # SAFE: XPath expression is entirely server-controlled
    products = root.xpath("//product[price>100]")
    summary = [{'name': p.find('name').text, 'price': p.find('price').text} for p in products]
    return jsonify({'expensive_products': summary})
