"""
Real-world SQL injection test cases for Kunlun-M scanner.
Simulates a Flask application with user management and search endpoints.
"""

import sqlite3
from flask import Blueprint, request, jsonify, g

users_bp = Blueprint('users', __name__)


def get_db():
    """Get database connection from Flask g object."""
    if 'db' not in g:
        g.db = sqlite3.connect('app.db')
        g.db.row_factory = sqlite3.Row
    return g.db


# ---------------------------------------------------------------------------
# VULN 1: SQL injection via string concatenation in SELECT
# ---------------------------------------------------------------------------
@users_bp.route('/api/users/search', methods=['GET'])
def search_users():
    """Search users by username."""
    keyword = request.args.get('q', '')
    db = get_db()
    # VULN: User input directly concatenated into SQL query
    # Attacker can inject: q="' OR 1=1 --" to dump all users
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{keyword}%'"
    cursor = db.execute(query)
    results = cursor.fetchall()
    return jsonify([dict(row) for row in results])


# ---------------------------------------------------------------------------
# VULN 2: SQL injection via f-string in UPDATE
# ---------------------------------------------------------------------------
@users_bp.route('/api/users/<int:user_id>/profile', methods=['POST'])
def update_profile(user_id):
    """Update user profile information."""
    bio = request.form.get('bio', '')
    db = get_db()
    # VULN: User input in f-string SQL without parameterization
    # Attacker can inject: bio="'; DROP TABLE users; --"
    query = f"UPDATE users SET bio = '{bio}' WHERE id = {user_id}"
    db.execute(query)
    db.commit()
    return jsonify({'status': 'updated'})


# ---------------------------------------------------------------------------
# VULN 3: SQL injection via string concatenation with ORDER BY
# ---------------------------------------------------------------------------
@users_bp.route('/api/users/list', methods=['GET'])
def list_users():
    """List users with sorting."""
    sort_col = request.args.get('sort', 'username')
    direction = request.args.get('dir', 'ASC')
    db = get_db()
    # VULN: User-controlled column name concatenated into ORDER BY clause
    # Attacker can inject: sort="username; DROP TABLE users --"
    query = f"SELECT id, username, email FROM users ORDER BY {sort_col} {direction}"
    cursor = db.execute(query)
    results = cursor.fetchall()
    return jsonify([dict(row) for row in results])


# ---------------------------------------------------------------------------
# SAFE 1: Parameterized query with ? placeholders
# ---------------------------------------------------------------------------
@users_bp.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a single user by ID."""
    db = get_db()
    # SAFE: Parameterized query prevents SQL injection
    cursor = db.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(dict(user))


# ---------------------------------------------------------------------------
# SAFE 2: Parameterized query with named placeholders
# ---------------------------------------------------------------------------
@users_bp.route('/api/users/lookup', methods=['POST'])
def lookup_user():
    """Look up a user by email."""
    email = request.form.get('email', '')
    db = get_db()
    # SAFE: Using named parameter placeholders
    cursor = db.execute(
        "SELECT id, username, email FROM users WHERE email = :email",
        {'email': email}
    )
    user = cursor.fetchone()
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(dict(user))
