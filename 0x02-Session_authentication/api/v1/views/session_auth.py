#!/usr/bin/env python3
"""Session authentication routes: login & logout
"""
from api.v1.views import app_views
from flask import request, jsonify, abort
from models.user import User
from os import getenv


def auth():
    """Lazy-import the global auth instance to avoid circular import"""
    from api.v1.app import auth
    return auth


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """POST /api/v1/auth_session/login — create a Session ID"""
    email = request.form.get('email')
    pwd = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not pwd:
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(pwd):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth().create_session(user.id)
    resp = jsonify(user.to_json())
    resp.set_cookie(getenv("SESSION_NAME"), session_id)
    return resp


@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_logout():
    """DELETE /api/v1/auth_session/logout — destroy the Session ID"""
    if not auth().destroy_session(request):
        abort(404)
    return jsonify({}), 200
