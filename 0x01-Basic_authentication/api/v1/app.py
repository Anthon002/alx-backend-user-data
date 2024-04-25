#!/usr/bin/env python3
"""method for routing module for the api
"""
import os
from flask import Flask, abort, request, jsonify,
from flask_cors import (CORS, cross_origin)
from os import getenv


from api.v1.views import app_views
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.auth import Auth


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None
authentication_type = getenv('AUTH_TYPE', 'auth')
if authentication_type == 'auth':
    auth = Auth()
if authentication_type == 'basic_auth':
    auth = BasicAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """method to handle Not found
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """method to handle Unauthorized
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """method to handle forbidden
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def authenticate_user():
    """method to authenticates users before request processing
    """
    if auth:
        excluded_paths = [
            '/api/v1/status/',
            '/api/v1/unauthorized/',
            '/api/v1/forbidden/',
        ]
        if auth.require_auth(request.path, excluded_paths):
            authentication_header = auth.authorization_header(request)
            user = auth.current_user(request)
            if authentication_header is None:
                abort(401)
            if user is None:
                abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
