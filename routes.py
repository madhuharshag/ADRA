"""
HTTP Routes Module (routes.py)
Defines web page rendering and API endpoints. Delegates all business logic
and validation to controller.py. Applies rate limiting to protect API resources.
"""

import logging
from flask import Blueprint, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import controller

logger = logging.getLogger(__name__)

# Create Flask Blueprint for modular routing
api_bp = Blueprint("api", __name__)


def register_routes(app, limiter: Limiter) -> None:
    """
    Registers Blueprint and route rate limits on the Flask application instance.
    """
    
    @app.route("/", methods=["GET"])
    def index():
        """Render main landing page and dashboard."""
        return render_template("index.html")

    @app.route("/risk", methods=["GET"])
    @limiter.limit("30 per minute")
    def get_risk_history():
        """Retrieve recent risk assessment submissions."""
        response, status_code = controller.fetch_assessment_history()
        return jsonify(response), status_code

    @app.route("/risk", methods=["POST"])
    @limiter.limit("10 per minute")
    def create_risk_assessment():
        """Process a new cybersecurity risk assessment."""
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        response, status_code = controller.process_risk_assessment(data)
        return jsonify(response), status_code

    @app.route("/risk/<int:assessment_id>", methods=["GET"])
    @limiter.limit("30 per minute")
    def get_risk_detail(assessment_id: int):
        """Retrieve detailed assessment by ID."""
        response, status_code = controller.fetch_assessment_detail(assessment_id)
        return jsonify(response), status_code
