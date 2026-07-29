"""
Flask Server Application Entrypoint (server.py)
Initializes environment variables, logging, database tables, rate limiting,
error handlers, and HTTP server routes.

Execution:
    python3 server.py
"""

import os
import logging
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

import db_service
import routes

# Load environment variables from .env file
load_dotenv()

# Configure Application Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("server")

# Initialize Flask App instance
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static")
)

# App Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default_fallback_secret_key_2026")
app.config["JSON_SORT_KEYS"] = False

# Configure Flask-Limiter safely for serverless runtime
try:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["100 per hour", "20 per minute"],
        storage_uri="memory://"
    )
except Exception as e:
    logger.warning(f"Flask-Limiter initialization warning: {e}")
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# Initialize Database Schema safely on startup
try:
    db_path = os.getenv("DATABASE_URL", "sqlite:///database/app.db")
    if db_path.startswith("sqlite:///"):
        db_path = db_path.replace("sqlite:///", "")
    db_service.init_db(db_path)
except Exception as e:
    logger.warning(f"Database schema initialization warning: {e}")

# Register routes with Flask app and Limiter
routes.register_routes(app, limiter)



# Global Custom Error Handlers
@app.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        "success": False,
        "error": "The requested resource or endpoint was not found on this server."
    }), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "success": False,
        "error": "Rate limit exceeded. Please wait a moment before sending additional requests."
    }), 429


@app.errorhandler(500)
def internal_error_handler(e):
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({
        "success": False,
        "error": "An internal server error occurred. Please contact the administrator."
    }), 500


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5050))
    debug = os.getenv("FLASK_ENV", "development") == "development"

    logger.info(f"Starting AI Cybersecurity Risk Analysis Server on http://{host}:{port} (Debug: {debug})")
    app.run(host=host, port=port, debug=debug)

