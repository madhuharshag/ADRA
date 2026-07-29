"""
Database Service Module (db_service.py)
Handles SQLite database initialization, data persistence, and query execution.
Provides safe parameter binding to prevent SQL injection vulnerabilities.
"""

import os
import json
import sqlite3
import logging
from typing import Dict, Any, List, Optional

# Set up module logger
logger = logging.getLogger(__name__)

# Default database path relative to project root
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "database", "app.db")


def resolve_db_path(db_path: Optional[str] = None) -> str:
    """
    Resolves a writable SQLite database path.
    On serverless environments (e.g. Vercel), fallbacks to /tmp/app.db if root directory is read-only.
    """
    if not db_path or db_path == DEFAULT_DB_PATH:
        db_path = os.getenv("DATABASE_URL", DEFAULT_DB_PATH)

    if db_path.startswith("sqlite:///"):
        db_path = db_path.replace("sqlite:///", "")

    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return "/tmp/app.db"

    db_dir = os.path.dirname(db_path)
    if db_dir:
        try:
            os.makedirs(db_dir, exist_ok=True)
        except (OSError, PermissionError):
            return "/tmp/app.db"

    return db_path


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a database connection with dictionary row formatting.
    Ensures safe fallback to /tmp/app.db on read-only serverless environments.
    """
    target_path = resolve_db_path(db_path)
    db_dir = os.path.dirname(target_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except (OSError, PermissionError):
            target_path = "/tmp/app.db"

    try:
        conn = sqlite3.connect(target_path)
    except sqlite3.OperationalError:
        target_path = "/tmp/app.db"
        conn = sqlite3.connect(target_path)

    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the SQLite database schema if the assessments table does not exist.
    """
    target_path = resolve_db_path(db_path)
    try:
        with get_db_connection(target_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    company_name TEXT NOT NULL,
                    industry TEXT NOT NULL,
                    employees INTEGER NOT NULL,
                    uses_mfa TEXT NOT NULL,
                    firewall_enabled TEXT NOT NULL,
                    antivirus_installed TEXT NOT NULL,
                    backup_strategy TEXT NOT NULL,
                    password_policy TEXT NOT NULL,
                    public_wifi_usage TEXT NOT NULL,
                    employee_training TEXT NOT NULL,
                    cloud_provider TEXT NOT NULL,
                    email_security TEXT NOT NULL,
                    previous_incidents INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    ai_explanation TEXT NOT NULL,
                    recommendations TEXT NOT NULL,
                    risk_breakdown TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            logger.info("Database schema initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database schema: {e}")
        raise


def save_assessment(
    input_data: Dict[str, Any],
    risk_result: Dict[str, Any],
    ai_result: Dict[str, Any],
    db_path: Optional[str] = None
) -> int:
    """
    Saves a completed assessment submission, score, and AI recommendations to SQLite.
    Returns the newly inserted record ID.
    """
    target_path = resolve_db_path(db_path)
    query = """
        INSERT INTO assessments (
            company_name, industry, employees, uses_mfa, firewall_enabled,
            antivirus_installed, backup_strategy, password_policy, public_wifi_usage,
            employee_training, cloud_provider, email_security, previous_incidents,
            risk_score, risk_level, ai_explanation, recommendations, risk_breakdown
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    recommendations_json = json.dumps(ai_result.get("recommendations", []))
    breakdown_json = json.dumps(risk_result.get("breakdown", []))

    params = (
        str(input_data.get("company_name", "")).strip(),
        str(input_data.get("industry", "")).strip(),
        int(input_data.get("employees", 0)),
        str(input_data.get("uses_mfa", "No")),
        str(input_data.get("firewall_enabled", "No")),
        str(input_data.get("antivirus_installed", "No")),
        str(input_data.get("backup_strategy", "None")),
        str(input_data.get("password_policy", "Weak")),
        str(input_data.get("public_wifi_usage", "Yes")),
        str(input_data.get("employee_training", "No")),
        str(input_data.get("cloud_provider", "None")),
        str(input_data.get("email_security", "None")),
        int(input_data.get("previous_incidents", 0)),
        int(risk_result.get("score", 0)),
        str(risk_result.get("level", "Medium")),
        str(ai_result.get("explanation", "")),
        recommendations_json,
        breakdown_json
    )

    try:
        with get_db_connection(target_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            assessment_id = cursor.lastrowid
            logger.info(f"Saved assessment record ID: {assessment_id}")
            return assessment_id
    except sqlite3.Error as e:
        logger.error(f"Error saving assessment record: {e}")
        raise


def get_all_assessments(limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves recent assessment records sorted by timestamp descending.
    """
    target_path = resolve_db_path(db_path)
    query = """
        SELECT id, company_name, industry, employees, risk_score, risk_level, 
               ai_explanation, recommendations, risk_breakdown, timestamp
        FROM assessments
        ORDER BY timestamp DESC
        LIMIT ?;
    """
    try:
        with get_db_connection(target_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                item = dict(row)
                # Deserialize stored JSON strings
                try:
                    item["recommendations"] = json.loads(item.get("recommendations", "[]"))
                except (json.JSONDecodeError, TypeError):
                    item["recommendations"] = []

                try:
                    item["risk_breakdown"] = json.loads(item.get("risk_breakdown", "[]"))
                except (json.JSONDecodeError, TypeError):
                    item["risk_breakdown"] = []

                results.append(item)
            return results
    except sqlite3.Error as e:
        logger.error(f"Error fetching assessment records: {e}")
        return []


def get_assessment_by_id(assessment_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single assessment record by ID.
    """
    target_path = resolve_db_path(db_path)
    query = "SELECT * FROM assessments WHERE id = ?;"
    try:
        with get_db_connection(target_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (assessment_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            item = dict(row)
            try:
                item["recommendations"] = json.loads(item.get("recommendations", "[]"))
            except (json.JSONDecodeError, TypeError):
                item["recommendations"] = []

            try:
                item["risk_breakdown"] = json.loads(item.get("risk_breakdown", "[]"))
            except (json.JSONDecodeError, TypeError):
                item["risk_breakdown"] = []

            return item
    except sqlite3.Error as e:
        logger.error(f"Error fetching assessment ID {assessment_id}: {e}")
        return None

