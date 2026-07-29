"""
Application Controller (controller.py)
Orchestrates request processing, input validation, risk scoring, AI advice generation,
and database persistence. Keeps business logic separated from HTTP routes.
"""

import logging
from typing import Dict, Any, Tuple, Optional
import db_service
import risk_service
import ai_service

logger = logging.getLogger(__name__)


def validate_assessment_input(data: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Validates user input submitted to the risk assessment form.

    Returns:
        (is_valid: bool, error_message: str | None, cleaned_data: dict)
    """
    if not isinstance(data, dict):
        return False, "Invalid request payload format. JSON object expected.", {}

    company_name = str(data.get("company_name", "")).strip()
    if not company_name or len(company_name) < 2:
        return False, "Company name must be at least 2 characters long.", {}
    if len(company_name) > 100:
        return False, "Company name cannot exceed 100 characters.", {}

    industry = str(data.get("industry", "")).strip()
    if not industry:
        return False, "Please select or specify a valid industry.", {}

    # Validate employee count
    try:
        employees = int(data.get("employees", 0))
        if employees < 1:
            return False, "Number of employees must be at least 1.", {}
        if employees > 1000000:
            return False, "Number of employees exceeds realistic maximum.", {}
    except (ValueError, TypeError):
        return False, "Number of employees must be a valid integer.", {}

    # Validate choices
    valid_yes_no = ["Yes", "No"]
    
    uses_mfa = str(data.get("uses_mfa", "")).strip().capitalize()
    if uses_mfa not in valid_yes_no:
        uses_mfa = "No"

    firewall_enabled = str(data.get("firewall_enabled", "")).strip().capitalize()
    if firewall_enabled not in valid_yes_no:
        firewall_enabled = "No"

    antivirus_installed = str(data.get("antivirus_installed", "")).strip().capitalize()
    if antivirus_installed not in valid_yes_no:
        antivirus_installed = "No"

    public_wifi_usage = str(data.get("public_wifi_usage", "")).strip().capitalize()
    if public_wifi_usage not in valid_yes_no:
        public_wifi_usage = "Yes"

    employee_training = str(data.get("employee_training", "")).strip().capitalize()
    if employee_training not in valid_yes_no:
        employee_training = "No"

    backup_strategy = str(data.get("backup_strategy", "None")).strip()
    password_policy = str(data.get("password_policy", "Weak")).strip()
    cloud_provider = str(data.get("cloud_provider", "None")).strip()
    email_security = str(data.get("email_security", "None")).strip()

    # Validate previous incidents count
    try:
        previous_incidents = int(data.get("previous_incidents", 0))
        if previous_incidents < 0:
            return False, "Number of previous incidents cannot be negative.", {}
    except (ValueError, TypeError):
        return False, "Previous incidents count must be a valid integer.", {}

    cleaned_data = {
        "company_name": company_name,
        "industry": industry,
        "employees": employees,
        "uses_mfa": uses_mfa,
        "firewall_enabled": firewall_enabled,
        "antivirus_installed": antivirus_installed,
        "backup_strategy": backup_strategy,
        "password_policy": password_policy,
        "public_wifi_usage": public_wifi_usage,
        "employee_training": employee_training,
        "cloud_provider": cloud_provider,
        "email_security": email_security,
        "previous_incidents": previous_incidents
    }

    return True, None, cleaned_data


def process_risk_assessment(raw_data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """
    Executes complete assessment workflow:
    1. Input validation
    2. Rule-based risk scoring
    3. AI advice generation
    4. Database archival

    Returns:
        (response_payload: dict, http_status_code: int)
    """
    is_valid, error_msg, cleaned_data = validate_assessment_input(raw_data)
    if not is_valid:
        logger.warning(f"Assessment validation failed: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }, 400

    try:
        # Step 1: Calculate risk score and level
        risk_result = risk_service.calculate_risk(cleaned_data)

        # Step 2: Generate AI executive summary & action items
        ai_result = ai_service.generate_assessment_advice(cleaned_data, risk_result)

        # Step 3: Persist record to SQLite
        assessment_id = db_service.save_assessment(cleaned_data, risk_result, ai_result)

        # Step 4: Construct response payload
        response = {
            "success": True,
            "assessment_id": assessment_id,
            "company_name": cleaned_data["company_name"],
            "industry": cleaned_data["industry"],
            "employees": cleaned_data["employees"],
            "risk_score": risk_result["score"],
            "risk_level": risk_result["level"],
            "risk_breakdown": risk_result["breakdown"],
            "ai_explanation": ai_result["explanation"],
            "recommendations": ai_result["recommendations"]
        }

        return response, 201

    except Exception as e:
        logger.error(f"Error processing assessment: {e}", exc_info=True)
        return {
            "success": False,
            "error": "An internal error occurred while processing the risk assessment."
        }, 500


def fetch_assessment_history(limit: int = 20) -> Tuple[Dict[str, Any], int]:
    """
    Retrieves recent assessment submissions from the database.
    """
    try:
        history = db_service.get_all_assessments(limit=limit)
        return {
            "success": True,
            "count": len(history),
            "data": history
        }, 200
    except Exception as e:
        logger.error(f"Error retrieving history: {e}")
        return {
            "success": False,
            "error": "Could not retrieve assessment history."
        }, 500


def fetch_assessment_detail(assessment_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Retrieves a single assessment submission by ID.
    """
    try:
        record = db_service.get_assessment_by_id(assessment_id)
        if not record:
            return {
                "success": False,
                "error": f"Assessment with ID {assessment_id} not found."
            }, 404
        
        return {
            "success": True,
            "data": record
        }, 200
    except Exception as e:
        logger.error(f"Error retrieving assessment {assessment_id}: {e}")
        return {
            "success": False,
            "error": "Error fetching assessment details."
        }, 500
