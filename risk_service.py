"""
Risk Assessment Engine Service (risk_service.py)
Evaluates organizational cybersecurity practices and calculates a score (0–100)
and risk level (Low, Medium, High, Critical) based on deterministic security rules.
"""

from typing import Dict, Any, List


def calculate_risk(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates the cybersecurity risk score, risk level, and detailed risk factors.

    Args:
        data: Dict containing security assessment answers.

    Returns:
        Dict containing:
        - score: Int (0–100)
        - level: Str ("Low" | "Medium" | "High" | "Critical")
        - breakdown: List of risk factor details (category, risk_added, reason)
    """
    base_score = 0
    breakdown: List[Dict[str, Any]] = []

    # 1. Multi-Factor Authentication (MFA)
    mfa = str(data.get("uses_mfa", "No")).strip().lower()
    if mfa in ["no", "false", "0", "none"]:
        score_add = 20
        base_score += score_add
        breakdown.append({
            "factor": "Multi-Factor Authentication (MFA)",
            "impact": "+20 Risk Points",
            "status": "Disabled",
            "severity": "High",
            "details": "Lack of MFA exposes user accounts to credential stuffing and phishing attacks."
        })

    # 2. Firewall Protection
    firewall = str(data.get("firewall_enabled", "No")).strip().lower()
    if firewall in ["no", "false", "0", "none"]:
        score_add = 20
        base_score += score_add
        breakdown.append({
            "factor": "Network Firewall",
            "impact": "+20 Risk Points",
            "status": "Disabled / Unconfigured",
            "severity": "High",
            "details": "Unprotected network boundaries allow unauthorized ingress and port intrusion."
        })

    # 3. Endpoint Antivirus / EDR
    antivirus = str(data.get("antivirus_installed", "No")).strip().lower()
    if antivirus in ["no", "false", "0", "none"]:
        score_add = 10
        base_score += score_add
        breakdown.append({
            "factor": "Endpoint Security / Antivirus",
            "impact": "+10 Risk Points",
            "status": "Missing",
            "severity": "Medium",
            "details": "Workstations and servers lack malware protection and automated endpoint monitoring."
        })

    # 4. Data Backup Strategy
    backup = str(data.get("backup_strategy", "None")).strip().lower()
    if backup in ["none", "no"]:
        score_add = 20
        base_score += score_add
        breakdown.append({
            "factor": "Data Backup Strategy",
            "impact": "+20 Risk Points",
            "status": "No Backups",
            "severity": "High",
            "details": "No data backup procedure leaves the company extremely vulnerable to ransomware loss."
        })
    elif backup in ["infrequent", "monthly", "manual"]:
        score_add = 10
        base_score += score_add
        breakdown.append({
            "factor": "Data Backup Strategy",
            "impact": "+10 Risk Points",
            "status": "Infrequent / Manual",
            "severity": "Medium",
            "details": "Infrequent backups risk business data loss between snapshot cycles."
        })

    # 5. Password Policy
    password_policy = str(data.get("password_policy", "Weak")).strip().lower()
    if password_policy in ["weak", "none"]:
        score_add = 15
        base_score += score_add
        breakdown.append({
            "factor": "Password Policy",
            "impact": "+15 Risk Points",
            "status": "Weak / Short Passwords",
            "severity": "High",
            "details": "Short or non-complex passwords are vulnerable to automated brute-force attacks."
        })
    elif password_policy in ["moderate", "medium"]:
        score_add = 5
        base_score += score_add
        breakdown.append({
            "factor": "Password Policy",
            "impact": "+5 Risk Points",
            "status": "Moderate",
            "severity": "Low",
            "details": "Password policy could be strengthened with longer passphrases and password managers."
        })

    # 6. Public Wi-Fi Usage
    public_wifi = str(data.get("public_wifi_usage", "Yes")).strip().lower()
    if public_wifi in ["yes", "true", "1"]:
        score_add = 10
        base_score += score_add
        breakdown.append({
            "factor": "Unsecured Public Wi-Fi Usage",
            "impact": "+10 Risk Points",
            "status": "Allowed without mandatory VPN",
            "severity": "Medium",
            "details": "Connecting to open networks risks Man-In-The-Middle (MITM) session hijacking."
        })

    # 7. Employee Security Awareness Training
    training = str(data.get("employee_training", "No")).strip().lower()
    if training in ["no", "false", "0", "none"]:
        score_add = 10
        base_score += score_add
        breakdown.append({
            "factor": "Security Awareness Training",
            "impact": "+10 Risk Points",
            "status": "No Regular Training",
            "severity": "Medium",
            "details": "Employees lack phishing awareness, making social engineering attacks more effective."
        })

    # 8. Email Security Gateway
    email_sec = str(data.get("email_security", "None")).strip().lower()
    if email_sec in ["none", "no"]:
        score_add = 15
        base_score += score_add
        breakdown.append({
            "factor": "Email Security Controls",
            "impact": "+15 Risk Points",
            "status": "No Advanced Filtering (SPF/DKIM/DMARC)",
            "severity": "High",
            "details": "Lack of email authentication and spam filtering exposes organization to CEO fraud and malware attachments."
        })
    elif email_sec in ["basic", "standard"]:
        score_add = 5
        base_score += score_add
        breakdown.append({
            "factor": "Email Security Controls",
            "impact": "+5 Risk Points",
            "status": "Basic Filtering Only",
            "severity": "Low",
            "details": "Consider upgrading to advanced threat protection (ATP) with link sandboxing."
        })

    # 9. Historical Cybersecurity Incidents
    try:
        incidents = int(data.get("previous_incidents", 0))
    except (ValueError, TypeError):
        incidents = 0

    if incidents >= 5:
        score_add = 15
        base_score += score_add
        breakdown.append({
            "factor": "Security Incident History",
            "impact": "+15 Risk Points",
            "status": f"{incidents} Incidents in Past Year",
            "severity": "High",
            "details": "Frequent historical breaches indicate persistent vulnerabilities and active target status."
        })
    elif 1 <= incidents < 5:
        score_add = 10
        base_score += score_add
        breakdown.append({
            "factor": "Security Incident History",
            "impact": "+10 Risk Points",
            "status": f"{incidents} Incident(s) in Past Year",
            "severity": "Medium",
            "details": "Recent incidents indicate room for remediation in threat defense."
        })

    # Ensure score stays within bound [0, 100]
    final_score = max(0, min(100, base_score))

    # Determine qualitative Risk Level based on final score
    if final_score <= 25:
        risk_level = "Low"
    elif final_score <= 50:
        risk_level = "Medium"
    elif final_score <= 75:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return {
        "score": final_score,
        "level": risk_level,
        "breakdown": breakdown
    }
