"""
AI Cybersecurity Advisory Service (ai_service.py)
Provides modular AI-driven cybersecurity posture explanations and action items.

Designed with an interface pattern:
- By default, uses a sophisticated local threat analysis engine based on score & risk vectors.
- Can be seamlessly switched to OpenAI API or another LLM provider by configuring OPENAI_API_KEY
  or changing the active provider in this module.
"""

import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class AIServiceInterface:
    """Abstract interface for AI Cybersecurity Advisory services."""

    def generate_advice(self, input_data: Dict[str, Any], risk_result: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("AI Service must implement generate_advice")


class LocalRuleAIService(AIServiceInterface):
    """
    Local AI Advisory Engine.
    Generates dynamic, context-aware cybersecurity executive summaries and prioritized action plans
    tailored to company size, industry, risk score, and detected vulnerabilities.
    """

    def generate_advice(self, input_data: Dict[str, Any], risk_result: Dict[str, Any]) -> Dict[str, Any]:
        company = input_data.get("company_name", "Your Organization")
        industry = input_data.get("industry", "General")
        employees = input_data.get("employees", 0)
        score = risk_result.get("score", 0)
        level = risk_result.get("level", "Medium")
        breakdown = risk_result.get("breakdown", [])

        # Executive summary generation
        summary_paragraphs = []
        if level == "Low":
            summary_paragraphs.append(
                f"{company} demonstrates a robust baseline cybersecurity posture for the {industry} sector. "
                f"With a risk score of {score}/100 ({level} Risk), fundamental security controls such as perimeter access "
                "and endpoint management appear well-managed."
            )
            summary_paragraphs.append(
                "To maintain this defensive edge, focus on continuous threat monitoring, zero-trust expansion, "
                "and quarterly incident response tabletop simulations."
            )
        elif level == "Medium":
            summary_paragraphs.append(
                f"{company} maintains a moderate security posture (Risk Score: {score}/100, {level} Risk). "
                f"While foundational controls exist, notable security gaps expose organizational assets in the {industry} environment."
            )
            summary_paragraphs.append(
                "Immediate attention should be directed toward closing high-priority gaps such as Multi-Factor Authentication (MFA) "
                "enforcement and implementing automated encrypted backups to prevent operational disruptions."
            )
        elif level == "High":
            summary_paragraphs.append(
                f"CRITICAL DEFENSE NOTICE: {company} currently exhibits a HIGH cybersecurity risk profile "
                f"with a score of {score}/100. Key structural vulnerabilities leave critical infrastructure vulnerable to ransomware, "
                "credential harvesting, and unauthorized data exfiltration."
            )
            summary_paragraphs.append(
                f"Operating with {employees} employees in the {industry} sector without comprehensive access and data controls "
                "significantly elevates compliance penalties and business disruption risks. Urgent remediation is required."
            )
        else: # Critical
            summary_paragraphs.append(
                f"URGENT SECURITY ALERT: {company} is operating at CRITICAL RISK ({score}/100). "
                "Multiple core security pillars—including authentication, firewalling, and backup redundancy—are currently deficient or unmonitored."
            )
            summary_paragraphs.append(
                "The organization is highly susceptible to immediate cyber attacks, ransomware lockouts, and regulatory non-compliance. "
                "Remediation must begin immediately starting with emergency access controls and perimeter defense hardening."
            )

        explanation = " ".join(summary_paragraphs)

        # Build prioritized actionable recommendations based on detected risk factors
        recommendations: List[Dict[str, Any]] = []

        # Check MFA
        if any(b.get("factor", "").startswith("Multi-Factor") for b in breakdown):
            recommendations.append({
                "title": "Mandate Multi-Factor Authentication (MFA) Enterprise-Wide",
                "priority": "High",
                "category": "Identity & Access Management",
                "description": "Enforce mandatory FIDO2 or authenticator app-based MFA across all remote access points, cloud services, and email logins.",
                "action_steps": [
                    "Deploy mandatory MFA policy in identity provider (e.g., Okta, Entra ID, Google Workspace).",
                    "Block legacy authentication protocols (IMAP/POP3/Basic Auth).",
                    "Distribute hardware security keys for administrative accounts."
                ]
            })

        # Check Firewall
        if any("Firewall" in b.get("factor", "") for b in breakdown):
            recommendations.append({
                "title": "Configure Next-Generation Firewall (NGFW) & Network Segmentation",
                "priority": "High",
                "category": "Perimeter Defense",
                "description": "Implement stateful firewall protection, default-deny ingress rules, and network micro-segmentation.",
                "action_steps": [
                    "Deploy hardware/cloud firewall with deep packet inspection.",
                    "Isolate guest Wi-Fi and IoT devices from internal corporate subnet.",
                    "Audit open ports and close unnecessary external listeners."
                ]
            })

        # Check Backup
        if any("Backup" in b.get("factor", "") for b in breakdown):
            recommendations.append({
                "title": "Implement 3-2-1 Automated Immutable Backup Strategy",
                "priority": "High",
                "category": "Data Resilience",
                "description": "Maintain 3 copies of business data on 2 different media types, with at least 1 offsite/immutable copy.",
                "action_steps": [
                    "Schedule automated daily incremental and weekly full backups.",
                    "Store immutable air-gapped snapshots resistant to ransomware deletion.",
                    "Conduct quarterly backup restoration drill to test recovery RTO/RPO objectives."
                ]
            })

        # Check Password Policy
        if any("Password" in b.get("factor", "") for b in breakdown):
            recommendations.append({
                "title": "Upgrade Password Policy & Mandate Enterprise Password Manager",
                "priority": "Medium",
                "category": "Access Control",
                "description": "Enforce minimum 16-character passphrases and equip staff with enterprise password vaulting software.",
                "action_steps": [
                    "Deploy enterprise password manager (e.g., 1Password, Bitwarden).",
                    "Disallow common passwords against breach database lists (HaveIBeenPwned API).",
                    "Eliminate mandatory arbitrary 90-day password expiration to reduce weak variations."
                ]
            })

        # Check Training
        if any("Training" in b.get("factor", "") for b in breakdown):
            recommendations.append({
                "title": "Launch Monthly Security Awareness & Simulated Phishing Programs",
                "priority": "Medium",
                "category": "Human Risk Management",
                "description": "Educate staff on social engineering, spear-phishing, and safe browsing habits.",
                "action_steps": [
                    "Enroll employees in interactive micro-training security modules.",
                    "Run monthly simulated phishing campaigns to measure vulnerability rate.",
                    "Establish clear one-click phishing report button in email clients."
                ]
            })

        # Check Public Wi-Fi / Remote access
        if any("Public Wi-Fi" in b.get("factor", "") for b in breakdown):
            recommendations.append({
                "title": "Enforce Always-On Corporate VPN / Zero-Trust Network Access (ZTNA)",
                "priority": "Medium",
                "category": "Endpoint Security",
                "description": "Secure remote and mobile worker internet traffic when connecting from untrusted networks.",
                "action_steps": [
                    "Deploy managed VPN or ZTNA client with automatic connection rules on public Wi-Fi.",
                    "Ensure full transport layer encryption (TLS 1.3/WireGuard).",
                    "Disable automatic connection to open Wi-Fi access points on company laptops."
                ]
            })

        # If recommendations are few (e.g. low risk), add proactive continuous monitoring suggestions
        if len(recommendations) < 3:
            recommendations.append({
                "title": "Establish Continuous Vulnerability Scanning & Patch Management",
                "priority": "Low",
                "category": "Vulnerability Management",
                "description": "Automate routine scanning of web applications and servers to detect emerging CVE vulnerabilities.",
                "action_steps": [
                    "Schedule weekly automated vulnerability scans.",
                    "Apply critical vendor security patches within 72 hours of publication.",
                    "Maintain an active inventory of hardware and software assets."
                ]
            })
            recommendations.append({
                "title": "Implement Centralized Log Management & SIEM",
                "priority": "Low",
                "category": "Detection & Response",
                "description": "Aggregate log telemetry across cloud services, firewalls, and endpoints for threat detection.",
                "action_steps": [
                    "Enable audit logging on cloud environments and domain controllers.",
                    "Configure automated security alerts for suspicious admin logins.",
                    "Retain security logs for a minimum of 90 days for forensic investigation."
                ]
            })

        return {
            "explanation": explanation,
            "recommendations": recommendations
        }


class OpenAIAPIService(AIServiceInterface):
    """
    OpenAI API Service Provider.
    Can be enabled by setting OPENAI_API_KEY environment variable.
    Demonstrates true drop-in replacement capability.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key

    def generate_advice(self, input_data: Dict[str, Any], risk_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends assessment details to OpenAI API (e.g., gpt-3.5-turbo or gpt-4o)
        and parses structured JSON response.
        Falls back gracefully to LocalRuleAIService if API call fails or package is absent.
        """
        try:
            # Dynamically import openai to avoid hard failure if not installed
            import openai

            client = openai.OpenAI(api_key=self.api_key)
            prompt = (
                f"You are a Senior CISO and AI Cybersecurity Advisor. Analyze the following organizational risk assessment:\n"
                f"Company: {input_data.get('company_name')}\n"
                f"Industry: {input_data.get('industry')}\n"
                f"Employees: {input_data.get('employees')}\n"
                f"Calculated Risk Score: {risk_result.get('score')}/100 ({risk_result.get('level')} Risk)\n"
                f"Risk Factor Breakdown: {json.dumps(risk_result.get('breakdown', []))}\n\n"
                f"Return a strict JSON object with format:\n"
                f"{{\n"
                f'  "explanation": "Executive summary paragraph explaining posture and risks.",\n'
                f'  "recommendations": [\n'
                f'    {{\n'
                f'      "title": "Action title",\n'
                f'      "priority": "High" | "Medium" | "Low",\n'
                f'      "category": "Category name",\n'
                f'      "description": "Why this matters",\n'
                f'      "action_steps": ["step 1", "step 2"]\n'
                f'    }}\n'
                f'  ]\n'
                f"}}\n"
            )

            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a professional cybersecurity risk advisor."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )

            result_json = json.loads(response.choices[0].message.content)
            return result_json
        except Exception as e:
            logger.warning(f"OpenAI API call failed or unavailable ({e}). Falling back to local AI advisory service.")
            fallback = LocalRuleAIService()
            return fallback.generate_advice(input_data, risk_result)


def get_ai_service() -> AIServiceInterface:
    """
    Factory function returning the configured AI service provider.
    Checks environment for OPENAI_API_KEY.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    if openai_key and openai_key != "your_openai_api_key_here":
        logger.info("Initializing OpenAI API Service Provider.")
        return OpenAIAPIService(api_key=openai_key)
    
    logger.info("Initializing Local Rule-Based AI Advisory Engine.")
    return LocalRuleAIService()


def generate_assessment_advice(input_data: Dict[str, Any], risk_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to invoke AI advisory generation.
    """
    service = get_ai_service()
    return service.generate_advice(input_data, risk_result)
