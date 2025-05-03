from fastapi import HTTPException, status
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

def calculate_security_score(vulnerabilities: List[Dict]) -> int:
    """Calculate security score based on vulnerabilities."""
    try:
        severe_count = len([v for v in vulnerabilities if v.get("extra", {}).get("severity") in ["ERROR", "WARNING"]])
        return max(0, 10 - severe_count)
    except Exception as e:
        logger.error(f"Error calculating security score: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error calculating security score"
        )

def count_severities(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """Count vulnerabilities by severity."""
    try:
        severities = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("extra", {}).get("severity", "INFO")
            severities[severity] = severities.get(severity, 0) + 1
        return severities
    except Exception as e:
        logger.error(f"Error counting severities: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error counting severities"
        ) 