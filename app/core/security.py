from fastapi import HTTPException, status
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

def calculate_security_score(vulnerabilities: List[Dict]) -> int:
    """Calculate security score based on vulnerabilities."""
    try:
        # Point deductions for each severity level
        point_deductions = {
            "ERROR": 2.0,    # Most severe: -2 points each
            "WARNING": 1.0,  # Medium severity: -1 point each
            "INFO": 0.4      # Least severe: -0.4 points each
        }
        
        if not vulnerabilities:
            return 10  # Perfect score if no vulnerabilities
            
        # Calculate base score (starts at 10)
        base_score = 10.0
        
        # Deduct points based on severity
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO").upper()
            deduction = point_deductions.get(severity, 0.4)  # Default to INFO deduction if unknown
            base_score -= deduction
            
        # Ensure score is between 0 and 10
        security_score = max(0, min(10, base_score))
        
        return int(round(security_score))
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
            sev = vuln.get('severity', 'INFO').upper()
            severities[sev] = severities.get(sev, 0) + 1
        return severities
    except Exception as e:
        logger.error(f"Error counting severities: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error counting severities"
        ) 