from fastapi import HTTPException, status
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

def calculate_security_score(vulnerabilities: List[Dict]) -> int:
    """Calculate security score based on vulnerabilities."""
    try:
        # Risk severity weights from supabase_service.py
        risk_weights = {
            "ERROR": 1.0,
            "WARNING": 0.7,
            "INFO": 0.3
        }
        
        # Calculate weighted score
        total_weight = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO").upper()
            weight = risk_weights.get(severity, 0.3)  # Default to INFO weight if unknown
            total_weight += weight
        
        # Normalize score to 0-10 range
        # More vulnerabilities = lower score
        # Higher severity = lower score
        max_possible_weight = len(vulnerabilities) * 1.0  # If all were ERROR
        if max_possible_weight == 0:
            return 10  # Perfect score if no vulnerabilities
            
        normalized_score = 1 - (total_weight / max_possible_weight)
        security_score = int(round(normalized_score * 10))
        
        return max(0, min(10, security_score))  # Ensure score is between 0 and 10
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