import requests
import time
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class OWASPService:
    def __init__(self):
        self.base_url = "http://localhost:8080"
        self.api_key = "1234"
        self.headers = {
            "X-ZAP-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def start_scan(self, target_url: str) -> Dict[str, Any]:
        """Start a new ZAP scan on the target URL."""
        try:
            start_time = time.time()
            
            # First, start the spider scan
            logger.info(f"Starting spider scan for {target_url}")
            spider_response = requests.get(
                f"{self.base_url}/JSON/spider/action/scan/",
                params={"url": target_url},
                headers=self.headers
            )
            spider_response.raise_for_status()
            spider_id = spider_response.json().get("scan")

            # Wait for spider to complete
            while True:
                spider_status = requests.get(
                    f"{self.base_url}/JSON/spider/view/status/",
                    params={"scanId": spider_id},
                    headers=self.headers
                )
                status = spider_status.json().get("status")
                if status == "100":
                    break
                time.sleep(5)

            # Now start the active scan
            logger.info(f"Starting active scan for {target_url}")
            ascan_response = requests.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={"url": target_url, "recurse": "true"},
                headers=self.headers
            )
            ascan_response.raise_for_status()
            scan_id = ascan_response.json().get("scan")

            # Wait for active scan to complete
            while True:
                status_response = requests.get(
                    f"{self.base_url}/JSON/ascan/view/status/",
                    params={"scanId": scan_id},
                    headers=self.headers
                )
                status = status_response.json().get("status")
                if status == "100":
                    break
                time.sleep(5)

            # Get scan results
            alerts_response = requests.get(
                f"{self.base_url}/JSON/core/view/alerts/",
                params={"baseurl": target_url},
                headers=self.headers
            )
            alerts = alerts_response.json().get("alerts", [])

            # Get scan report
            report_response = requests.get(
                f"{self.base_url}/OTHER/core/other/htmlreport/",
                params={"apikey": self.api_key},
                headers=self.headers
            )
            report_html = report_response.text

            # Calculate severity counts
            severity_count = {
                "ERROR": len([a for a in alerts if a.get("risk") == "High"]),
                "WARNING": len([a for a in alerts if a.get("risk") == "Medium"]),
                "INFO": len([a for a in alerts if a.get("risk") == "Low"]) + len([a for a in alerts if a.get("risk") == "Info"])
            }

            # Calculate security score (0-10)
            total_alerts = len(alerts)
            if total_alerts == 0:
                security_score = 10
            else:
                # Weight high risk alerts more heavily
                weighted_score = (
                    severity_count["ERROR"] * 3 +  # High risk counts as 3
                    severity_count["WARNING"] * 2 +  # Medium risk counts as 2
                    severity_count["INFO"]  # Low/Info risk counts as 1
                )
                # Convert to 0-10 scale, where 0 is worst and 10 is best
                security_score = max(0, round(10 - (weighted_score / total_alerts)))

            scan_duration = time.time() - start_time

            # Format vulnerabilities to match Semgrep format
            vulnerabilities = []
            for alert in alerts:
                vulnerability = {
                    "check_id": f"zap-{alert.get('pluginId', 'unknown')}",
                    "path": alert.get("url", ""),
                    "start": {"line": 0},
                    "end": {"line": 0},
                    "extra": {
                        "message": alert.get("name", ""),
                        "severity": "ERROR" if alert.get("risk") == "High" else "WARNING" if alert.get("risk") == "Medium" else "INFO",
                        "description": alert.get("description", ""),
                        "solution": alert.get("solution", ""),
                        "reference": alert.get("reference", ""),
                        "evidence": alert.get("evidence", ""),
                        "confidence": alert.get("confidence", "")
                    }
                }
                vulnerabilities.append(vulnerability)

            return {
                "scan_id": scan_id,
                "file_name": f"dast_scan_{target_url.replace('://', '_').replace('/', '_')}",
                "scan_timestamp": datetime.utcnow().isoformat(),
                "vulnerabilities": vulnerabilities,
                "severity_count": severity_count,
                "total_vulnerabilities": total_alerts,
                "security_score": security_score,
                "scan_status": "completed",
                "scan_duration": scan_duration,
                "scan_metadata": {
                    "tool_version": "zap-latest",
                    "scan_type": "dast",
                    "target_url": target_url,
                    "report_html": report_html
                }
            }

        except Exception as e:
            logger.error(f"Error in OWASP ZAP scan: {str(e)}")
            raise Exception(f"Failed to complete OWASP ZAP scan: {str(e)}")

    def calculate_security_score(self, alerts: List[Dict]) -> float:
        """Calculate security score based on alerts."""
        if not alerts:
            return 10  # Perfect score if no vulnerabilities found
        
        # Define weights for different risk levels
        weights = {
            'High': 1.0,
            'Medium': 0.5,
            'Low': 0.1,
            'Info': 0.01
        }
        
        # Count alerts by risk level
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Info')
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        # Calculate weighted score
        total_weight = sum(risk_counts.values())
        if total_weight == 0:
            return 10
        
        weighted_score = sum(
            risk_counts[risk] * weights[risk]
            for risk in risk_counts
        )
        
        # Calculate final score (10 - weighted average) and round to whole number
        score = round(10 - (weighted_score / total_weight))
        return max(0, min(10, score))

owasp_service = OWASPService() 