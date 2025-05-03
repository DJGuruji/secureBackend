import subprocess
import json
import logging
from typing import List, Dict
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

def run_semgrep(file_path: str) -> List[Dict]:
    """Run semgrep on the given file or directory and return the results."""
    try:
        logger.info(f"Running semgrep on {file_path}")
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        results = json.loads(result.stdout)
        
        if "results" in results:
            logger.info(f"Found {len(results['results'])} vulnerabilities")
            return results["results"]
        logger.info("No vulnerabilities found")
        return []
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep error: {e.stderr}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Semgrep scan failed: {e.stderr}"
        )
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse semgrep output: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse semgrep output"
        )
    except Exception as e:
        logger.error(f"Unexpected error in semgrep scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error during scan"
        ) 