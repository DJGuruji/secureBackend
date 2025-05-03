from fastapi import APIRouter, UploadFile, File, HTTPException, status
import os
import tempfile
import shutil
import logging
import time
from typing import Dict, Any
from app.services.semgrep_service import run_semgrep
from app.services.supabase_service import store_scan_results, get_scan_history, get_scan_by_id
from app.core.security import calculate_security_score, count_severities
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()

def process_upload(file: UploadFile) -> Dict[str, Any]:
    """Process the uploaded file and return vulnerability results."""
    try:
        logger.info(f"Processing file: {file.filename}")
        start_time = time.time()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, file.filename)
            
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            if file.filename.endswith('.zip'):
                logger.info("Extracting zip file")
                shutil.unpack_archive(file_path, temp_dir)
                vulnerabilities = run_semgrep(temp_dir)
            else:
                vulnerabilities = run_semgrep(file_path)

            # Ensure top-level severity field for each vulnerability
            for vuln in vulnerabilities:
                vuln['severity'] = vuln.get('extra', {}).get('severity', 'info')

            # Calculate metrics
            severity_count = count_severities(vulnerabilities)
            total_vulnerabilities = len(vulnerabilities)
            security_score = calculate_security_score(vulnerabilities)
            
            scan_duration = time.time() - start_time
            
            return {
                "vulnerabilities": vulnerabilities,
                "severity_count": severity_count,
                "total_vulnerabilities": total_vulnerabilities,
                "security_score": security_score,
                "scan_duration": scan_duration,
                "tool_version": "semgrep-latest",
                "environment": os.getenv("ENVIRONMENT", "development")
            }
            
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Handle file upload, run SAST scan, and store results in Supabase."""
    try:
        logger.info(f"Starting upload process for file: {file.filename}")
        
        # Process file and get scan results
        scan_results = process_upload(file)
        
        # Prepare data for Supabase
        data = {
            "file_name": file.filename,
            **scan_results
        }
        
        # Store results in Supabase
        stored_result = store_scan_results(data)
        
        return {
            **scan_results,
            "scan_id": stored_result["id"]
        }
        
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/history")
async def get_history(limit: int = 10, offset: int = 0):
    """Retrieve scan history with pagination."""
    try:
        return get_scan_history(limit, offset)
    except Exception as e:
        logger.error(f"Error retrieving scan history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Retrieve a specific scan by ID."""
    try:
        return get_scan_by_id(scan_id)
    except Exception as e:
        logger.error(f"Error retrieving scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 