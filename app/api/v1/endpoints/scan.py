from fastapi import APIRouter, UploadFile, File, HTTPException, status
import os
import tempfile
import shutil
import logging
from typing import Dict, Any
from app.services.semgrep_service import run_semgrep
from app.services.supabase_service import store_scan_results
from app.core.security import calculate_security_score, count_severities
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()

def process_upload(file: UploadFile) -> Dict[str, Any]:
    """Process the uploaded file and return vulnerability results."""
    try:
        logger.info(f"Processing file: {file.filename}")
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
                
            # Calculate metrics
            severity_count = count_severities(vulnerabilities)
            total_vulnerabilities = len(vulnerabilities)
            security_score = calculate_security_score(vulnerabilities)
            
            return {
                "vulnerabilities": vulnerabilities,
                "severity_count": severity_count,
                "total_vulnerabilities": total_vulnerabilities,
                "security_score": security_score
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