from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import tempfile
import shutil
import subprocess
import json
import logging
from typing import List, Dict
from pathlib import Path
from datetime import datetime
from supabase import create_client
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Validate environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase credentials. Please set SUPABASE_URL and SUPABASE_KEY in .env file")

app = FastAPI()

# Initialize Supabase client
try:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("Successfully connected to Supabase")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory if it doesn't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

def calculate_security_score(vulnerabilities: List[Dict]) -> int:
    """Calculate security score based on vulnerabilities."""
    severe_count = len([v for v in vulnerabilities if v.get("extra", {}).get("severity") in ["ERROR", "WARNING"]])
    return max(0, 10 - severe_count)

def count_severities(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """Count vulnerabilities by severity."""
    severities = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("extra", {}).get("severity", "INFO")
        severities[severity] = severities.get(severity, 0) + 1
    return severities

def run_semgrep(file_path: str) -> List[dict]:
    """Run semgrep on the given file or directory and return the results."""
    try:
        logger.info(f"Running semgrep on {file_path}")
        # Run semgrep with auto config to get relevant rules for the project
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the results
        results = json.loads(result.stdout)
        
        # Filter only severe vulnerabilities (error and warning)
        if "results" in results:
            logger.info(f"Found {len(results['results'])} vulnerabilities")
            severe_results = [
                result for result in results["results"]
                if result.get("extra", {}).get("severity") in ["ERROR", "WARNING"]
            ]
            return severe_results
        logger.info("No vulnerabilities found")
        return []
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep error: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse semgrep output: {str(e)}")
        return []

def process_upload(file: UploadFile) -> List[dict]:
    """Process the uploaded file and return vulnerability results."""
    try:
        logger.info(f"Processing file: {file.filename}")
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, file.filename)
            
            # Save the uploaded file
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # If it's a zip file, extract it
            if file.filename.endswith('.zip'):
                logger.info("Extracting zip file")
                shutil.unpack_archive(file_path, temp_dir)
                # Run semgrep on the extracted directory
                return run_semgrep(temp_dir)
            else:
                # Run semgrep on the single file
                return run_semgrep(file_path)
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Handle file upload, run SAST scan, and store results in Supabase."""
    try:
        logger.info(f"Starting upload process for file: {file.filename}")
        
        # Run SAST scan
        vulnerabilities = process_upload(file)
        
        # Calculate metrics
        severity_count = count_severities(vulnerabilities)
        total_vulnerabilities = len(vulnerabilities)
        security_score = calculate_security_score(vulnerabilities)
        
        logger.info(f"Scan completed. Found {total_vulnerabilities} vulnerabilities")
        
        # Store results in Supabase
        data = {
            "file_name": file.filename,
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total_vulnerabilities,
            "security_score": security_score
        }
        
        logger.info("Storing results in Supabase")
        result = supabase.table("sast").insert(data).execute()
        
        if not result.data:
            logger.error("Failed to store results in Supabase: No data returned")
            raise HTTPException(status_code=500, detail="Failed to store results in database")
            
        logger.info("Successfully stored results in Supabase")
        return {
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total_vulnerabilities,
            "security_score": security_score,
            "scan_id": result.data[0]["id"]
        }
        
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"status": "API is running"}
