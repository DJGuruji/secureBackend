from supabase import create_client
from typing import Dict, Any
import logging
from fastapi import HTTPException, status
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Initialize Supabase client
try:
    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    logger.info("Successfully connected to Supabase")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

def store_scan_results(data: Dict[str, Any]) -> Dict[str, Any]:
    """Store scan results in Supabase and return the inserted record."""
    try:
        logger.info("Storing results in Supabase")
        result = supabase.table("sast").insert(data).execute()
        
        if not result.data:
            logger.error("Failed to store results in Supabase: No data returned")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store results in database"
            )
            
        logger.info("Successfully stored results in Supabase")
        return result.data[0]
        
    except Exception as e:
        logger.error(f"Error storing results in Supabase: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        ) 