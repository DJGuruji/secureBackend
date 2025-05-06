from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from app.api.v1.api import api_router
from app.core.config import get_settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load settings
settings = get_settings()

app = FastAPI(
    title="SecureEngine API",
    description="API for code vulnerability scanning",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"status": "API is running"}
