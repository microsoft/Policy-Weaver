"""
Configuration module for BigQuery application
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration"""
    
    # Google Cloud configuration
    GOOGLE_APPLICATION_CREDENTIALS = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
    PROJECT_ID = os.getenv('PROJECT_ID')
    DATASET_ID = os.getenv('DATASET_ID')
    
    # BigQuery configuration
    BQ_LOCATION = os.getenv('BQ_LOCATION', 'US')
    BQ_JOB_TIMEOUT = int(os.getenv('BQ_JOB_TIMEOUT', 300))
    
    @classmethod
    def validate(cls):
        """Validate that all required variables are defined"""
        required_vars = ['PROJECT_ID', 'DATASET_ID']
        missing_vars = [var for var in required_vars if not getattr(cls, var)]
        
        if missing_vars:
            raise ValueError(f"Missing environment variables: {', '.join(missing_vars)}")
        
        return True