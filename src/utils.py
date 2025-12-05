"""
Utilities for BigQuery project
"""
import json
from datetime import datetime, date
from typing import Any, Dict

def save_results_to_file(df, filename: str, format: str = 'csv'):
    """
    Save results to file
    
    Args:
        df: Pandas DataFrame
        filename: Output filename
        format: Output format ('csv', 'json', 'excel')
    """
    try:
        if format.lower() == 'csv':
            df.to_csv(filename, index=False)
        elif format.lower() == 'json':
            df.to_json(filename, orient='records', indent=2)
        elif format.lower() == 'excel':
            df.to_excel(filename, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"Results saved to {filename}")
        
    except Exception as e:
        print(f"Error saving results: {e}")

class BigQueryHelper:
    """Helper class for common BigQuery operations"""
    
    @staticmethod
    def build_where_clause(filters: Dict[str, Any]) -> str:
        """
        Build WHERE clause from filters dictionary
        
        Args:
            filters: Dictionary of filters {column: value}
            
        Returns:
            str: Formatted WHERE clause
        """
        if not filters:
            return ""
        
        conditions = []
        for column, value in filters.items():
            if isinstance(value, str):
                conditions.append(f"{column} = '{value}'")
            elif isinstance(value, (int, float)):
                conditions.append(f"{column} = {value}")
            elif isinstance(value, list):
                if all(isinstance(v, str) for v in value):
                    values = "', '".join(value)
                    conditions.append(f"{column} IN ('{values}')")
                else:
                    values = ", ".join(str(v) for v in value)
                    conditions.append(f"{column} IN ({values})")
        
        return "WHERE " + " AND ".join(conditions) if conditions else ""
    
    @staticmethod
    def estimate_query_cost(query: str, client) -> Dict[str, Any]:
        """
        Estimate query cost before execution
        
        Args:
            query: SQL query
            client: BigQuery client
            
        Returns:
            Dict with estimation information
        """
        try:
            from google.cloud import bigquery
            
            job_config = bigquery.QueryJobConfig()
            job_config.dry_run = True
            job_config.use_query_cache = False
            
            query_job = client.query(query, job_config=job_config)
            
            # Approximate cost calculation (5$ per TB in 2024)
            bytes_processed = query_job.total_bytes_processed
            cost_estimate = (bytes_processed / (1024**4)) * 5  # Cost in USD
            
            return {
                'bytes_processed': bytes_processed,
                'gb_processed': bytes_processed / (1024**3),
                'cost_estimate_usd': round(cost_estimate, 4),
                'query_valid': True
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'query_valid': False
            }