"""
BigQuery client for database operations
"""
from google.cloud import bigquery
from google.oauth2 import service_account
import pandas as pd
import logging
from typing import Optional, Dict, Any, List
from config import Config

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BigQueryClient:
    """Client to interact with Google BigQuery"""
    
    def __init__(self):
        """Initialize BigQuery client"""
        try:
            # Validate configuration
            Config.validate()
            
            # Initialize BigQuery client
            if Config.GOOGLE_APPLICATION_CREDENTIALS:
                # Use credentials file
                credentials = service_account.Credentials.from_service_account_file(
                    Config.GOOGLE_APPLICATION_CREDENTIALS
                )
                self.client = bigquery.Client(
                    credentials=credentials,
                    project=Config.PROJECT_ID
                )
            else:
                # Use default credentials (ADC)
                self.client = bigquery.Client(project=Config.PROJECT_ID)
                
            logger.info(f"BigQuery client initialized for project: {Config.PROJECT_ID}")
            
        except Exception as e:
            logger.error(f"Error initializing BigQuery client: {e}")
            raise
    
    def execute_query(self, query: str, parameters: Optional[List] = None) -> pd.DataFrame:
        """
        Execute a BigQuery query and return results in a DataFrame
        
        Args:
            query (str): SQL query to execute
            parameters (Optional[List]): Parameters for the query
            
        Returns:
            pd.DataFrame: Query results
        """
        try:
            logger.info("Executing BigQuery query...")
            
            # Job configuration
            job_config = bigquery.QueryJobConfig()
            if parameters:
                job_config.query_parameters = parameters
            
            # Execute query
            query_job = self.client.query(query, job_config=job_config)
            
            # Wait for results with timeout
            results = query_job.result(timeout=Config.BQ_JOB_TIMEOUT)
            
            # Convert to DataFrame
            df = results.to_dataframe()
            
            logger.info(f"Query executed successfully. {len(df)} rows returned.")
            return df
            
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            raise
    
    def get_table_info(self, table_id: str) -> Dict[str, Any]:
        """
        Get information about a table
        
        Args:
            table_id (str): Table ID (format: dataset.table)
            
        Returns:
            Dict[str, Any]: Table information
        """
        try:
            full_table_id = f"{Config.PROJECT_ID}.{table_id}"
            table = self.client.get_table(full_table_id)
            
            return {
                "table_id": table.table_id,
                "dataset_id": table.dataset_id,
                "project": table.project,
                "created": table.created,
                "modified": table.modified,
                "num_rows": table.num_rows,
                "num_bytes": table.num_bytes,
                "schema": [{"name": field.name, "type": field.field_type, "mode": field.mode} 
                          for field in table.schema]
            }
            
        except Exception as e:
            logger.error(f"Error retrieving table information: {e}")
            raise
    
    def list_tables(self, dataset_id: Optional[str] = None) -> List[str]:
        """
        List tables in a dataset
        
        Args:
            dataset_id (Optional[str]): Dataset ID (uses config default if not provided)
            
        Returns:
            List[str]: List of table names
        """
        try:
            dataset_id = dataset_id or Config.DATASET_ID
            dataset_ref = self.client.dataset(dataset_id)
            tables = list(self.client.list_tables(dataset_ref))
            
            table_names = [table.table_id for table in tables]
            logger.info(f"Found {len(table_names)} tables in dataset {dataset_id}")
            
            return table_names
            
        except Exception as e:
            logger.error(f"Error listing tables: {e}")
            raise
    
    def upload_dataframe(self, df: pd.DataFrame, table_id: str, 
                        write_disposition: str = "WRITE_TRUNCATE") -> None:
        """
        Upload a DataFrame to BigQuery
        
        Args:
            df (pd.DataFrame): DataFrame to upload
            table_id (str): Destination table ID
            write_disposition (str): Write mode (WRITE_TRUNCATE, WRITE_APPEND, WRITE_EMPTY)
        """
        try:
            full_table_id = f"{Config.PROJECT_ID}.{Config.DATASET_ID}.{table_id}"
            
            job_config = bigquery.LoadJobConfig()
            job_config.write_disposition = write_disposition
            job_config.autodetect = True
            
            job = self.client.load_table_from_dataframe(
                df, full_table_id, job_config=job_config
            )
            
            job.result()  # Wait for job completion
            
            logger.info(f"DataFrame uploaded successfully to {full_table_id}")
            
        except Exception as e:
            logger.error(f"Error uploading DataFrame: {e}")
            raise
    
    def get_table_security_info(self, table_id: str) -> Dict[str, Any]:
        """
        Get security and access information about a table
        
        Args:
            table_id (str): Table ID (format: dataset.table)
            
        Returns:
            Dict[str, Any]: Security information including access controls
        """
        try:
            full_table_id = f"{Config.PROJECT_ID}.{table_id}"
            table = self.client.get_table(full_table_id)
            
            security_info = {
                "table_id": table.table_id,
                "dataset_id": table.dataset_id,
                "project": table.project,
                "encryption_configuration": None,
                "access_entries": [],
                "require_partition_filter": getattr(table, 'require_partition_filter', False),
                "labels": dict(table.labels) if table.labels else {}
            }
            
            # Get encryption configuration if available
            if hasattr(table, 'encryption_configuration') and table.encryption_configuration:
                security_info["encryption_configuration"] = {
                    "kms_key_name": table.encryption_configuration.kms_key_name
                }
            
            # Get dataset-level access controls
            dataset_ref = self.client.dataset(table.dataset_id)
            dataset = self.client.get_dataset(dataset_ref)
            
            if dataset.access_entries:
                for entry in dataset.access_entries:
                    access_info = {
                        "role": entry.role,
                        "entity_type": entry.entity_type,
                        "entity_id": entry.entity_id
                    }
                    
                    # Add specific entity information based on type
                    if entry.entity_type == "userByEmail":
                        access_info["user_email"] = entry.entity_id
                    elif entry.entity_type == "groupByEmail":
                        access_info["group_email"] = entry.entity_id
                    elif entry.entity_type == "domain":
                        access_info["domain"] = entry.entity_id
                    elif entry.entity_type == "specialGroup":
                        access_info["special_group"] = entry.entity_id
                    elif entry.entity_type == "serviceAccount":
                        access_info["service_account"] = entry.entity_id
                    elif entry.entity_type == "view":
                        access_info["authorized_view"] = entry.entity_id
                    elif entry.entity_type == "routine":
                        access_info["authorized_routine"] = entry.entity_id
                        
                    security_info["access_entries"].append(access_info)
            
            logger.info(f"Retrieved security info for table {full_table_id}")
            return security_info
            
        except Exception as e:
            logger.error(f"Error retrieving table security info: {e}")
            raise
    
    def get_dataset_security_info(self, dataset_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get security information about a dataset
        
        Args:
            dataset_id (Optional[str]): Dataset ID (uses config default if not provided)
            
        Returns:
            Dict[str, Any]: Dataset security information
        """
        try:
            dataset_id = dataset_id or Config.DATASET_ID
            dataset_ref = self.client.dataset(dataset_id)
            dataset = self.client.get_dataset(dataset_ref)
            
            security_info = {
                "dataset_id": dataset.dataset_id,
                "project": dataset.project,
                "location": dataset.location,
                "default_encryption_configuration": None,
                "access_entries": [],
                "labels": dict(dataset.labels) if dataset.labels else {},
                "default_table_expiration_ms": dataset.default_table_expiration_ms,
                "default_partition_expiration_ms": getattr(dataset, 'default_partition_expiration_ms', None)
            }
            
            # Get default encryption configuration
            if hasattr(dataset, 'default_encryption_configuration') and dataset.default_encryption_configuration:
                security_info["default_encryption_configuration"] = {
                    "kms_key_name": dataset.default_encryption_configuration.kms_key_name
                }
            
            # Get access entries
            if dataset.access_entries:
                for entry in dataset.access_entries:
                    access_info = {
                        "role": entry.role,
                        "entity_type": entry.entity_type,
                        "entity_id": entry.entity_id
                    }
                    security_info["access_entries"].append(access_info)
            
            logger.info(f"Retrieved security info for dataset {dataset_id}")
            return security_info
            
        except Exception as e:
            logger.error(f"Error retrieving dataset security info: {e}")
            raise
    
    def get_table_security_tags(self, table_id: str) -> Dict[str, Any]:
        """
        Get security tags (CLS/RLS) and policy information about a table
        
        Args:
            table_id (str): Table ID (format: dataset.table)
            
        Returns:
            Dict[str, Any]: Security tags and policy information
        """
        try:
            full_table_id = f"{Config.PROJECT_ID}.{table_id}"
            table = self.client.get_table(full_table_id)
            
            tags_info = {
                "table_id": table.table_id,
                "dataset_id": table.dataset_id,
                "project": table.project,
                "column_security": [],
                "row_access_policies": [],
                "policy_tags": {},
                "has_column_level_security": False,
                "has_row_level_security": False
            }
            
            # Check for column-level security (policy tags)
            if table.schema:
                for field in table.schema:
                    column_info = {
                        "name": field.name,
                        "type": field.field_type,
                        "mode": field.mode,
                        "policy_tags": []
                    }
                    
                    # Check if field has policy tags (CLS)
                    if hasattr(field, 'policy_tags') and field.policy_tags:
                        column_info["policy_tags"] = list(field.policy_tags.names) if field.policy_tags.names else []
                        tags_info["has_column_level_security"] = True
                    
                    if column_info["policy_tags"]:
                        tags_info["column_security"].append(column_info)
            
            # Try to get row access policies using INFORMATION_SCHEMA
            try:
                # First check if INFORMATION_SCHEMA is available
                test_query = f"""
                SELECT schema_name 
                FROM `{Config.PROJECT_ID}.{Config.DATASET_ID}.INFORMATION_SCHEMA.SCHEMATA` 
                LIMIT 1
                """
                job_config = bigquery.QueryJobConfig()
                test_job = self.client.query(test_query, job_config=job_config)
                test_job.result()
                
                # If test passes, query for RLS policies
                rls_query = f"""
                SELECT 
                    row_access_policy_name,
                    grantees,
                    filter_predicate
                FROM `{Config.PROJECT_ID}.{Config.DATASET_ID}.INFORMATION_SCHEMA.ROW_ACCESS_POLICIES`
                WHERE table_name = '{table.table_id}'
                """
                
                query_job = self.client.query(rls_query, job_config=job_config)
                rls_results = query_job.result()
                
                for row in rls_results:
                    policy_info = {
                        "policy_name": row.row_access_policy_name,
                        "grantees": list(row.grantees) if row.grantees else [],
                        "filter_predicate": row.filter_predicate
                    }
                    tags_info["row_access_policies"].append(policy_info)
                    tags_info["has_row_level_security"] = True
                
                tags_info["information_schema_available"] = True
                    
            except Exception as rls_error:
                tags_info["information_schema_available"] = False
                tags_info["information_schema_error"] = "INFORMATION_SCHEMA not available for this dataset"
            
            # Try to get policy tag information (only if INFORMATION_SCHEMA is available)
            if tags_info.get("information_schema_available", False):
                try:
                    policy_query = f"""
                    SELECT 
                        column_name,
                        policy_tags
                    FROM `{Config.PROJECT_ID}.{Config.DATASET_ID}.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`
                    WHERE table_name = '{table.table_id}' 
                    AND policy_tags IS NOT NULL
                    """
                    
                    job_config = bigquery.QueryJobConfig()
                    query_job = self.client.query(policy_query, job_config=job_config)
                    policy_results = query_job.result()
                    
                    for row in policy_results:
                        if row.policy_tags:
                            tags_info["policy_tags"][row.column_name] = list(row.policy_tags)
                            tags_info["has_column_level_security"] = True
                            
                except Exception as policy_error:
                    tags_info["policy_query_error"] = f"Error querying policy tags: {str(policy_error)}"
            
            logger.info(f"Retrieved security tags info for table {full_table_id}")
            return tags_info
            
        except Exception as e:
            logger.error(f"Error retrieving table security tags info: {e}")
            raise