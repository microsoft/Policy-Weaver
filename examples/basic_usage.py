"""
Basic usage example of BigQuery client
"""
import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from bigquery_client import BigQueryClient
from queries import SIMPLE_COUNT_QUERY
from config import Config


def display_client_info():
    """Display BigQuery client initialization information"""
    print("=== BigQuery client initialized ===")
    print(f"Project: {Config.PROJECT_ID}")
    print(f"Dataset: {Config.DATASET_ID}")
    print()


def display_available_tables(bq_client: BigQueryClient):
    """Display list of available tables in the dataset"""
    print("=== Available tables ===")
    tables = bq_client.list_tables()
    for table in tables:
        print(f"- {table}")
    print()
    return tables


def example_count_rows(bq_client: BigQueryClient, table_name: str):
    """Example 1: Count rows in a table"""
    print(f"=== Example 1: Count rows in {table_name} ===")
    
    count_query = SIMPLE_COUNT_QUERY.format(
        project_id=Config.PROJECT_ID,
        dataset_id=Config.DATASET_ID,
        table_id=table_name
    )
    
    try:
        result_df = bq_client.execute_query(count_query)
        print(f"Total rows: {result_df.iloc[0]['total_rows']}")
    except Exception as e:
        print(f"Error counting rows: {e}")
    print()


def example_table_info(bq_client: BigQueryClient, table_name: str):
    """Example 2: Display table information"""
    print(f"=== Example 2: Information about table {table_name} ===")
    
    try:
        table_info = bq_client.get_table_info(f"{Config.DATASET_ID}.{table_name}")
        
        print(f"Number of rows: {table_info['num_rows']}")
        print(f"Size in bytes: {table_info['num_bytes']}")
        print(f"Created: {table_info['created']}")
        print(f"Modified: {table_info['modified']}")
        
        print("Schema:")
        schema_fields = table_info['schema'][:5]  # Show first 5 fields
        for field in schema_fields:
            print(f"  - {field['name']}: {field['type']} ({field['mode']})")
            
        if len(table_info['schema']) > 5:
            remaining_fields = len(table_info['schema']) - 5
            print(f"  ... and {remaining_fields} other fields")
            
    except Exception as e:
        print(f"Error retrieving table info: {e}")
    print()


def example_table_preview(bq_client: BigQueryClient, table_name: str):
    """Example 3: Preview table data"""
    print(f"=== Example 3: Preview of {table_name} ===")
    
    preview_query = f"""
    SELECT *
    FROM `{Config.PROJECT_ID}.{Config.DATASET_ID}.{table_name}`
    LIMIT 5
    """
    
    try:
        preview_df = bq_client.execute_query(preview_query)
        print("Data preview:")
        print(preview_df.to_string(index=False))
    except Exception as e:
        print(f"Error in preview: {e}")
    print()


def display_access_entry_details(entry: dict, index: int):
    """Display details for a single access control entry"""
    print(f"  {index}. Role: {entry['role']}")
    print(f"     Type: {entry['entity_type']}")
    print(f"     Entity: {entry['entity_id']}")
    
    # Show additional details based on entity type
    entity_details = {
        'user_email': 'User Email',
        'group_email': 'Group Email',
        'service_account': 'Service Account',
        'domain': 'Domain',
        'special_group': 'Special Group'
    }
    
    for key, label in entity_details.items():
        if key in entry:
            print(f"     {label}: {entry[key]}")
    print()


def example_table_tags(bq_client: BigQueryClient, tables: list):
    """Example 5: Display security tags (CLS/RLS) for all tables"""
    print("=== Example 5: Security tags (CLS/RLS) for all tables ===")
    
    for table_name in tables:
        print(f"\n--- Table: {table_name} ---")
        
        try:
            security_info = bq_client.get_table_security_info(f"{Config.DATASET_ID}.{table_name}")
            
            # Basic table information
            print(f"Project: {security_info['project']}")
            print(f"Dataset: {security_info['dataset_id']}")
            
            # Encryption configuration
            if security_info['encryption_configuration']:
                kms_key = security_info['encryption_configuration']['kms_key_name']
                print(f"Encryption: {kms_key}")
            else:
                print("Encryption: Default (Google-managed)")
            
            print(f"Require partition filter: {security_info['require_partition_filter']}")
            
            # Labels
            if security_info['labels']:
                print("Labels:")
                for key, value in security_info['labels'].items():
                    print(f"  - {key}: {value}")
            else:
                print("Labels: None")
            
            # Get and display security tags information
            tags_info = bq_client.get_table_security_tags(f"{Config.DATASET_ID}.{table_name}")
            
            # Check if INFORMATION_SCHEMA is available
            if not tags_info.get('information_schema_available', True):
                print("Security Tags Analysis: Not available")
                print("Reason: INFORMATION_SCHEMA not accessible for this dataset")
                print("Note: Advanced security features (CLS/RLS) cannot be verified")
            else:
                # Column-Level Security (CLS) information
                print(f"Column-Level Security (CLS): {'Yes' if tags_info['has_column_level_security'] else 'No'}")
                
                if tags_info['column_security']:
                    print("Protected Columns:")
                    for column in tags_info['column_security']:
                        print(f"  - {column['name']} ({column['type']})")
                        for policy_tag in column['policy_tags']:
                            print(f"    * Policy Tag: {policy_tag}")
                
                # Policy tags from INFORMATION_SCHEMA
                if tags_info['policy_tags']:
                    print("Policy Tags (INFORMATION_SCHEMA):")
                    for column_name, policy_list in tags_info['policy_tags'].items():
                        print(f"  - {column_name}: {', '.join(policy_list)}")
                elif tags_info.get('policy_query_error'):
                    print("Policy Tags: Could not retrieve (query error)")
                
                # Row-Level Security (RLS) information
                print(f"Row-Level Security (RLS): {'Yes' if tags_info['has_row_level_security'] else 'No'}")
                
                if tags_info['row_access_policies']:
                    print("Row Access Policies:")
                    for policy in tags_info['row_access_policies']:
                        print(f"  - Policy: {policy['policy_name']}")
                        print(f"    Grantees: {', '.join(policy['grantees']) if policy['grantees'] else 'None'}")
                        print(f"    Filter: {policy['filter_predicate']}")
                
                # Security summary
                if not tags_info['has_column_level_security'] and not tags_info['has_row_level_security']:
                    print("Security Level: Standard (No CLS/RLS configured)")
                else:
                    security_features = []
                    if tags_info['has_column_level_security']:
                        security_features.append("CLS")
                    if tags_info['has_row_level_security']:
                        security_features.append("RLS")
                    print(f"Security Level: Enhanced ({', '.join(security_features)} enabled)")
            
            # Access control summary (just the count and roles)
            access_entries = security_info['access_entries']
            if access_entries:
                unique_roles = set(entry['role'] for entry in access_entries)
                print(f"Access Roles: {', '.join(sorted(unique_roles))} ({len(access_entries)} entries)")
            else:
                print("Access Roles: Default permissions")
                
        except Exception as e:
            print(f"Error retrieving security info for {table_name}: {e}")
    
    print()


def example_dataset_security(bq_client: BigQueryClient):
    """Example 4: Display dataset security and roles information"""
    print("=== Example 4: Dataset security and roles information ===")
    
    try:
        dataset_security = bq_client.get_dataset_security_info()
        
        # Basic dataset information
        print(f"Dataset: {dataset_security['dataset_id']}")
        print(f"Project: {dataset_security['project']}")
        print(f"Location: {dataset_security['location']}")
        
        # Encryption configuration
        if dataset_security['default_encryption_configuration']:
            kms_key = dataset_security['default_encryption_configuration']['kms_key_name']
            print(f"Default encryption: {kms_key}")
        else:
            print("Default encryption: Google-managed")
        
        # Table expiration
        if dataset_security['default_table_expiration_ms']:
            expiration_ms = dataset_security['default_table_expiration_ms']
            expiration_days = expiration_ms / (1000 * 60 * 60 * 24)
            print(f"Default table expiration: {expiration_days:.0f} days")
        else:
            print("Default table expiration: None")
        
        # Labels
        if dataset_security['labels']:
            print("Dataset labels:")
            for key, value in dataset_security['labels'].items():
                print(f"  - {key}: {value}")
        
        # Detailed access entries and roles
        access_entries = dataset_security['access_entries']
        print(f"\nTotal access entries: {len(access_entries)}")
        
        if access_entries:
            print("\nDetailed Access Control Entries:")
            for i, entry in enumerate(access_entries, 1):
                display_access_entry_details(entry, i)
            
            # Show summary of unique roles
            unique_roles = set(entry['role'] for entry in access_entries)
            print(f"Available roles in dataset: {', '.join(sorted(unique_roles))}")
        else:
            print("No specific access entries found (using default permissions)")
        
    except Exception as e:
        print(f"Error retrieving dataset security info: {e}")
    print()


def main():
    """Main example function"""
    try:
        # Initialize BigQuery client
        bq_client = BigQueryClient()
        
        # Display client information
        display_client_info()
        
        # List and display available tables
        tables = display_available_tables(bq_client)
        
        # If tables exist, run examples
        if tables:
            # Use the third table (index 2) or first if less than 3 tables for individual examples
            table_index = min(2, len(tables) - 1)
            table_name = tables[table_index]
            
            # Run examples on a single table
            example_count_rows(bq_client, table_name)
            example_table_info(bq_client, table_name)
            example_table_preview(bq_client, table_name)
            
            # Run security and metadata examples (dataset security first, then table tags)
            example_dataset_security(bq_client)
            example_table_tags(bq_client, tables)
        else:
            print("No tables found in dataset. Create tables first to test queries.")
        
        print("=== Examples completed ===")
        
    except Exception as e:
        print(f"Error in main example: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)