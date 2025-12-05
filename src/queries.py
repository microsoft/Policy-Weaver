"""
BigQuery query templates
"""

# Simple query to count rows
SIMPLE_COUNT_QUERY = """
SELECT COUNT(*) as total_rows
FROM `{project_id}.{dataset_id}.{table_id}`
"""