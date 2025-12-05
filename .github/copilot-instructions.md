# Python BigQuery Project Instructions

This is a Python project for querying Google BigQuery databases on Google Cloud Platform.

## Project Structure
- Main application code in `src/` directory
- Configuration files for GCP authentication
- Example queries and data analysis scripts
- Requirements and dependencies management

## Development Guidelines
- Use google-cloud-bigquery library for BigQuery operations
- Follow Python best practices and PEP 8 style guide
- Include proper error handling for GCP API calls
- Use environment variables for sensitive configuration

## BigQuery Specific Instructions
- Always use parameterized queries to prevent SQL injection
- Implement proper cost management with query limits
- Use streaming inserts for real-time data
- Follow GCP security best practices for authentication