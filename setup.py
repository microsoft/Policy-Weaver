from setuptools import setup, find_packages

setup(
    name="bigquery-client",
    version="1.0.0",
    description="Python client for Google BigQuery",
    packages=find_packages(),
    install_requires=[
        "google-cloud-bigquery>=3.13.0",
        "python-dotenv>=1.0.0",
        "pandas>=2.0.0",
        "google-auth>=2.20.0",
        "google-auth-oauthlib>=1.0.0",
        "google-auth-httplib2>=0.2.0",
        "db-dtypes>=1.0.0"
    ],
    python_requires=">=3.8",
)