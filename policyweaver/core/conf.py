from logging import config
import logging
import os
from uuid import uuid4
import requests

from policyweaver.models.config import SourceMap
from policyweaver.core.auth import AzureCLIClient
try:
    import notebookutils
except:
    pass

class Configuration:
    """
    Configuration class for managing application settings and environment variables.
    This class provides methods to set and retrieve configuration values,
    including correlation IDs and service principal credentials.
    Example usage:
        config = Configuration()
        config.configure_environment(SourceMap(correlation_id="12345"))
        print(os.environ['CORRELATION_ID'])  # Outputs: 12345
    """
    @staticmethod
    def configure_environment(config:SourceMap):
        """
        Configure the environment with the provided SourceMap configuration.
        This method sets the correlation ID in the environment variables
        and ensures that a unique correlation ID is generated if not provided.
        Args:
            config (SourceMap): The SourceMap instance containing configuration values.
        """
        if not config.correlation_id:
            config.correlation_id = str(uuid4())

        if config.keyvault and config.keyvault.use_key_vault:
            Configuration.retrieve_key_vault_credentials(config)

        os.environ['CORRELATION_ID'] = config.correlation_id

    @staticmethod
    def retrieve_key_vault_credentials(config:SourceMap):
        """
        Retrieve the Key Vault credentials from the configuration.
        This method checks if the Key Vault is enabled and retrieves the necessary credentials.
        Args:
            config (SourceMap): The SourceMap instance containing configuration values.
        Returns:
            dict: A dictionary containing Key Vault credentials if available.
        """
        logger = logging.getLogger("POLICY_WEAVER")

        if not(config.keyvault and config.keyvault.use_key_vault):
            logger.error("Key Vault is not enabled in the configuration.")
            raise ValueError("Key Vault is not enabled in the configuration.")
        if not(config.keyvault.name and config.keyvault.authentication_method):
            logger.error("Key Vault name and authentication method must be provided.")
            raise ValueError("Key Vault name and authentication method must be provided.")
        
        key_vault_name = config.keyvault.name

        if config.keyvault.authentication_method == "azure_cli":
            
            credential = AzureCLIClient()
            credential.initialize()
            
            def get_secret(secret_name, config_name):
                """
                Retrieve a secret from Azure Key Vault using the Azure CLI credentials.
                Args:
                    secret_name (str): The name of the secret to retrieve.
                Returns:
                    str: The value of the secret.
                """
                key_vault_base_url = f"https://{key_vault_name}.vault.azure.net"
                headers = credential.get_token_header(key_vault_base_url)
                
                keyvault_url = f"{key_vault_base_url}/secrets/{secret_name}?api-version=7.4"
                response = requests.get(keyvault_url, headers=headers)
                
                if response.status_code == 200:
                    return response.json()["value"]
                else:
                    logger.warning(f"Failed to retrieve secret '{config_name}' from Key Vault. Using the configured value as fallback.")
                    return secret_name

        elif config.keyvault.authentication_method == "fabric_notebook":
            def get_secret(secret_name, config_name):
                """
                Retrieve a secret from Azure Key Vault using the Fabric Notebook credentials.
                Args:
                    secret_name (str): The name of the secret to retrieve.
                Returns:
                    str: The value of the secret.
                """
                # Assuming notebookutils is available in the environment
                try:
                    return notebookutils.credentials.getSecret(f'https://{key_vault_name}.vault.azure.net/', secret_name)
                except Exception as e:
                    logger.warning(f"Failed to retrieve secret '{config_name}' from Key Vault. Using the configured value as fallback.")
                    return secret_name
            
        else:
            raise ValueError("Unsupported Key Vault authentication method. Use 'azure_cli' or 'fabric_notebook'.")

        config.service_principal.tenant_id = get_secret(config.service_principal.tenant_id, config_name="tenant_id")
        config.service_principal.client_id = get_secret(config.service_principal.client_id, config_name="client_id")
        config.service_principal.client_secret = get_secret(config.service_principal.client_secret, config_name="client_secret")
        if hasattr(config, 'databricks') and config.databricks is not None:
            config.databricks.account_api_token = get_secret(config.databricks.account_api_token, config_name="databricks.account_api_token")
        if hasattr(config, 'snowflake') and config.snowflake is not None:
            config.snowflake.account_name = get_secret(config.snowflake.account_name, config_name="snowflake account_name")
            config.snowflake.user_name = get_secret(config.snowflake.user_name, config_name="snowflake user_name")
            config.snowflake.password = get_secret(config.snowflake.password, config_name="snowflake password")

