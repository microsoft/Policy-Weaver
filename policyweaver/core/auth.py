from azure.identity import ClientSecretCredential, AzureCliCredential
import os

from policyweaver.core.common import classproperty

class ServicePrincipal:
    """
    Service Principal for Azure Fabric API Authentication.
    This class provides methods to initialize the service principal with tenant ID,
    client ID, and client secret, and to retrieve an access token for API calls.
    It uses the Azure Identity library to manage authentication.
    Example usage:
        ServicePrincipal.initialize(tenant_id, client_id, client_secret)
        token = ServicePrincipal.get_token()
        headers = ServicePrincipal.get_token_header()
    """
    @classmethod
    def initialize(cls, tenant_id:str, client_id:str, client_secret: str):
        """
        Initialize the service principal with the provided tenant ID, client ID, and client secret.
        This method sets the environment variables required for authentication and clears any existing token.
        Args:
            tenant_id (str): The Azure Active Directory tenant ID.
            client_id (str): The client ID of the service principal.
            client_secret (str): The client secret of the service principal.
        """
        cls.__token__ = None

        os.environ["SP_TENANT_ID"] = tenant_id
        os.environ["SP_CLIENT_ID"] = client_id
        os.environ["SP_CLIENT_SECRET"] = client_secret

    @classproperty
    def Credential(cls) -> ClientSecretCredential:
        """
        Returns a ClientSecretCredential instance using the service principal's tenant ID,
        client ID, and client secret.
        This credential can be used to authenticate API calls to Azure services.
        Returns:
            ClientSecretCredential: An instance of ClientSecretCredential initialized with the service principal's credentials.
        """
        return ClientSecretCredential(
            cls.TenantId,
            cls.ClientId,
            cls.ClientSecret
        )

    @classproperty
    def TenantId(cls) -> str:
        """
        Returns the tenant ID of the service principal from the environment variable.
        This method retrieves the tenant ID that was set during initialization.
        Returns:
            str: The tenant ID of the service principal.
        """
        return os.environ["SP_TENANT_ID"]
    
    @classproperty
    def ClientId(cls) -> str:
        """
        Returns the client ID of the service principal from the environment variable.
        This method retrieves the client ID that was set during initialization.
        Returns:
            str: The client ID of the service principal.
        """
        return os.environ["SP_CLIENT_ID"]
    
    @classproperty
    def ClientSecret(cls) -> str:
        """
        Returns the client secret of the service principal from the environment variable.
        This method retrieves the client secret that was set during initialization.
        Returns:
            str: The client secret of the service principal.
        """
        return os.environ["SP_CLIENT_SECRET"]
    
    @classmethod
    def get_token(cls, scope="https://api.fabric.microsoft.com/.default") -> str:
        """
        Retrieves an access token for the Azure Fabric API using the service principal's credentials.
        If the token is not already cached, it creates a new token using the ClientSecretCredential.
        This method caches the token for subsequent calls to avoid unnecessary authentication requests.
        Returns:
            str: The access token for the Azure Fabric API.
        """
        cls.__token__ = cls.Credential.get_token(scope)
        
        return cls.__token__.token

    @classmethod
    def get_token_header(cls, scope="https://api.fabric.microsoft.com/.default") -> dict:
        """
        Returns a dictionary containing the authorization header with the Bearer token.
        This header can be used in API requests to authenticate with the Azure Fabric API.
        Returns:
            dict: A dictionary with the authorization header containing the Bearer token.
        """
        return {
            "Authorization": f"Bearer {cls.get_token(scope)}",
        }

class AzureCLIClient:
    """
    Azure CLI Client for Azure Fabric API Authentication.
    This class provides methods to retrieve the access token using the Azure CLI.
    It is used when the service principal is not available or when using Azure CLI authentication.
    """
    @classmethod
    def initialize(cls):
        """
        Initialize the Azure CLI client.
        """
        cls.__token__ = None

    @classproperty
    def Credential(cls) -> AzureCliCredential:
        """
        Returns a AzureCliCredential instance .
        This credential can be used to authenticate API calls to Azure services.
        Returns:
            AzureCliCredential: An instance of AzureCliCredential.
        """
        return AzureCliCredential()
    
    @classmethod
    def get_token(cls, scope="https://api.fabric.microsoft.com/.default") -> str:
        """
        Retrieves an access token for the Azure Fabric API using the Azure CLI credentials.
        This method uses the AzureCliCredential to obtain the token.
        Returns:
            str: The access token for the Azure Fabric API.
        """
        cls.__token__ = cls.Credential.get_token(scope)
        return cls.__token__.token
    
    @classmethod
    def get_token_header(cls, scope="https://api.fabric.microsoft.com/.default") -> dict:
        """
        Returns a dictionary containing the authorization header with the Bearer token.
        This header can be used in API requests to authenticate with the Azure Fabric API.
        Returns:
            dict: A dictionary with the authorization header containing the Bearer token.
        """
        return {
            "Authorization": f"Bearer {cls.get_token(scope)}",
        }
