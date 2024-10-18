from pydantic import BaseModel
from enum import Enum

class PolicyWeaverConnectorType(Enum):
    """
    Enum class representing different types of connectors for Policy Weaver.
    Attributes:
        UNITYCATALOG (int): Represents the Unity Catalog connector type.
        SNOWFLAKE (int): Represents the Snowflake connector type.
        BIGQUERY (int): Represents the BigQuery connector type.
    """

    UNITYCATALOG = 1
    SNOWFLAKE = 2
    BIGQUERY = 3

class PolicyStoreType(Enum):
    """
    PolicyStoreType is an enumeration that defines the types of policy stores available.
    Attributes:
        ONELAKE (int): Represents a policy store type that uses OneLake.
        LOCAL (int): Represents a policy store type that uses a local storage.
    """

    ONELAKE = 1
    LOCAL = 2

class PolicyStoreConfig(BaseModel):
    """
    PolicyStoreConfig is a configuration class for the policy store.
    Attributes:
        Type (PolicyStoreType): The type of the policy store.
        Path (str): The file path to the policy store.
    """

    Type: PolicyStoreType
    Path: str

class FabricConfig(BaseModel):
    """
    FabricConfig is a configuration model for fabric settings.
    Attributes:
        WorkspaceId (str): The unique identifier for the workspace.
        LakehouseId (str): The unique identifier for the lakehouse.
        LakehouseName (str): The name of the lakehouse.
        Credentials (str): The credentials required for accessing the lakehouse.
        APIEndpoint (str): The API endpoint for fabric operations.
        OneLakeEndpoint (str): The endpoint for OneLake services.
    """

    WorkspaceId: str
    LakehouseId: str
    LakehouseName: str
    Credentials: str
    APIEndpoint: str
    OneLakeEndpoint: str

class WeaverConfig(BaseModel):
    """
    WeaverConfig is a configuration model for the Policy Weaver application.
    Attributes:
        ConnectorType (PolicyWeaverConnectorType): Specifies the type of connector used by Policy Weaver.
        PolicyStore (PolicyStoreConfig): Configuration settings for the policy store.
        Fabric (FabricConfig): Configuration settings for the fabric.
        Connectors (str): A string representing the connectors.
    """

    ConnectorType: PolicyWeaverConnectorType
    PolicyStore: PolicyStoreConfig
    Fabric: FabricConfig
    Connectors: str
