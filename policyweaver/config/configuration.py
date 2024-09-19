from dataclasses import dataclass
from enum import Enum

class PolicyWeaverConnectorType(Enum):
    UNITYCATALOG = 1
    SNOWFLAKE = 2
    BIGQUERY = 3

class PolicyStoreType(Enum):
    ONELAKE = 1
    LOCAL = 2

@dataclass
class PolicyStoreConfig():
    Type: PolicyStoreType
    Path: str

@dataclass
class FabricConfig():
    WorkspaceId: str
    LakehouseId: str
    LakehouseName: str
    Credentials: str
    APIEndpoint: str
    OneLakeEndpoint: str

@dataclass
class WeaverConfig():
    ConnectorType: PolicyWeaverConnectorType
    PolicyStore: PolicyStoreConfig
    Fabric: FabricConfig
    Connectors: str
