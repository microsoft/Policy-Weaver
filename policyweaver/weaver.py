from enum import Enum

from policyweaver.connectors.databricks.unitycatalog import *
from policyweaver.connectors.nullconnector.null import *

class PolicyWeaverConnectorType(Enum):
    UNITYCATALOG = 1
    SNOWFLAKE = 2
    BIGQUERY = 3

def main():
    connector_type = PolicyWeaverConnectorType.UNITYCATALOG
    connector = None

    match connector_type:
        case PolicyWeaverConnectorType.UNITYCATALOG:
            connector = UnityCatalogConnector(dbx_host="",
                                              dbx_token="",
                                              uc_catalog = "",
                                              uc_schemas= "")
        case _:
            connector = NullConnector()
    
    print(f"{connector_type.name} Policy Weaver started...")

    policy_service = PolicyService(source = connector)

    access_policies = policy_service.get_access_policies()
    print(access_policies)

    print(f"{connector_type.name} Policy Weaver complete!")

if __name__ == "__main__":
    main()