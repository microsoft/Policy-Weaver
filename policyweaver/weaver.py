import sys

from policyweaver.connectors.databricks.unitycatalog import *
from policyweaver.connectors.nullconnector.null import *
from policyweaver.config.configuration import *


class PolicyWeaver():
    def __init__(self, path:str):
        self.config = self.get_config(path)

    def run(self):
        connector_type = self.config.ConnectorType
        connector = None

        match connector_type:
            case PolicyWeaverConnectorType.UNITYCATALOG:
                connector = UnityCatalogConnector(connector_cfg=self.config.Connectors)
            case _:
                connector = NullConnector()
        
        print(f"{connector_type.name} Policy Weaver started...")

        policy_service = PolicyService(source = connector)
        access_policies = policy_service.get_access_policies()
        print(access_policies)

        print(f"{connector_type.name} Policy Weaver complete!")

    def get_config(self, path:str) -> WeaverConfig:
        cfg = None

        with open(path, "r") as f:
            cfg = json.load(f)
        
        if not cfg:
            raise Exception("Invalid or Missing Application Config")
    
        config = WeaverConfig(
            ConnectorType= PolicyWeaverConnectorType[cfg["connectortype"]],
            PolicyStore=PolicyStoreConfig(
                Type=PolicyStoreType[cfg["policystore.type"]], 
                Path=cfg["policystore.path"]),
            Fabric=FabricConfig(
                WorkspaceId=cfg["fabric.workspaceid"],
                LakehouseId=cfg["fabric.lakehouseid"],
                LakehouseName=cfg["fabric.lakehousename"],
                Credentials=cfg["fabric.credentials"],
                APIEndpoint=cfg["fabric.apiendpoing"],
                OneLakeEndpoint=cfg["fabric.onelakeendpoint"]),
            Connectors=cfg["connectors"]
            )
        
        return config

def main():
    config_path = "config.json"

    if len(sys.argv) > 0:
        config_path = sys.argv[0]
    
    weaver = PolicyWeaver(path=config_path)
    weaver.run()

if __name__ == "__main__":
    main()