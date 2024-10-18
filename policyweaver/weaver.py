import sys

from policyweaver.connectors.databricks.unitycatalog import *
from policyweaver.connectors.nullconnector.null import *
from policyweaver.config.configuration import *


class PolicyWeaver():
    """
    PolicyWeaver is responsible for orchestrating the policy weaving process based on the provided configuration.
    Attributes:
        config (WeaverConfig): The configuration object for the PolicyWeaver.
    Methods:
        __init__(path: str):
            Initializes the PolicyWeaver with the configuration from the specified path.
        run():
            Executes the policy weaving process based on the configuration.
        get_config(path: str) -> WeaverConfig:
            Reads and parses the configuration file from the specified path and returns a WeaverConfig object.
    """

    def __init__(self, path:str):
        """
        Initializes the Weaver instance.
        Args:
            path (str): The path to the configuration file.
        """

        self.config = self.get_config(path)

    def run(self):
        """
        Executes the policy weaver process based on the configured connector type.
        This method initializes the appropriate connector based on the `ConnectorType`
        specified in the configuration. It then starts the policy service to retrieve
        access policies and prints the results.
        Steps:
        1. Determine the connector type from the configuration.
        2. Initialize the corresponding connector.
        3. Print a message indicating the start of the policy weaver process.
        4. Create a `PolicyService` instance with the initialized connector.
        5. Retrieve and print access policies.
        6. Print a message indicating the completion of the policy weaver process.
        Raises:
            AttributeError: If `ConnectorType` or `Connectors` is not found in the configuration.
        """

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
        """
        Reads a configuration file from the specified path and returns a WeaverConfig object.
        Args:
            path (str): The file path to the configuration file.
        Returns:
            WeaverConfig: An object containing the configuration settings.
        Raises:
            Exception: If the configuration file is invalid or missing required fields.
        """

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
    """
    Main function to execute the PolicyWeaver.
    This function sets the configuration file path, either from the command line
    argument or defaults to "config.json". It then initializes the PolicyWeaver
    with the specified configuration path and runs it.
    Args:
        None
    Returns:
        None
    """

    config_path = "config.json"

    if len(sys.argv) > 0:
        config_path = sys.argv[0]
    
    weaver = PolicyWeaver(path=config_path)
    weaver.run()

if __name__ == "__main__":
    main()