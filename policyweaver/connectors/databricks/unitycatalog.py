import urllib
import requests
import json

from enum import Enum
from policyweaver.connectors.source import *

class UnityCatalogSecurable(Enum):
    """
    Enum class representing different types of securable objects in Databricks Unity Catalog.
    Attributes:
        CATALOG (str): Represents a catalog securable object.
        SCHEMA (str): Represents a schema securable object.
        TABLE (str): Represents a table securable object.
    """

    CATALOG = "catalog"
    SCHEMA = "schema"
    TABLE = "table"

class UnityCatalogConnector(PolicySource):
    """
    A connector class for interacting with Databricks Unity Catalog to fetch policies.
    Attributes:
        config (dict): Configuration dictionary containing workspace, token, catalog, and schemas.
        util (UnityCatalogUtil): Utility class instance for Unity Catalog operations.
    Methods:
        __init__(connector_cfg: str):
            Initializes the UnityCatalogConnector with the provided configuration.
        open():
            Opens the connection to the Unity Catalog. (Currently a placeholder)
        close():
            Closes the connection to the Unity Catalog. (Currently a placeholder)
        validate():
            Validates the connection to the Unity Catalog. (Currently a placeholder)
        get_policies() -> list:
            Fetches and returns a list of policies from the Unity Catalog.
    """
    
    def __init__(self, connector_cfg:str):
        """
        Initializes the UnityCatalog connector with the provided configuration.
        Args:
            connector_cfg (str): A string containing the configuration for the UnityCatalog connector.
                The configuration should include the following keys:
                - "host": The workspace host.
                - "token": The access token.
                - "catalog": The catalog name.
                - "schemas": A JSON string representing the schemas.
        Attributes:
            config (dict): A dictionary containing the parsed configuration.
            util (UnityCatalogUtil): An instance of UnityCatalogUtil initialized with the parsed configuration.
        """

        cfg = connector_cfg["unitycatalog"]

        self.config = {
            'workspace': cfg["host"],
            'token': cfg["token"],
            'catalog': cfg["catalog"],
            'schemas': json.loads(cfg["schemas"])
        }
        self.util = UnityCatalogUtil(config=self.config)
    
    def open(self):
        """
        Opens a connection or performs an initialization process.
        This method is intended to be overridden in subclasses to provide
        specific functionality for opening a connection or initializing
        resources. The base implementation does nothing and returns immediately.
        Returns:
            None
        """

        return
    
    def close(self):
        """
        Closes the connection to the Databricks Unity Catalog.
        This method is intended to perform any necessary cleanup operations
        before the object is destroyed. Currently, it does not perform any
        specific actions.
        """

        return
    
    def validate(self):
        """
        Validates the current state or configuration.
        Returns:
            bool: Always returns True.
        """

        True
    
    def get_policies(self) -> list:
        """
        Retrieve a list of policies from Unity Catalog.
        This method collects various permissions and policies from Unity Catalog,
        including catalog permissions, schema permissions, and table permissions.
        Returns:
            list: A list of policies retrieved from Unity Catalog.
        """

        policies = []

        # Get catalog permissions
        policies.append(self.util.get_unity_catalog_permissions())

        # Get schema permissions
        policies.append(self.util.get_unity_catalog_schema_permissions())

        # Get the tables for the specified catalog/schemas
        tbls = self.util.get_unity_catalog_tables()

        # Get the table permissions
        policies.append(self.util.get_unity_catalog_table_permissions(tbls))

        return policies

class UnityCatalogUtil:  
    """
    Utility class for interacting with Databricks Unity Catalog.
    Attributes:
        config (dict[str, str]): Configuration dictionary containing Databricks workspace and token.
    Methods:
        __init__(config: dict[str, str]):
            Initializes the UnityCatalogUtil with the provided configuration.
        execute_dbx_api(api_method: str, params: dict = {}) -> str:
            Executes a Databricks API call with the given method and parameters.
        get_unity_catalog_tables() -> list:
            Retrieves a list of tables from the Unity Catalog based on the provided schemas.
        get_unity_catalog_permission(securable: UnityCatalogSecurable, obj: str):
            Retrieves permissions for a specific securable object in the Unity Catalog.
        get_unity_catalog_permissions() -> list:
            Retrieves permissions for the catalog specified in the configuration.
        get_unity_catalog_schema_permissions() -> list:
            Retrieves permissions for schemas specified in the configuration.
        get_unity_catalog_table_permissions(tables: list[str]) -> list:
            Retrieves permissions for the provided list of tables.
    """

    def __init__(self, config:dict[str,str]):
        """
        Initializes the UnityCatalog connector with the given configuration.
        Args:
            config (dict[str, str]): A dictionary containing configuration parameters.
        """

        self.config = config
          
    def execute_dbx_api(self, api_method:str, params:dict={}) -> str:
        """
        Executes a Databricks API call.
        Args:
            api_method (str): The API method to be called.
            params (dict, optional): A dictionary of parameters to be included in the API call. Defaults to an empty dictionary.
        Returns:
            str: The response from the API call in JSON format.
        Raises:
            Exception: If the API call returns a status code other than 200, an exception is raised with the error code and message.
        """

        dbx_host = self.config["workspace"]
        dbx_token = self.config["token"]

        headers = {
            'Authorization': f'Bearer {dbx_token}',
            'Content-Type': 'application/json'
        }

        url = f"{dbx_host}{api_method}?{urllib.parse.urlencode(params)}"
        payload = {}
        response = requests.get(url=url, data=payload, headers=headers)

        if (response.status_code != 200):
            raise Exception("Error: %s: %s" % (response.json()["error_code"], response.json()["message"]))

        return json.loads(response.text)

    def get_unity_catalog_tables(self) -> list:
        """
        Retrieves a list of Unity Catalog tables from Databricks.
        This method fetches tables from the Unity Catalog for the specified catalog and schemas
        defined in the configuration. It makes API calls to the Databricks Unity Catalog endpoint
        to retrieve the tables and aggregates them into a single list.
        Returns:
            list: A list of tables retrieved from the Unity Catalog.
        """

        tbls = []

        catalog = self.config["catalog"]
        schemas = self.config["schemas"]

        for schema in schemas:
            api_method = "/api/2.1/unity-catalog/tables"
            params = {
                'catalog_name' : self.config["catalog"],
                'schema_name' : schema
            }
            
            try:
                response = self.execute_dbx_api(api_method, params)
                tbls.extend(response['tables'])
            finally:
                continue
            
        return tbls

    def get_unity_catalog_permission(self, securable:UnityCatalogSecurable, obj:str):
        """
        Retrieves the permissions for a specified Unity Catalog securable object.
        Args:
            securable (UnityCatalogSecurable): The type of Unity Catalog securable (e.g., table, database).
            obj (str): The name of the securable object.
        Returns:
            dict: A dictionary containing the securable object and its permissions if the API call is successful.
            None: If there is an error during the API call.
        """

        api_method = f"/api/2.1/unity-catalog/permissions/{securable.value}/{obj}"
        
        try:
            response = self.execute_dbx_api(api_method)
            
            permission = {
                securable.value : obj,
                'permissions' : response['privilege_assignments']
            }
        except:
            print("API Error....")
            permission = None

        return permission

    def get_unity_catalog_permissions(self) -> list:
        """
        Retrieves the Unity Catalog permissions for the specified catalog.
        Returns:
            list: A list of permissions for the specified Unity Catalog.
        """

        securable_type = UnityCatalogSecurable.CATALOG
        catalog = self.config["catalog"]

        return self.get_unity_catalog_permission(securable_type, catalog)

    def get_unity_catalog_schema_permissions(self) -> list:
        """
        Retrieves the permissions for schemas in the Unity Catalog.
        This method iterates over the schemas specified in the configuration,
        fetches their permissions, and compiles them into a list.
        Returns:
            list: A list of permissions for each schema in the Unity Catalog.
        """

        schema_permissions = []

        catalog = self.config["catalog"]
        schemas = self.config["schemas"]
        securable_type = UnityCatalogSecurable.SCHEMA
        
        for schema in schemas:
            permission = self.get_unity_catalog_permission(securable_type, f"{catalog}.{schema}")

            if permission:
                schema_permissions.append(permission)
            
        return schema_permissions

    def get_unity_catalog_table_permissions(self,tables:list[str]) -> list:
        """
        Retrieves the permissions for a list of Unity Catalog tables.
        Args:
            tables (list[str]): A list of table names for which to retrieve permissions.
        Returns:
            list: A list of permissions for the specified tables.
        """

        tbls_permissions = []
        securable_type = UnityCatalogSecurable.TABLE

        for tbl in tables:
            permission = self.get_unity_catalog_permission(securable_type, tbl['full_name'])

            if permission:
                tbls_permissions.append(permission)

        return tbls_permissions