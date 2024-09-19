import urllib
import requests
import json

from enum import Enum
from policyweaver.connectors.source import *

class UnityCatalogSecurable(Enum):
    CATALOG = "catalog"
    SCHEMA = "schema"
    TABLE = "table"

class UnityCatalogConnector(PolicySource):
    def __init__(self, connector_cfg:str):
        cfg = connector_cfg["unitycatalog"]

        self.config = {
            'workspace': cfg["host"],
            'token': cfg["token"],
            'catalog': cfg["catalog"],
            'schemas': json.loads(cfg["schemas"])
        }
        self.util = UnityCatalogUtil(config=self.config)
    
    def open(self):
        return
    
    def close(self):
        return
    
    def validate(self):
        True
    
    def get_policies(self) -> list:
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
    def __init__(self, config:dict[str,str]):
        self.config = config
          
    def execute_dbx_api(self, api_method:str, params:dict={}) -> str:
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
        securable_type = UnityCatalogSecurable.CATALOG
        catalog = self.config["catalog"]

        return self.get_unity_catalog_permission(securable_type, catalog)

    def get_unity_catalog_schema_permissions(self) -> list:
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
        tbls_permissions = []
        securable_type = UnityCatalogSecurable.TABLE

        for tbl in tables:
            permission = self.get_unity_catalog_permission(securable_type, tbl['full_name'])

            if permission:
                tbls_permissions.append(permission)

        return tbls_permissions