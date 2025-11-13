from typing import Optional, List
from pydantic import Field

import os
import yaml

from policyweaver.models.common import CommonBaseModel
from policyweaver.core.enum import PolicyWeaverConnectorType
from policyweaver.core.exception import PolicyWeaverError

class SourceSchema(CommonBaseModel):
    """
    Represents a schema in a source.
    Attributes:
        name (str): The name of the schema.
        tables (List[str]): A list of table names in the schema.
    """
    name: Optional[str] = Field(alias="name", default=None)
    tables: Optional[List[str]] = Field(alias="tables", default=None)

class Source(CommonBaseModel):
    """
    Represents a source in the Policy Weaver application.
    Attributes:
        id (str): The unique identifier for the source.
        type (PolicyWeaverConnectorType): The type of the source connector.
        name (str): The name of the source.
        schemas (List[SourceSchema]): A list of schemas in the source.
    """
    name: Optional[str] = Field(alias="name", default=None)
    schemas: Optional[List[SourceSchema]] = Field(alias="schemas", default=None)

    def get_schema_list(self) -> List[str]:
        """
        Returns a list of schema names in the source.
        If there are no schemas, returns None.  
        Returns:
            List[str]: A list of schema names if schemas exist, otherwise None.
        """
        if not self.schemas:
            return None

        return [s.name for s in self.schemas]

class ColumnConstraintsConfig(CommonBaseModel):
    """
    Configuration for column constraints in the fabric.
    Attributes:
        columnlevelsecurity (bool): Flag to indicate whether column-level security is enabled.
        fallback (str): The fallback policy, e.g., "deny" or "allow".
    """
    columnlevelsecurity: Optional[bool] = Field(alias="columnlevelsecurity", default=False)
    fallback: Optional[str] = Field(alias="fallback", default="deny")

class RowConstraintsConfig(CommonBaseModel):
    """
    Configuration for row constraints in the fabric.
    Attributes:
        rowlevelsecurity (bool): Flag to indicate whether row-level security is enabled.
        fallback (str): The fallback policy, e.g., "deny" or "allow".
    """
    rowlevelsecurity: Optional[bool] = Field(alias="rowlevelsecurity", default=False)
    fallback: Optional[str] = Field(alias="fallback", default="deny")

class ConstraintsConfig(CommonBaseModel):
    """
    Configuration for fabric constraints in the Policy Weaver application.
    Attributes:
        columns (dict): A dictionary containing column-level security settings.
            - columnlevelsecurity (bool): Flag to indicate whether column-level security is enabled.
            - fallback (str): The fallback policy, e.g., "deny" or "allow".
    """
    columns: Optional[ColumnConstraintsConfig] = Field(alias="columns", default=None)
    rows: Optional[RowConstraintsConfig] = Field(alias="rows", default=None)

class FabricConfig(CommonBaseModel):
    """
    Configuration for the fabric in the Policy Weaver application.
    Attributes:
        tenant_id (str): The Azure tenant ID.
        workspace_id (str): The Azure workspace ID.
        workspace_name (str): The name of the Azure workspace.
        mirror_id (str): The ID of the mirror in the fabric.
        mirror_name (str): The name of the mirror in the fabric.
        fabric_role_suffix (str): The suffix for the fabric role, default is "PWPolicy".
        delete_default_reader_role (bool): Flag to indicate whether to delete the default reader role,
            default is False.
    """
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    workspace_id: Optional[str] = Field(alias="workspace_id", default=None)
    workspace_name: Optional[str] = Field(alias="workspace_name", default=None)
    mirror_id: Optional[str] = Field(alias="mirror_id", default=None)
    mirror_name: Optional[str] = Field(alias="mirror_name", default=None)
    fabric_role_suffix: Optional[str] = Field(alias="fabric_role_suffix", default="PWPolicy")
    delete_default_reader_role: Optional[bool] = Field(alias="delete_default_reader_role", default=False)
    policy_mapping: Optional[str] = Field(alias="policy_mapping", default="table_based")

class ServicePrincipalConfig(CommonBaseModel):
    """
    Configuration for service principal authentication.
    Attributes:
        tenant_id (str): The Azure tenant ID.
        client_id (str): The client ID of the service principal.
        client_secret (str): The client secret of the service principal.
    """
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    client_id: Optional[str] = Field(alias="client_id", default=None)
    client_secret: Optional[str] = Field(alias="client_secret", default=None)

class KeyVaultConfig(CommonBaseModel):
    """
    Configuration for Azure Key Vault.
    Attributes:
        use_key_vault (bool): Flag to indicate whether to use Azure Key Vault.
        name (str): The name of the Key Vault.
        authentication_method (str): The authentication method to use for accessing the Key Vault.
    """
    use_key_vault: Optional[bool] = Field(alias="use_key_vault", default=False)
    name: Optional[str] = Field(alias="name", default=None)
    authentication_method: Optional[str] = Field(alias="authentication_method", default=None)


class CatalogItem(CommonBaseModel):
    """
    Base model for catalog items.
    This model provides common functionality for catalog items such as ID, name, and type.
    Attributes:
        id (str): The unique identifier for the catalog item.
        name (str): The name of the catalog item.
        type (str): The type of the catalog item.
        catalog (str): The catalog to which the item belongs.
        catalog_schema (str): The schema of the catalog.
        table (str): The table associated with the catalog item.
    """
    catalog: Optional[str] = Field(alias="catalog", default=None)
    catalog_schema: Optional[str] = Field(alias="catalog_schema", default=None)
    table: Optional[str] = Field(alias="table", default=None)
    
class SourceMapItem(CatalogItem):
    """
    Represents an item in the source map.
    Attributes:
        id (str): The unique identifier for the source map item.
        name (str): The name of the source map item.
        type (str): The type of the source map item.
        catalog (str): The catalog to which the source map item belongs.
        catalog_schema (str): The schema of the catalog.
        table (str): The table associated with the source map item.
        mirror_table_name (str): The name of the mirror table associated with the source map item.
    """
    mirror_table_name: Optional[str] = Field(alias="mirror_table_name", default=None)

class SourceMap(CommonBaseModel):
    """
    Represents a source map in the Policy Weaver application.
    This model contains configuration for the source map, including application name, correlation ID,
    connector type, source, fabric configuration, service principal configuration, and mapped items.
    Attributes:
        application_name (str): The name of the application using the source map.
        correlation_id (str): A unique identifier for the correlation of operations.
        type (PolicyWeaverConnectorType): The type of the connector used in the source map.
        source (Source): The source from which the policies are mapped.
        fabric (FabricConfig): Configuration for the fabric in which the policies are managed.
        service_principal (ServicePrincipalConfig): Configuration for service principal authentication.
        mapped_items (List[SourceMapItem]): A list of items that are mapped in the source map.
    """
    application_name: Optional[str] = Field(alias="application_name", default="POLICY_WEAVER")
    correlation_id: Optional[str] = Field(alias="correlation_id", default=None)
    type: Optional[PolicyWeaverConnectorType] = Field(alias="type", default=None)
    source: Optional[Source] = Field(alias="source", default=None)
    fabric: Optional[FabricConfig] = Field(alias="fabric", default=None)
    constraints: Optional[ConstraintsConfig] = Field(alias="constraints", default=None)
    service_principal: Optional[ServicePrincipalConfig] = Field(alias="service_principal", default=None)
    mapped_items: Optional[List[SourceMapItem]] = Field(alias="mapped_items", default=None)
    keyvault: Optional[KeyVaultConfig] = Field(alias="keyvault", default=None)

    _default_paths = ['./settings.yaml']

    @classmethod
    def from_yaml(cls, path:str=None) -> 'SourceMap':
        """
        Load a SourceMap instance from a YAML file.
        Args:
            path (str): The path to the YAML file. If None, uses the default paths. 
        Returns:
            SourceMap: An instance of SourceMap loaded from the YAML file.
        Raises:
            PolicyWeaverError: If the YAML file does not exist or cannot be loaded.
        """
        paths = [path] if path else cls._default_paths.default
            
        for p in paths:
            if os.path.exists(p):
                with open(p, 'r', encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                return cls(**data)
        
        raise PolicyWeaverError("Policy Sync settings file not found")

    def __save_to_first_writable_path__(self, path:str=None) -> None:
        """
        Save the SourceMap instance to the first writable path in the provided list or default paths.
        Args:
            path (str): The path to save the YAML file. If None, uses the default paths.
        Raises:
            IOError: If none of the paths are writable.
        """
        paths = [path] if path else self._default_paths

        for p in paths:
            try:
                with open(p, 'w', encoding="utf-8") as f:
                    yaml.safe_dump(self.model_dump(exclude_none=True, exclude_unset=True), f)
                print(f"Settings saved to {p}")
                return
            except IOError:
                print(f"Unable to write to {p}")
        raise IOError(f"None of the paths in {paths} are writable.")

    def to_yaml(self, path:str=None) -> None:
        """
        Save the SourceMap instance to a YAML file.
        Args:
            path (str): The path to save the YAML file. If None, uses the default paths.
        Raises:
            IOError: If none of the paths are writable.
        """
        self.__save_to_first_writable_path__(path)