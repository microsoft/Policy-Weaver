from typing import Optional, List, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

import os
import re
import yaml
import uuid

class classproperty(property):
    """
    A class property decorator that allows you to define properties that can be accessed on the class itself.
    Usage:
        class MyClass:
            @classproperty
            def my_property(cls):
                return "This is a class property
    """
    def __get__(self, owner_self, owner_cls):
        """
        Get the value of the property.
        Args:
            owner_self: The owner self.
            owner_cls: The owner class.
        Returns:
            The value of the property.
        """
        return self.fget(owner_cls)
    
class PolicyWeaverError(Exception):
    """
    Custom exception for Policy Weaver errors.
    This exception can be raised for any errors specific to the Policy Weaver application.
    It can be used to differentiate between general exceptions and those specific to Policy Weaver.
    Attributes:
        message (str): The error message.
    """
    pass

class CommonBaseModel(BaseModel):
    """
    Base model for all common models in the Policy Weaver application.
    This model provides common functionality such as alias handling and JSON serialization.
    Attributes:
        model_config (ConfigDict): Configuration for the model.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        exclude_unset=True,
        exclude_none=True,
    )

    def model_dump(self, **kwargs) -> dict[str, Any]:
        """
        Dumps the model to a dictionary, using aliases for field names.
        Args:
            **kwargs: Additional keyword arguments to pass to the model dump.
        Returns:
            dict[str, Any]: The model data as a dictionary with aliases.
        """
        return super().model_dump(by_alias=True, **kwargs)

    def model_dump_json(self, **kwargs) -> dict[str, Any]:
        """
        Dumps the model to a JSON string, using aliases for field names.
        Args:
            **kwargs: Additional keyword arguments to pass to the model dump.
        Returns:
            dict[str, Any]: The model data as a JSON string with aliases.
        """
        return super().model_dump_json(by_alias=True, **kwargs)

    def __getattr__(self, item):
        """
        Custom __getattr__ method to handle field aliases.
        This allows accessing model fields using their aliases.
        Args:
            item (str): The name of the attribute to access.
        Returns:
            Any: The value of the attribute if it exists, otherwise raises AttributeError.
        """
        for field, meta in self.model_fields.items():
            if meta.alias == item:
                return getattr(self, field)
        return super().__getattr__(item)

    def _get_alias(self, item_name):
        """
        Get the alias for a given item name.
        Args:
            item_name (str): The name of the item to get the alias for.
        Returns:
            str: The alias for the item if it exists, otherwise None.
        """
        for field, meta in self.model_fields.items():
            if field == item_name:
                return meta.alias

        return None

class CommonBaseEnum(Enum):
    """
    Base class for all common enums in the Policy Weaver application.
    This class provides common functionality such as string representation and value access.
    Attributes:
        value (str): The value of the enum member.
    """
    def __str__(self):
        """
        Returns the string representation of the enum member.
        Returns:
            str: The string representation of the enum member.
        """
        return str(self.value)

class IamType(str, CommonBaseEnum):
    """
    Enum representing different types of IAM entities.
    This enum is used to categorize IAM entities such as users, groups, managed identities, and service principals.
    Attributes:
        USER (str): Represents a user IAM entity.
        GROUP (str): Represents a group IAM entity.
        MANAGED_IDENTITY (str): Represents a managed identity IAM entity.
        SERVICE_PRINCIPAL (str): Represents a service principal IAM entity.
    """
    USER = "USER"
    GROUP = "GROUP"
    MANAGED_IDENTITY = "MANAGED_IDENTITY"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"

class PermissionType(str, CommonBaseEnum):
    """
    Enum representing different types of permissions.
    This enum is used to categorize permissions.
    Attributes:
        SELECT (str): Represents a SELECT permission.
    """
    SELECT = "SELECT"

class PermissionState(str, CommonBaseEnum):
    """
    Enum representing different states of permissions.
    This enum is used to categorize the state of permissions.
    Attributes:
        GRANT (str): Represents a GRANT state of permission.
    """
    GRANT = "GRANT"

class PolicyWeaverConnectorType(str, CommonBaseEnum):
    """
    Enum representing different types of Policy Weaver connectors.
    This enum is used to categorize the type of connector used in Policy Weaver.
    Attributes:
        UNITY_CATALOG (str): Represents a Unity Catalog connector.
        SNOWFLAKE (str): Represents a Snowflake connector.
        BIGQUERY (str): Represents a BigQuery connector.
    """
    UNITY_CATALOG = "UNITY_CATALOG"
    SNOWFLAKE = "SNOWFLAKE"
    BIGQUERY = "BIGQUERY"

class SourceSchema(CommonBaseModel):
    """
    Represents a schema in a source.
    Attributes:
        name (str): The name of the schema.
        tables (List[str]): A list of table names in the schema.
    """
    name: Optional[str] = Field(alias="name", default=None)
    tables: Optional[List[str]] = Field(alias="tables", default=None)

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

class PermissionObject(CommonBaseModel):
    """
    Represents an object in a permission.
    Attributes:
        id (str): The unique identifier for the object.
        type (IamType): The type of the IAM entity associated with the object.
    """
    id: Optional[str] = Field(alias="id", default=None)
    type: Optional[IamType] = Field(alias="type", default=None)

class Permission(CommonBaseModel):
    """
    Represents a permission in the Policy Weaver application.
    Attributes:
        id (str): The unique identifier for the permission.
        type (PermissionType): The type of the permission.
        name (str): The name of the permission.
        state (PermissionState): The state of the permission.
        objects (List[PermissionObject]): A list of objects associated with the permission.
    """
    name: Optional[str] = Field(alias="name", default=None)
    state: Optional[str] = Field(alias="state", default=None)
    objects: Optional[List[PermissionObject]] = Field(alias="objects", default=None)

class Policy(CatalogItem):
    """
    Represents a policy in the Policy Weaver application.
    Attributes:
        id (str): The unique identifier for the policy.
        name (str): The name of the policy.
        type (str): The type of the policy.
        catalog (str): The catalog to which the policy belongs.
        catalog_schema (str): The schema of the catalog.
        table (str): The table associated with the policy.
        permissions (List[Permission]): A list of permissions associated with the policy.
    """
    permissions: Optional[List[Permission]] = Field(alias="permissions", default=None)

class PolicyExport(CommonBaseModel):
    """
    Represents a policy export in the Policy Weaver application.
    Attributes:
        id (str): The unique identifier for the policy export.
        name (str): The name of the policy export.
        source (Source): The source from which the policy is exported.
        type (PolicyWeaverConnectorType): The type of the connector used for the policy export.
        policies (List[Policy]): A list of policies included in the export.
    """
    source: Optional[Source] = Field(alias="source", default=None)
    type: Optional[PolicyWeaverConnectorType] = Field(alias="type", default=None)
    policies: Optional[List[Policy]] = Field(alias="policies", default=None)

class FabricConfig(CommonBaseModel):
    """
    Configuration for the fabric in the Policy Weaver application.
    Attributes:
        tenant_id (str): The Azure tenant ID.
        workspace_id (str): The Azure workspace ID.
        workspace_name (str): The name of the Azure workspace.
        mirror_id (str): The ID of the mirror in the fabric.
        mirror_name (str): The name of the mirror in the fabric.
    """
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    workspace_id: Optional[str] = Field(alias="workspace_id", default=None)
    workspace_name: Optional[str] = Field(alias="workspace_name", default=None)
    mirror_id: Optional[str] = Field(alias="mirror_id", default=None)
    mirror_name: Optional[str] = Field(alias="mirror_name", default=None)

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
    service_principal: Optional[ServicePrincipalConfig] = Field(alias="service_principal", default=None)
    mapped_items: Optional[List[SourceMapItem]] = Field(alias="mapped_items", default=None)

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

class Utils:
    """
    Utility class for common operations in the Policy Weaver application.
    This class provides static methods for validating email addresses and UUIDs.
    """

    @staticmethod
    def is_email(email):
        """
        Validate if the provided string is a valid email address.
        Args:
            email (str): The email address to validate.
        Returns:
            bool: True if the email is valid, False otherwise.
        """
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(pattern, email)
    
    @staticmethod
    def is_uuid(uuid_string:str) -> bool:
        """
        Validate if the provided string is a valid UUID.
        Args:
            uuid_string (str): The UUID string to validate.
        Returns:
            bool: True if the string is a valid UUID, False otherwise.
        """
        if not uuid_string:
            return False
        
        try:
            uuid.UUID(uuid_string)
            return True
        except ValueError:
            return False