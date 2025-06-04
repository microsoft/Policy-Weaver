from typing import Optional, List, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

import os
import re
import yaml

class PolicyWeaverError(Exception):
    pass

class CommonBaseModel(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        exclude_unset=True,
        exclude_none=True,
    )

    def model_dump(self, **kwargs) -> dict[str, Any]:
        return super().model_dump(by_alias=True, **kwargs)

    def model_dump_json(self, **kwargs) -> dict[str, Any]:
        return super().model_dump_json(by_alias=True, **kwargs)

    def __getattr__(self, item):
        for field, meta in self.model_fields.items():
            if meta.alias == item:
                return getattr(self, field)
        return super().__getattr__(item)

    def _get_alias(self, item_name):
        for field, meta in self.model_fields.items():
            if field == item_name:
                return meta.alias

        return None


class CommonBaseEnum(Enum):
    def __str__(self):
        return str(self.value)


class IamType(str, CommonBaseEnum):
    USER = "USER"
    GROUP = "GROUP"


class PermissionType(str, CommonBaseEnum):
    SELECT = "SELECT"


class PermissionState(str, CommonBaseEnum):
    GRANT = "GRANT"


class PolicyWeaverConnectorType(str, CommonBaseEnum):
    UNITY_CATALOG = "UNITY_CATALOG"
    SNOWFLAKE = "SNOWFLAKE"
    BIGQUERY = "BIGQUERY"


class SourceSchema(CommonBaseModel):
    name: Optional[str] = Field(alias="name", default=None)
    tables: Optional[List[str]] = Field(alias="tables", default=None)


class CatalogItem(CommonBaseModel):
    catalog: Optional[str] = Field(alias="catalog", default=None)
    catalog_schema: Optional[str] = Field(alias="catalog_schema", default=None)
    table: Optional[str] = Field(alias="table", default=None)


class Source(CommonBaseModel):
    name: Optional[str] = Field(alias="name", default=None)
    schemas: Optional[List[SourceSchema]] = Field(alias="schemas", default=None)

    def get_schema_list(self) -> List[str]:
        if not self.schemas:
            return None

        return [s.name for s in self.schemas]


class PermissionObject(CommonBaseModel):
    id: Optional[str] = Field(alias="id", default=None)
    type: Optional[IamType] = Field(alias="type", default=None)


class Permission(CommonBaseModel):
    name: Optional[str] = Field(alias="name", default=None)
    state: Optional[str] = Field(alias="state", default=None)
    objects: Optional[List[PermissionObject]] = Field(alias="objects", default=None)


class Policy(CatalogItem):
    permissions: Optional[List[Permission]] = Field(alias="permissions", default=None)


class PolicyExport(CommonBaseModel):
    source: Optional[Source] = Field(alias="source", default=None)
    type: Optional[PolicyWeaverConnectorType] = Field(alias="type", default=None)
    policies: Optional[List[Policy]] = Field(alias="policies", default=None)


class FabricConfig(CommonBaseModel):
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    workspace_id: Optional[str] = Field(alias="workspace_id", default=None)
    workspace_name: Optional[str] = Field(alias="workspace_name", default=None)
    mirror_id: Optional[str] = Field(alias="mirror_id", default=None)
    mirror_name: Optional[str] = Field(alias="mirror_name", default=None)

class ServicePrincipalConfig(CommonBaseModel):
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    client_id: Optional[str] = Field(alias="client_id", default=None)
    client_secret: Optional[str] = Field(alias="client_secret", default=None)


class SourceMapItem(CatalogItem):
    mirror_table_name: Optional[str] = Field(
        alias="mirror_table_name", default=None
    )

class SourceMap(CommonBaseModel):
    application_name: Optional[str] = Field(alias="application_name", default="POLICY_WEAVER")
    correlation_id: Optional[str] = Field(alias="correlation_id", default=None)
    type: Optional[PolicyWeaverConnectorType] = Field(alias="type", default=None)
    source: Optional[Source] = Field(alias="source", default=None)
    fabric: Optional[FabricConfig] = Field(alias="fabric", default=None)
    service_principal: Optional[ServicePrincipalConfig] = Field(
        alias="service_principal", default=None
    )
    mapped_items: Optional[List[SourceMapItem]] = Field(
        alias="mapped_items", default=None
    )

    _default_paths = ['./settings.yaml']

    @classmethod
    def from_yaml(cls, path:str=None) -> 'SourceMap':
        paths = [path] if path else cls._default_paths.default
            
        for p in paths:
            if os.path.exists(p):
                with open(p, 'r', encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                return cls(**data)
        
        raise PolicyWeaverError("Policy Sync settings file not found")

    def __save_to_first_writable_path__(self, path:str=None) -> None:
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
        self.__save_to_first_writable_path__(path)

class Utils:
    @staticmethod
    def is_email(email):
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(pattern, email)