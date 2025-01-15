from typing import Optional, List, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


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
    api_token: Optional[str] = Field(alias="api_token", default=None)
    workspace_id: Optional[str] = Field(alias="workspace_id", default=None)
    workspace_name: Optional[str] = Field(alias="workspace_name", default=None)
    lakehouse_id: Optional[str] = Field(alias="lakehouse_id", default=None)
    lakehouse_name: Optional[str] = Field(alias="lakehouse_name", default=None)


class ServicePrincipalConfig(CommonBaseModel):
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    client_id: Optional[str] = Field(alias="client_id", default=None)
    client_secret: Optional[str] = Field(alias="client_secret", default=None)


class SourceMapItem(CatalogItem):
    lakehouse_table_name: Optional[str] = Field(
        alias="lakehouse_table_name", default=None
    )


class SourceMap(CommonBaseModel):
    type: Optional[PolicyWeaverConnectorType] = Field(alias="type", default=None)
    source: Optional[Source] = Field(alias="source", default=None)
    fabric: Optional[FabricConfig] = Field(alias="fabric", default=None)
    service_principal: Optional[ServicePrincipalConfig] = Field(
        alias="service_principal", default=None
    )
    mapped_items: Optional[List[SourceMapItem]] = Field(
        alias="mapped_items", default=None
    )
