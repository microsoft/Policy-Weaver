from policyweaver.models.common import (
    CommonBaseModel, 
    IamType,
    SourceMap
)

from pydantic import Field
from typing import Optional, List

class Privilege(CommonBaseModel):
    principal: Optional[str] = Field(alias="principal", default=None)
    privileges: Optional[List[str]] = Field(alias="privileges", default=None)


class BaseObject(CommonBaseModel):
    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)


class PrivilegedObject(BaseObject):
    privileges: Optional[List[Privilege]] = Field(alias="privileges", default=None)


class FunctionMap(BaseObject):
    columns: Optional[List[str]] = Field(alias="column", default=None)


class Function(PrivilegedObject):
    sql: Optional[str] = Field(alias="sql", default=None)


class Table(PrivilegedObject):
    column_masks: Optional[List[FunctionMap]] = Field(
        alias="column_masks", default=None
    )
    row_filter: Optional[FunctionMap] = Field(alias="row_filter", default=None)


class Schema(PrivilegedObject):
    tables: Optional[List[Table]] = Field(alias="table", default=None)
    mask_functions: Optional[List[Function]] = Field(
        alias="mask_functions", default=None
    )


class Catalog(PrivilegedObject):
    schemas: Optional[List[Schema]] = Field(alias="schemas", default=None)


class WorkspaceUser(BaseObject):
    email: Optional[str] = Field(alias="email", default=None)


class WorkspaceGroupMember(BaseObject):
    type: Optional[IamType] = Field(alias="type", default=None)


class WorkspaceGroup(BaseObject):
    members: Optional[List[WorkspaceGroupMember]] = Field(alias="members", default=None)


class Workspace(BaseObject):
    catalog: Optional[Catalog] = Field(alias="catalog", default=None)
    users: Optional[List[WorkspaceUser]] = Field(alias="users", default=None)
    groups: Optional[List[WorkspaceGroup]] = Field(alias="groups", default=None)

class DatabricksSourceMap(SourceMap):
    workspace_url: Optional[str] = Field(alias="workspace_url", default=None)