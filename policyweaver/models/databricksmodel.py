from policyweaver.models.common import (
    CommonBaseModel,
    CommonBaseEnum,
    IamType,
    SourceMap
)

from pydantic import Field
from typing import Optional, List, Dict

class UnityCatalogPrincipalType(str, CommonBaseEnum):
    USER = "USER"
    GROUP = "GROUP"

class DependencyMap(CommonBaseModel):
    catalog: Optional[str] = Field(alias="catalog", default=None)
    catalog_schema: Optional[str] = Field(alias="schema", default=None)
    table: Optional[str] = Field(alias="table", default=None)
    privileges: Optional[List[str]] = Field(alias="privileges", default=[])
    catalog_prerequisites: Optional[bool] = Field(alias="catalog_prerequisites", default=False)
    schema_prerequisites: Optional[bool] = Field(alias="schema_prerequisites", default=False)
    read_permissions: Optional[bool] = Field(alias="read_permissions", default=False)

    @property
    def key(self) -> str:
        s = f".{self.catalog_schema}" if self.catalog_schema else ""
        t = f".{self.table}" if self.table else ""

        return f"{self.catalog}{s}{t}".lower()

class PrivilegeSnapshot(CommonBaseModel):
    principal: Optional[str] = Field(alias="principal", default=None)
    type: Optional[UnityCatalogPrincipalType] = Field(alias="type", default=None)
    maps: Optional[Dict[str, DependencyMap]] = Field(alias="maps", default={})    
    group_membership: Optional[List[str]] = Field(alias="group_membership", default=[])

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

    def lookup_user_by_id(self, id: str) -> WorkspaceUser:
        user = list(filter(lambda u: u.id == id, self.users))

        if user:
            return user[0]

        return None

    def lookup_user_by_email(self, email: str) -> WorkspaceUser:
        user = list(filter(lambda u: u.email == email, self.users))

        if user:
            return user[0]

        return None
    
    def lookup_group_by_name(self, name: str) -> WorkspaceUser:
        group = list(filter(lambda g: g.name == name, self.groups))

        if group:
            return group[0]
        
        return None
    
    def lookup_object_id(self, principal:str, type:IamType) -> str:
        if type == IamType.USER:
            u = self.lookup_user_by_email(principal)
            return u.id if u else None
        else:
            g = self.lookup_group_by_name(principal)
            return g.id if g else None
    
    def get_user_groups(self, object_id:str) -> List[str]:
        membership = []
        
        for g in self.groups:
            membership = self.__extend_with_dedup__(membership, 
                                                    self.__flatten_group__(g.name, object_id))                  

        return membership
    
    def __extend_with_dedup__(self, src, new):
        if not src or len(src) == 0:
            return new

        if not new or len(new) == 0:
            return src

        s = set(src)
        s.update(new)

        return list(s)
    
    def __flatten_group__(self, name: str, id: str) -> List[str]:
        group = self.lookup_group_by_name(name)
        membership = []

        if group:
            for m in group.members:
                if m.type == IamType.USER and m.id == id:
                    if m.name not in membership:
                        membership.append(group.name)
                elif m.type == IamType.GROUP:
                    membership = self.__extend_with_dedup__(
                        membership, self.__flatten_group__(m.name, id)
                    )

        return membership

class DatabricksSourceMap(SourceMap):
    workspace_url: Optional[str] = Field(alias="workspace_url", default=None)