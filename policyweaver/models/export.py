from typing import Optional, List
from pydantic import Field

from policyweaver.models.common import CommonBaseModel
from policyweaver.core.enum import IamType, PolicyWeaverConnectorType, PermissionType, PermissionState
from policyweaver.models.config import CatalogItem, Source

class PermissionObject(CommonBaseModel):
    """
    Represents an object in a permission.
    Attributes:
        id (str): The unique identifier for the object.
        type (IamType): The type of the IAM entity associated with the object.
        email (str): The email of the IAM entity, if applicable.
        app_id (str): The application ID of the IAM entity, if applicable.
    """
    id: Optional[str] = Field(alias="id", default=None)
    email: Optional[str] = Field(alias="email", default=None)
    app_id: Optional[str] = Field(alias="app_id", default=None)
    type: Optional[IamType] = Field(alias="type", default=None)
    entra_object_id: Optional[str] = Field(alias="entra_object_id", default=None)

    @property
    def lookup_id(self) -> str:
        """
        Returns the identifier used for looking up the object.
        Depending on the type of IAM entity, it returns either the email, app_id, or id.
        Returns:
            str: The identifier for the object based on its type.
        """
        if self.type == IamType.USER:
            return self.email
        elif self.type == IamType.SERVICE_PRINCIPAL:
            return self.app_id
        elif self.type == IamType.GROUP:
            return self.id
        return self.id

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
    name: Optional[PermissionType] = Field(alias="name", default=None)
    state: Optional[PermissionState] = Field(alias="state", default=None)
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


class PermissionScope(CommonBaseModel):
    """
    Represents the scope of a permission in the Policy Weaver application.
    Attributes:
        catalog (str): The catalog to which the permission applies.
        catalog_schema (str): The schema of the catalog.
        table (str): The table associated with the permission.
        name (str): The name of the permission like read or write.
        state (str): The state of the permission like permit or deny
    """
    catalog: Optional[str] = Field(alias="catalog", default=None)
    catalog_schema: Optional[str] = Field(alias="catalog_schema", default=None)
    table: Optional[str] = Field(alias="table", default=None)
    name: Optional[PermissionType] = Field(alias="name", default=None)
    state: Optional[PermissionState] = Field(alias="state", default=None)

class ColumnConstraint(CommonBaseModel):
    """
    Represents a constraint in the Policy Weaver application.
    Attributes:
        column_action (str): The action associated with the column constraint.
        column_effect (str): The effect of the column constraint.
        column_names (List[str]): A list of column names to which the constraint applies.
        table_name (str): The name of the table associated with the constraint.
        schema_name (str): The schema of the table.
        catalog_name (str): The catalog of the table.

    """
    column_actions: Optional[List[PermissionType]] = Field(alias="column_actions", default=None)
    column_effect: Optional[PermissionState] = Field(alias="column_effect", default=None)
    column_names: Optional[List[str]] = Field(alias="column_names", default=None)
    table_name: Optional[str] = Field(alias="table_name", default=None)
    schema_name: Optional[str] = Field(alias="schema_name", default=None)
    catalog_name: Optional[str] = Field(alias="catalog_name", default=None)

class RowConstraint(CommonBaseModel):
    """
    Represents a row-level constraint in the Policy Weaver application.
    Attributes:
        filter_condition (str): The condition used to filter rows.
        table_name (str): The name of the table associated with the constraint.
        schema_name (str): The schema of the table.
        catalog_name (str): The catalog of the table.
    """
    filter_condition: Optional[str] = Field(alias="filter_condition", default=None)
    table_name: Optional[str] = Field(alias="table_name", default=None)
    schema_name: Optional[str] = Field(alias="schema_name", default=None)
    catalog_name: Optional[str] = Field(alias="catalog_name", default=None)

class RolePolicy(CommonBaseModel):
    """
    Represents a policy in the Policy Weaver application.
    Attributes:
        id (str): The unique identifier for the policy.
        name (str): The name of the policy.
        type (str): The type of the policy.
        permissions (List[Permission]): A list of permissions associated with the policy.
        permissionscopes (List[PermissionScope]): A list of permission scopes associated with the policy.
    """
    permissionobjects: Optional[List[PermissionObject]] = Field(alias="permissionobjects", default=None)
    permissionscopes: Optional[List[PermissionScope]] = Field(alias="permissionscopes", default=None)
    columnconstraints: Optional[List[ColumnConstraint]] = Field(alias="columnconstraints", default=None)
    rowconstraints: Optional[List[RowConstraint]] = Field(alias="rowconstraints", default=None)
    name: Optional[str] = Field(alias="name", default=None)

class RolePolicyExport(CommonBaseModel):
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
    policies: Optional[List[RolePolicy]] = Field(alias="policies", default=None)