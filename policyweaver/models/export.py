from typing import Optional, List
from pydantic import Field

from policyweaver.models.common import CommonBaseModel
from policyweaver.core.enum import IamType, PolicyWeaverConnectorType
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