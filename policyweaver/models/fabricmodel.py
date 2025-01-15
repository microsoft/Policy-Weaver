from policyweaver.models.common import CommonBaseModel, CommonBaseEnum
from typing import List, Optional
from pydantic import Field


class FabricPolicyAccessType(str, CommonBaseEnum):
    EXECUTE = "Execute"
    EXPLORE = "Explore"
    READ = "Read"
    READ_ALL = "ReadAll"
    RESHARE = "Reshare"
    WRITE = "Write"


class FabricMemberObjectType(str, CommonBaseEnum):
    GROUP = "Group"
    MANAGED_IDENTITY = "ManagedIdentity"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    USER = "User"


class PolicyEffectType(str, CommonBaseEnum):
    PERMIT = "Permit"


class PolicyAttributeType(str, CommonBaseEnum):
    ACTION = "Action"
    PATH = "Path"


class EntraMember(CommonBaseModel):
    object_id: Optional[str] = Field(alias="objectId", default=None)
    object_type: Optional[FabricMemberObjectType] = Field(
        alias="objectType", default=None
    )
    tenant_id: Optional[str] = Field(alias="tenantId", default=None)


class PolicyMember(CommonBaseModel):
    source_path: Optional[str] = Field(alias="sourcePath", default=None)
    item_access: Optional[List[FabricPolicyAccessType]] = Field(
        alias="itemAccess", default=None
    )


class PolicyMembers(CommonBaseModel):
    fabric_members: Optional[List[PolicyMember]] = Field(
        alias="fabricItemMembers", default=None
    )
    entra_members: Optional[List[EntraMember]] = Field(
        alias="microsoftEntraMembers", default=None
    )


class PolicyPermissionScope(CommonBaseModel):
    attribute_name: Optional[PolicyAttributeType] = Field(
        alias="attributeName", default=None
    )
    attribute_value_included_in: Optional[List[str]] = Field(
        alias="attributeValueIncludedIn", default=None
    )


class PolicyDecisionRule(CommonBaseModel):
    effect: Optional[PolicyEffectType] = Field(alias="effect", default=None)
    permission: Optional[List[PolicyPermissionScope]] = Field(
        alias="permission", default=None
    )


class DataAccessPolicy(CommonBaseModel):
    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    decision_rules: Optional[List[PolicyDecisionRule]] = Field(
        alias="decisionRules", default=None
    )
    members: Optional[PolicyMembers] = Field(alias="members", default=None)
