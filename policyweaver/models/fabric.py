from typing import List, Optional
from pydantic import Field

from policyweaver.models.common import CommonBaseModel
from policyweaver.core.enum import (
    FabricMemberObjectType,
    FabricPolicyAccessType,
    PolicyAttributeType,
    PolicyEffectType
)

class EntraMember(CommonBaseModel):
    """
    Represents a member in Microsoft Entra.
    Attributes:
        object_id: The unique identifier of the member.
        object_type: The type of the member (e.g., Group, User).
        tenant_id: The identifier of the tenant to which the member belongs.
    """
    object_id: Optional[str] = Field(alias="objectId", default=None)
    object_type: Optional[FabricMemberObjectType] = Field(
        alias="objectType", default=None
    )
    tenant_id: Optional[str] = Field(alias="tenantId", default=None)

class PolicyMember(CommonBaseModel):
    """
    Represents a member in a Fabric policy.
    Attributes:
        object_id: The unique identifier of the member.
        object_type: The type of the member (e.g., Group, User).
        tenant_id: The identifier of the tenant to which the member belongs.
        source_path: The source path associated with the member.
        item_access: A list of access types granted to the member.
    """
    source_path: Optional[str] = Field(alias="sourcePath", default=None)
    item_access: Optional[List[FabricPolicyAccessType]] = Field(alias="itemAccess", default=None)

class PolicyMembers(CommonBaseModel):
    """
    Represents the members of a policy, including Fabric and Entra members.
    Attributes:
        fabric_members: A list of Fabric policy members.
        entra_members: A list of Microsoft Entra members.
    """
    fabric_members: Optional[List[PolicyMember]] = Field(alias="fabricItemMembers", default=None)
    entra_members: Optional[List[EntraMember]] = Field(alias="microsoftEntraMembers", default=None)


class PolicyPermissionScope(CommonBaseModel):
    """
    Represents the scope of permissions in a policy.
    Attributes:
        attribute_name: The name of the attribute for the permission scope.
        attribute_value_included_in: A list of values that are included in the attribute.
    """
    attribute_name: Optional[PolicyAttributeType] = Field(alias="attributeName", default=None)
    attribute_value_included_in: Optional[List[str]] = Field(alias="attributeValueIncludedIn", default=None)

class ColumnConstraint(CommonBaseModel):
    """
    Represents a column constraint in a policy decision rule.
    Attributes:
        table_path: The path of the table to which the constraint applies.
        column_names: A list of column names to which the constraint applies.
        column_effect: The effect of the constraint (e.g., Permit).
        column_action: The action associated with the constraint (e.g., Read, Write).
    """
    table_path: Optional[str] = Field(alias="tablePath", default=None)
    column_names: Optional[List[str]] = Field(alias="columnNames", default=None)
    column_effect: Optional[PolicyEffectType] = Field(alias="columnEffect", default=None)
    column_action: Optional[List[FabricPolicyAccessType]] = Field(alias="columnAction", default=None)

class RowConstraint(CommonBaseModel):
    """
    Represents a row constraint in a policy decision rule.
    Attributes:
        table_path: The path of the table to which the constraint applies.
        value: The condition or value defining the row constraint.
    """
    table_path: Optional[str] = Field(alias="tablePath", default=None)
    value: Optional[str] = Field(alias="value", default=None)

class Constraints(CommonBaseModel):
    """
    Represents constraints in a policy decision rule.
    Attributes:
        columns: A list of column constraints associated with the policy decision.
    """
    columns: Optional[List[ColumnConstraint]] = Field(alias="columns", default=None)
    rows: Optional[List['RowConstraint']] = Field(alias="rows", default=None)


class PolicyDecisionRule(CommonBaseModel):
    """
    Represents a decision rule in a policy.
    Attributes:
        effect: The effect of the policy decision (e.g., Permit).
        permission: A list of permission scopes associated with the policy decision.
    """
    effect: Optional[PolicyEffectType] = Field(alias="effect", default=None)
    permission: Optional[List[PolicyPermissionScope]] = Field(alias="permission", default=None)
    constraints: Optional[Constraints] = Field(alias="constraints", default=None)


class DataAccessPolicy(CommonBaseModel):
    """
    Represents a data access policy in a Fabric environment.
    Attributes:
        id: The unique identifier of the policy.
        name: The name of the policy.
        decision_rules: A list of decision rules associated with the policy.
        members: The members associated with the policy, including Fabric and Entra members.
    """
    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    decision_rules: Optional[List[PolicyDecisionRule]] = Field(alias="decisionRules", default=None)
    members: Optional[PolicyMembers] = Field(alias="members", default=None)
