from enum import Enum

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

class ColumnMaskType(str, CommonBaseEnum):
    """
    Enum representing different types of column masks.
    This enum is used to categorize column masks.
    Attributes:
        GROUP_MEMBERSHIP (str): Represents a column mask based on group membership.
    """    
    UNMASK_FOR_GROUP = "UNMASK_FOR_GROUP"
    MASK_FOR_GROUP = "MASK_FOR_GROUP"
    UNSUPPORTED = "UNSUPPORTED"

class RowFilterType(str, CommonBaseEnum):
    """
    Enum representing different types of row filters.
    This enum is used to categorize row filters.
    Attributes:
        GROUP_MEMBERSHIP (str): Represents a row filter based on group membership.
    """
    EXPLICIT_GROUP_MEMBERSHIP = "EXPLICIT_GROUP_MEMBERSHIP"
    UNSUPPORTED = "UNSUPPORTED"

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

class FabricPolicyAccessType(str, CommonBaseEnum):
    """
    Enum representing the access types for Fabric policies.
    Attributes:
        EXECUTE: Permission to execute actions.
        EXPLORE: Permission to explore resources.
        READ: Permission to read resources.
        READ_ALL: Permission to read all resources.
        RESHARE: Permission to reshare resources.
        WRITE: Permission to write or modify resources.
    """
    EXECUTE = "Execute"
    EXPLORE = "Explore"
    READ = "Read"
    READ_ALL = "ReadAll"
    RESHARE = "Reshare"
    WRITE = "Write"

class FabricMemberObjectType(str, CommonBaseEnum):
    """
    Enum representing the types of Fabric members.
    Attributes:
        GROUP: Represents a group of members.
        MANAGED_IDENTITY: Represents a managed identity.
        SERVICE_PRINCIPAL: Represents a service principal.
        USER: Represents a user.
    """
    GROUP = "Group"
    MANAGED_IDENTITY = "ManagedIdentity"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    USER = "User"


class PolicyEffectType(str, CommonBaseEnum):
    """
    Enum representing the effect types for policies.
    Attributes:
        PERMIT: Indicates that the action is permitted.
    """
    PERMIT = "Permit"


class PolicyAttributeType(str, CommonBaseEnum):
    """
    Enum representing the types of attributes for policies.
    Attributes:
        ACTION: Represents an action attribute.
        PATH: Represents a path attribute.
    """
    ACTION = "Action"
    PATH = "Path"