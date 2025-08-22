from pydantic import Field
from typing import Optional, List, Dict

from policyweaver.core.utility import Utils
from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap
from policyweaver.core.enum import IamType


class SnowflakeUser(CommonBaseModel):
    """
    Represents a user in the Snowflake workspace.
    This class extends BaseObject to include additional attributes specific to users.
    Attributes:
        id (Optional[int]): The unique identifier for the user.
        name (Optional[str]): The name of the user.
        email (Optional[str]): The email address of the user.
        login_name (Optional[str]): The login name of the user.
        role_assignments (List[SnowflakeRole]): The roles that this user is assigned to.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    email: Optional[str] = Field(alias="email", default=None)
    login_name: Optional[str] = Field(alias="login_name", default=None)
    role_assignments: List["SnowflakeRole"] = Field(alias="role_assignments", default_factory=list)

class SnowflakeRole(CommonBaseModel):
    """
    Represents a role in the Snowflake workspace.
    This class extends BaseObject to include additional attributes specific to roles.
    Attributes:
        id (Optional[int]): The unique identifier for the role.
        name (Optional[str]): The name of the role.
        members_user (List[SnowflakeUser]): The users that are assigned to this role.
        members_role (List[SnowflakeRole]): The roles that are assigned to this role.
        role_assignments (List[SnowflakeRole]): The roles that this role is assigned to.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    members_user: List[SnowflakeUser] = Field(alias="members_user", default_factory=list)
    members_role: List["SnowflakeRole"] = Field(alias="members_role", default_factory=list)
    role_assignments: List["SnowflakeRole"] = Field(alias="role_assignments", default_factory=list)

class SnowflakeGrant(CommonBaseModel):
    # To be implemented
    id: Optional[int] = Field(alias="id", default=None)

class SnowflakeDatabaseMap(CommonBaseModel):
    """
    A collection of Snowflake users, roles, and grants for a database
    """
    users: List[SnowflakeUser] = Field(alias="users", default_factory=list)
    roles: List[SnowflakeRole] = Field(alias="roles", default_factory=list)
    grants: List[SnowflakeGrant] = Field(alias="grants", default_factory=list)

class SnowflakeConnection(CommonBaseModel):
    """
    Represents a connection to a Snowflake account.
    Attributes:
        account_name (Optional[str]): The name of the Snowflake account.
        user_name (Optional[str]): The user name for accessing the Snowflake account.
        password (Optional[str]): The password for accessing the Snowflake account.
        warehouse (Optional[str]): The warehouse to use for the Snowflake connection.
    """
    account_name: Optional[str] = Field(alias="account_name", default=None)
    user_name: Optional[str] = Field(alias="user_name", default=None)
    password: Optional[str] = Field(alias="password", default=None)
    warehouse: Optional[str] = Field(alias="warehouse", default=None)

class SnowflakeSourceConfig(CommonBaseModel):
    """
    Represents the configuration for a Snowflake source.
    This class includes the account name, user name, and password.
    Attributes:
        account_name (Optional[str]): The name of the Snowflake account.
        user_name (Optional[str]): The user name for accessing the Snowflake account.
        password (Optional[str]): The password for accessing the Snowflake account.
        warehouse (Optional[str]): The warehouse to use for the Snowflake connection.
    """
    account_name: Optional[str] = Field(alias="account_name", default=None)
    user_name: Optional[str] = Field(alias="user_name", default=None)
    password: Optional[str] = Field(alias="password", default=None)
    warehouse: Optional[str] = Field(alias="warehouse", default=None)

class SnowflakeSourceMap(SourceMap):
    snowflake: Optional[SnowflakeSourceConfig] = Field(alias="snowflake", default=None)