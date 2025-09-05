from pydantic import Field
from typing import Optional, List

from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap


class SnowflakeUserOrRole(CommonBaseModel):
    """
    Represents a user or role in the Snowflake workspace.
    This class is a base class for both users and roles.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)

class SnowflakeUser(SnowflakeUserOrRole):
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

class SnowflakeRole(SnowflakeUserOrRole):
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

class SnowflakeRoleMemberMap(CommonBaseModel):
    """
    Represents the members of a Snowflake role.
    This class includes the users and roles that are members of the role.
    Attributes:
        users (List[SnowflakeUser]): The users that are members of the role.
        roles (List[SnowflakeRole]): The roles that are members of the role.
    """
    role_name: Optional[str] = Field(alias="role_name", default=None)
    users: List[SnowflakeUser] = Field(alias="users", default_factory=list)
    roles: List["SnowflakeRole"] = Field(alias="roles", default_factory=list)

class SnowflakeGrant(CommonBaseModel):
    """
    Represents a grant in the Snowflake workspace.
    Attributes:
        privilege (Optional[str]): The privilege granted.
        granted_on (Optional[str]): The object type on which the privilege is granted.
        table_catalog (Optional[str]): The catalog of the table.
        table_schema (Optional[str]): The schema of the table.
        name (Optional[str]): The name of the object.
        grantee_name (Optional[str]): The name of the grantee (user or role).
    """
    
    privilege: Optional[str] = Field(alias="privilege", default=None)
    granted_on: Optional[str] = Field(alias="granted_on", default=None)
    table_catalog: Optional[str] = Field(alias="table_catalog", default=None)
    table_schema: Optional[str] = Field(alias="table_schema", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    grantee_name: Optional[str] = Field(alias="grantee_name", default=None)

class SnowflakeDatabaseMap(CommonBaseModel):
    """
    A collection of Snowflake users, roles, and grants for a database
    Attributes:
        users (List[SnowflakeUser]): The list of users in the Snowflake database.
        roles (List[SnowflakeRole]): The list of roles in the Snowflake database.
        grants (List[SnowflakeGrant]): The list of grants in the Snowflake database.
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
    private_key_file: Optional[str] = Field(alias="private_key_file", default=None)
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
        private_key_file (Optional[str]): The path to the private key file for accessing the Snowflake account.
    """
    account_name: Optional[str] = Field(alias="account_name", default=None)
    user_name: Optional[str] = Field(alias="user_name", default=None)
    password: Optional[str] = Field(alias="password", default=None)
    warehouse: Optional[str] = Field(alias="warehouse", default=None)
    private_key_file: Optional[str] = Field(alias="private_key_file", default=None)

class SnowflakeSourceMap(SourceMap):
    """
    Represents the configuration for a Snowflake source map.
    This class extends SourceMap to include Snowflake-specific configuration.
    Attributes:
        snowflake (Optional[SnowflakeSourceConfig]): The Snowflake source configuration.
    """
    snowflake: Optional[SnowflakeSourceConfig] = Field(alias="snowflake", default=None)