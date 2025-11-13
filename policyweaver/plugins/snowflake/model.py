from pydantic import Field
from typing import Optional, List

from policyweaver.core.enum import ColumnMaskType, RowFilterType
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


class SnowflakeTableWithPolicy(CommonBaseModel):
    """
    Represents a table in Snowflake that has column masks applied.
    Attributes:
        database_name (Optional[str]): The name of the database containing the table.
        schema_name (Optional[str]): The name of the schema containing the table.
        table_name (Optional[str]): The name of the table.
        column_names (Optional[List[str]]): A list of column names in the table that have masks applied.
    """
    database_name: Optional[str] = Field(alias="database_name", default=None)
    schema_name: Optional[str] = Field(alias="schema_name", default=None)
    table_name: Optional[str] = Field(alias="table_name", default=None)
    column_names: Optional[List[str]] = Field(alias="column_names", default=None)


class SnowflakeMaskingPolicy(CommonBaseModel):
    """
    Represents a masking policy in the Snowflake workspace.
    Attributes:
        id (Optional[int]): The unique identifier for the masking policy.
        name (Optional[str]): The name of the masking policy.
        database_name (Optional[str]): The name of the database to which the masking policy applies.
        schema_name (Optional[str]): The name of the schema to which the masking policy applies.
        entity_name (Optional[str]): The name of the entity to which the masking policy applies.
        column_name (Optional[str]): The name of the column to which the masking policy applies.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    database_name: Optional[str] = Field(alias="database_name", default=None)
    schema_name: Optional[str] = Field(alias="schema_name", default=None)
    table_name: Optional[str] = Field(alias="table_name", default=None)
    column_name: Optional[str] = Field(alias="column_name", default=None)
    group_names: Optional[List[str]] = Field(alias="group_names", default=None)
    mask_pattern: Optional[str] = Field(alias="mask_pattern", default=None)
    column_mask_type: Optional[ColumnMaskType] = Field(alias="column_mask_type", default=None)

class SnowflakeColumnMaskExtraction(CommonBaseModel):
    """
    Represents the result of extracting group name and mask pattern from a column mask function definition.
    Attributes:
        group_name (Optional[str]): The name of the group associated with the column mask.
        mask_pattern (Optional[str]): The mask pattern applied by the column mask.
        column_mask_type (Optional[ColumnMaskType]): The type of the column mask (e.g., UNMASK_FOR_GROUP, MASK_FOR_GROUP, UNSUPPORTED).
    """
    group_names: Optional[List[str]] = Field(alias="group_name", default=None)
    mask_pattern: Optional[str] = Field(alias="mask_pattern", default=None)
    column_mask_type: Optional[ColumnMaskType] = Field(alias="column_mask_type", default=None)

class SnowflakeColumnMask(CommonBaseModel):
    """
    Represents a column mask that can be applied to data in the Databricks workspace.
    This class extends BaseObject to include the routine definition of the mask.
    Attributes:
        name: (Optional[str]): The name of the column mask .
        routine_definition (Optional[str]): The SQL definition of the column mask routine.
        column_name (Optional[str]): The name of the column to which the mask applies.
    """

    name: Optional[str] = Field(alias="name", default=None)
    routine_definition: Optional[str] = Field(alias="routine_definition", default=None)
    column_name: Optional[str] = Field(alias="column_name", default=None)
    mask_type: Optional[ColumnMaskType] = Field(alias="mask_type", default=None)
    group_names: Optional[List[str]] = Field(alias="group_name", default=None)
    mask_pattern: Optional[str] = Field(alias="mask_pattern", default=None)

class RowFilterDetailGroup(CommonBaseModel):
    """
    Represents a group within a row filter, including its name and return value.
    Attributes:
        group_name (Optional[str]): The name of the group associated with the row filter.
        return_value (Optional[str]): The value returned by the row filter for this group.
    """
    group_name: Optional[str] = Field(alias="group_name", default=None)
    return_value: Optional[str] = Field(alias="return_value", default=None)

class RowFilterDetails(CommonBaseModel):
    """
    Represents the extraction of a row filter from a SQL definition.
    This class is used to capture the details of a row filter, including the group name and condition for others.
    Attributes:
        group_name (Optional[str]): The name of the group associated with the row filter.
        row_filter_type (Optional[RowFilterType]): The type of the row filter (e.g., EXPLICIT_GROUP_MEMBERSHIP).
        default_value (Optional[str]): The default value returned by the row filter when no group matches.
    """
    groups: Optional[List[RowFilterDetailGroup]] = Field(alias="groups", default=None)
    row_filter_type: Optional[RowFilterType] = Field(alias="row_filter_type", default=None)
    default_value: Optional[str] = Field(alias="default_value", default=None)

class SnowflakeRowFilter(CommonBaseModel):
    """
    Represents a row filter that can be applied to data in the Databricks workspace.
    This class extends CommonBaseModel to include the routine definition of the filter.
    Attributes:
        name: (Optional[str]): The name of the row filter.
        routine_definition (Optional[str]): The SQL definition of the row filter routine.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    routine_definition: Optional[str] = Field(alias="routine_definition", default=None)
    database_name: Optional[str] = Field(alias="database_name", default=None)
    schema_name: Optional[str] = Field(alias="schema_name", default=None)
    table_name: Optional[str] = Field(alias="table_name", default=None)
    details: Optional[RowFilterDetails] = Field(alias="details", default=None)

class SnowflakeDatabaseMap(CommonBaseModel):
    """
    A collection of Snowflake users, roles, and grants for a database
    Attributes:
        users (List[SnowflakeUser]): The list of users in the Snowflake database.
        roles (List[SnowflakeRole]): The list of roles in the Snowflake database.
        grants (List[SnowflakeGrant]): The list of grants in the Snowflake database.
        masking_policies (List[SnowflakeMaskingPolicy]): The list of masking policies in the Snowflake database.
    """
    users: List[SnowflakeUser] = Field(alias="users", default_factory=list)
    roles: List[SnowflakeRole] = Field(alias="roles", default_factory=list)
    grants: List[SnowflakeGrant] = Field(alias="grants", default_factory=list)
    masking_policies: List[SnowflakeMaskingPolicy] = Field(alias="masking_policies", default_factory=list)
    tables_with_masks: List[SnowflakeTableWithPolicy] = Field(alias="tables_with_masks", default_factory=list)
    row_access_policies: List[SnowflakeRowFilter] = Field(alias="row_access_policies", default_factory=list)
    tables_with_raps: List[SnowflakeTableWithPolicy] = Field(alias="tables_with_raps", default_factory=list)
    unsupported_tables: List[SnowflakeTableWithPolicy] = Field(alias="unsupported_tables", default_factory=list)

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