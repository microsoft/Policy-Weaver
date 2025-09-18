from pydantic import Field
from typing import Optional, List

from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap


class BigQueryUserOrRole(CommonBaseModel):
    """
    Represents a user or role in the BigQuery workspace.
    This class is a base class for both users and roles.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)

class BigQueryUser(BigQueryUserOrRole):
    """
    Represents a user in the BigQuery workspace.
    This class extends BaseObject to include additional attributes specific to users.
    Attributes:
        role_assignments (List[BigQueryRole]): The roles that this user is assigned to.
    """

    ## TBD

    # id: Optional[int] = Field(alias="id", default=None)
    # name: Optional[str] = Field(alias="name", default=None)
    # email: Optional[str] = Field(alias="email", default=None)
    # login_name: Optional[str] = Field(alias="login_name", default=None)
    role_assignments: List["BigQueryRole"] = Field(alias="role_assignments", default_factory=list)

class BigQueryRole(BigQueryUserOrRole):
    """
    Represents a role in the Snowflake workspace.
    This class extends BaseObject to include additional attributes specific to roles.
    Attributes:
        id (Optional[int]): The unique identifier for the role.
        name (Optional[str]): The name of the role.
        members_user (List[BigQueryUser]): The users that are assigned to this role.
        members_role (List[BigQueryRole]): The roles that are assigned to this role.
        role_assignments (List[BigQueryRole]): The roles that this role is assigned to.
    """
    id: Optional[int] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)
    members_user: List[BigQueryUser] = Field(alias="members_user", default_factory=list)
    members_role: List["BigQueryRole"] = Field(alias="members_role", default_factory=list)
    role_assignments: List["BigQueryRole"] = Field(alias="role_assignments", default_factory=list)

class BigQueryRoleMemberMap(CommonBaseModel):
    """
    Represents the members of a BigQuery role.
    This class includes the users and roles that are members of the role.
    Attributes:
        users (List[BigQueryUser]): The users that are members of the role.
        roles (List[BigQueryRole]): The roles that are members of the role.
    """
    role_name: Optional[str] = Field(alias="role_name", default=None)
    users: List[BigQueryUser] = Field(alias="users", default_factory=list)
    roles: List["BigQueryRole"] = Field(alias="roles", default_factory=list)

class BigQueryGrant(CommonBaseModel):
    """
    Represents a grant in the BigQuery workspace.
    Attributes:

    """

    ### TBD
    # privilege: Optional[str] = Field(alias="privilege", default=None)
    # granted_on: Optional[str] = Field(alias="granted_on", default=None)
    # table_catalog: Optional[str] = Field(alias="table_catalog", default=None)
    # table_schema: Optional[str] = Field(alias="table_schema", default=None)
    # name: Optional[str] = Field(alias="name", default=None)
    # grantee_name: Optional[str] = Field(alias="grantee_name", default=None)

class BigQueryDatabaseMap(CommonBaseModel):
    """
    A collection of BigQuery users, roles, and grants for a database
    Attributes:
        users (List[BigQueryUser]): The list of users in the BigQuery database.
        roles (List[BigQueryRole]): The list of roles in the BigQuery database.
        grants (List[BigQueryGrant]): The list of grants in the BigQuery database.
    """
    users: List[BigQueryUser] = Field(alias="users", default_factory=list)
    roles: List[BigQueryRole] = Field(alias="roles", default_factory=list)
    grants: List[BigQueryGrant] = Field(alias="grants", default_factory=list)

class BigQueryConnection(CommonBaseModel):
    """
    Represents a connection to a BigQuery account.
    Attributes:

    """
    ## TBD

    # account_name: Optional[str] = Field(alias="account_name", default=None)
    # user_name: Optional[str] = Field(alias="user_name", default=None)
    # password: Optional[str] = Field(alias="password", default=None)
    # private_key_file: Optional[str] = Field(alias="private_key_file", default=None)
    # warehouse: Optional[str] = Field(alias="warehouse", default=None)

class BigQuerySourceConfig(CommonBaseModel):
    """
    Represents the configuration for a BigQuery source.
    This class includes the account name, user name, and password.
    Attributes:

    """
    ## TBD

    # account_name: Optional[str] = Field(alias="account_name", default=None)
    # user_name: Optional[str] = Field(alias="user_name", default=None)
    # password: Optional[str] = Field(alias="password", default=None)
    # warehouse: Optional[str] = Field(alias="warehouse", default=None)
    # private_key_file: Optional[str] = Field(alias="private_key_file", default=None)

class BigQuerySourceMap(SourceMap):
    """
    Represents the configuration for a BigQuery source map.
    This class extends SourceMap to include BigQuery-specific configuration.
    Attributes:
        bigquery (Optional[BigQuerySourceConfig]): The BigQuery source configuration.
    """
    bigquery: Optional[BigQuerySourceConfig] = Field(alias="bigquery", default=None)