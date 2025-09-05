import logging
import pandas as pd
import json
import os
from pydantic.json import pydantic_encoder

import snowflake.connector

from typing import List, Tuple

from policyweaver.models.config import (
    SourceSchema, Source
)
from policyweaver.plugins.databricks.model import (
    DatabricksUser, DatabricksServicePrincipal, DatabricksGroup,
    DatabricksGroupMember, Account, Workspace, Catalog, Schema, Table,
    Function, FunctionMap, Privilege,
)

from policyweaver.plugins.snowflake.model import (
    SnowflakeConnection,
    SnowflakeGrant,
    SnowflakeRole,
    SnowflakeRoleMemberMap,
    SnowflakeUser,
    SnowflakeDatabaseMap,
    SnowflakeUserOrRole
)
from policyweaver.core.enum import (
    IamType
)

from policyweaver.core.auth import ServicePrincipal

class SnowflakeAPIClient:
    """
    Snowflake API Client for fetching account policies.
    This client uses the Snowflake SDK to interact with the Snowflake account
    and retrieve users, databases, schemas, tables, and privileges.
    This class is designed to be used within the Policy Weaver framework to gather and map policies
    from Snowflake workspaces and accounts.
    """
    def __init__(self):
        """
        Initializes the Snowflake API Client with a connection to the Snowflake account.
        Sets up the logger for the client.
        Raises:
            EnvironmentError: If required environment variables are not set.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")

        private_key_file = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE", None)
        if not private_key_file or not os.path.isfile(private_key_file):
            self.logger.warning("SNOWFLAKE_PRIVATE_KEY_FILE environment variable is not set or the file does not exist. Trying user/password authentication.")
            self.connection = SnowflakeConnection(
                user_name=os.environ["SNOWFLAKE_USER"],
                password=os.environ["SNOWFLAKE_PASSWORD"],
                account_name=os.environ["SNOWFLAKE_ACCOUNT"],
                warehouse=os.environ["SNOWFLAKE_WAREHOUSE"]
            )
        else:
            self.connection = SnowflakeConnection(
                user_name=os.environ["SNOWFLAKE_USER"],
                password=os.environ["SNOWFLAKE_PASSWORD"],
                account_name=os.environ["SNOWFLAKE_ACCOUNT"],
                warehouse=os.environ["SNOWFLAKE_WAREHOUSE"],
                private_key_file=private_key_file
            )

        self.users = None
        self.roles = None
        self.grants = None
        self.role_assignments = None
        self.user_assignments = None



    def __get_snowflake_connection__(self) -> snowflake.connector.SnowflakeConnection:
        """
        Establishes a connection to the Snowflake account.
        Returns:
            snowflake.connector.SnowflakeConnection: A connection object to the Snowflake account.
        Raises:
            EnvironmentError: If required environment variables are not set.
        """

        if self.connection.private_key_file:

            private_key_file = self.connection.private_key_file
            private_key_file_pwd = self.connection.password

            conn_params = {
                'account': self.connection.account_name,
                'user': self.connection.user_name,
                'authenticator': 'SNOWFLAKE_JWT',
                'private_key_file': private_key_file,
                'private_key_file_pwd':private_key_file_pwd,
                'warehouse': self.connection.warehouse,
                'disable_ocsp_checks': True,
                'database': 'SNOWFLAKE',
                'schema': 'ACCOUNT_USAGE'
            }

            ctx = snowflake.connector.connect(**conn_params)
            return ctx
        else:
            return snowflake.connector.connect(
                user=self.connection.user_name,
                password=self.connection.password,
                account=self.connection.account_name,
                warehouse=self.connection.warehouse,
                disable_ocsp_checks=True,
                database="SNOWFLAKE",
                schema="ACCOUNT_USAGE"
            )
        

    def __run_query__(self, query: str, columns: List[str]) -> List[dict]:
        """
        Execute a SQL query against Snowflake and return the results.

        Args:
            query (str): SQL query to execute

        Returns:
            list: Query results as a list of tuples
        """
        with self.__get_snowflake_connection__() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                results = cur.fetchall()
        return [dict(zip(columns, row)) for row in results]

    def __get_database_map__(self) -> SnowflakeDatabaseMap:
        """
        Retrieves the database map from the Snowflake account.
        Returns:
            dict: A dictionary mapping database names to their schemas.
            NotFound: If the catalog specified in the source is not found in the workspace.
        """
        
        # get users

        self.users = self.__get_users__()

        # get roles

        self.roles = self.__get_roles__()

        # get direct and indirect members for each role

        role_memberships = self.__get_role_memberships__()
        for role in self.roles:
            role_name = role.name
            role.members_user = role_memberships[role_name].users
            role.members_role = role_memberships[role_name].roles

        # get user/role to role memberships

        user_role_assignments = self.__get_user_role_assignments__()
        for u in self.users:
            u.role_assignments = user_role_assignments[u.name]
        for r in self.roles:
            r.role_assignments = user_role_assignments[r.name]

        # get grants to roles and users

        self.grants = self.__get_grants__()

        return SnowflakeDatabaseMap(users=self.users, roles=self.roles, grants=self.grants)

    def __get_grants__(self, database="DEMODATA") -> List[SnowflakeGrant]:

        query = f"""select   "PRIVILEGE", "GRANTED_ON", "TABLE_CATALOG", "TABLE_SCHEMA", "NAME", "GRANTEE_NAME"
                    from     SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                    where    DELETED_ON is null and
                            GRANTED_ON in ('TABLE','SCHEMA','DATABASE') and
                            TABLE_CATALOG = '{database}'"""
        
        grants_raw = self.__run_query__(query, columns=["PRIVILEGE", "GRANTED_ON", "TABLE_CATALOG", "TABLE_SCHEMA", "NAME", "GRANTEE_NAME"]) 

        grants = [SnowflakeGrant(privilege=grant["PRIVILEGE"],
                                 granted_on=grant["GRANTED_ON"],
                                 table_catalog=grant["TABLE_CATALOG"],
                                 table_schema=grant["TABLE_SCHEMA"],
                                 name=grant["NAME"],
                                 grantee_name=grant["GRANTEE_NAME"]) for grant in grants_raw]
        
        return grants

    def __get_user_role_assignment__(self, user: SnowflakeUserOrRole, is_user: bool) -> List[SnowflakeRole]:
        
        if is_user:
            directly_assigned = [role["NAME"] for role in self.user_assignments if role["GRANTEE_NAME"] == user.name]
        else:
            directly_assigned = [role["NAME"] for role in self.role_assignments if role["GRANTEE_NAME"] == user.name]

        assigned_roles = [role for role in self.roles if role.name in directly_assigned]

        # Inherited assignment
        for role in assigned_roles:
            inherited_roles = self.__get_user_role_assignment__(role, is_user=False)
            assigned_roles.extend(inherited_roles)

        return assigned_roles

    def __get_user_role_assignments__(self) -> dict[str, List[SnowflakeRole]]:
        user_role_assignments = dict()
        for user in self.users:
            user_role_assignments[user.name] = self.__get_user_role_assignment__(user, is_user=True)

        for role in self.roles:
            user_role_assignments[role.name] = self.__get_user_role_assignment__(role, is_user=False)

        return user_role_assignments

    def __get_role_membership__(self, role_name) -> Tuple[List[str], List[str]]:

        users = [user["GRANTEE_NAME"] for user in self.user_assignments if user["NAME"] == role_name]
        roles = list()

        for role_ass in self.role_assignments:
            if role_ass["NAME"] == role_name:
                roles.append(role_ass["GRANTEE_NAME"])

                users_, roles_ = self.__get_role_membership__(role_name=role_ass["GRANTEE_NAME"])
                users.extend(users_)
                roles.extend(roles_)

        return users, roles

    def __get_role_memberships__(self) -> dict[str, SnowflakeRoleMemberMap]:

        role_query = f"""select  "NAME", GRANTEE_NAME
                    from    SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                    where   GRANTED_TO = 'ROLE' and
                            GRANTED_ON = 'ROLE' and
                            DELETED_ON is null and
                            PRIVILEGE = 'USAGE'"""

        self.role_assignments = self.__run_query__(role_query, columns=["NAME", "GRANTEE_NAME"])

        user_query = f"""select   "ROLE", GRANTEE_NAME 
                        from     SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                        WHERE DELETED_ON is null"""

        self.user_assignments = self.__run_query__(user_query, columns=["NAME", "GRANTEE_NAME"])

        role_memberships = dict()
        for role in self.roles:
            role_name = role.name
            users, roles = self.__get_role_membership__(role_name)

            member_users = [user for user in self.users if user.name in users]
            member_roles = [role for role in self.roles if role.name in roles]

            role_memberships[role_name] = SnowflakeRoleMemberMap(
                role_name=role_name,
                users=member_users,
                roles=member_roles
            )

        return role_memberships

    def __get_users__(self) -> List[SnowflakeUser]:

        columns = ["USER_ID", "NAME", "LOGIN_NAME", "EMAIL"]

        query = f"""SELECT {', '.join(columns)}
                    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS where DELETED_ON is null and DISABLED = false
                    """

        users = self.__run_query__(query, columns=columns)
        return [SnowflakeUser(
            id=user["USER_ID"],
            name=user["NAME"],
            login_name=user["LOGIN_NAME"],
            email=user["EMAIL"]
        ) for user in users]

    def __get_roles__(self) -> List[SnowflakeRole]:
        """
        Retrieves all roles from the Snowflake account.
        Returns:
            List[SnowflakeRole]: A list of SnowflakeRole objects representing the roles in the account.
        """
        columns = ["ROLE_ID", "NAME"]

        query = f"""SELECT {', '.join(columns)}
                    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES where DELETED_ON is null and ROLE_TYPE = 'ROLE'

                    """

        roles = self.__run_query__(query, columns=columns)
        return [SnowflakeRole(
            id=role["ROLE_ID"],
            name=role["NAME"]
        ) for role in roles]

    def get_grants(self, database: str) -> pd.DataFrame:
        """
        Retrieves all grants from the Snowflake account.
        This method fetches grants for users, roles, and privileges across databases, schemas, and tables.
        Returns:
            pd.DataFrame: A DataFrame containing grant information.
        """
        raise NotImplementedError("Method not implemented yet.")