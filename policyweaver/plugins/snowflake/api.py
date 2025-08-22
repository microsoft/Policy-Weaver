import logging
import pandas as pd
import json
import os
from pydantic.json import pydantic_encoder

import snowflake.connector

from typing import List

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
    SnowflakeRole,
    SnowflakeUser,
    SnowflakeDatabaseMap
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

        self.connection = SnowflakeConnection(
            user_name=os.environ["SNOWFLAKE_USER"],
            password=os.environ["SNOWFLAKE_PASSWORD"],
            account_name=os.environ["SNOWFLAKE_ACCOUNT"],
            warehouse=os.environ["SNOWFLAKE_WAREHOUSE"]
        )



    def __get_snowflake_connection__(self) -> snowflake.connector.SnowflakeConnection:
        """
        Establishes a connection to the Snowflake account.
        Returns:
            snowflake.connector.SnowflakeConnection: A connection object to the Snowflake account.
        Raises:
            EnvironmentError: If required environment variables are not set.
        """

        return snowflake.connector.connect(
            user=self.connection.user_name,
            password=self.connection.password,
            account=self.connection.account_name,
            warehouse=self.connection.warehouse,
            disable_ocsp_checks=True
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

        users = self.__get_users__()

        # get roles

        roles = self.__get_roles__()

        # get direct and indirect members for each role

        member_users, member_roles = self.__get_role_memberships__()
        roles.members_user = member_users
        roles.members_role = member_roles

        # get user/role to role memberships

        user_role_assignments = self.__get_user_role_assignments__()
        for u in users:
            u.role_assignments = user_role_assignments[u]
        for r in roles:
            r.role_assignments = user_role_assignments[r]

        # get grants to roles and users

        grants = self.__get_grants__()

        map = SnowflakeDatabaseMap(
            users=users,
            roles=roles,
            grants=grants
        )
        return map

    def __get_users__(self) -> List[SnowflakeUser]:

        columns = ["USER_ID", "NAME", "LOGIN_NAME", "EMAIL"]

        query = f"""SELECT {', '.join(columns)}
                    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS where DELETED_ON is null and DISABLED = false
                    """

        users = self.__run_query__(query, columns=columns)
        print(users)
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