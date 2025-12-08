import logging
import re
import os
from pydantic.json import pydantic_encoder

import snowflake.connector

from typing import List, Tuple

from policyweaver.models.config import (
    SourceSchema, Source
)

from policyweaver.core.enum import ColumnMaskType, RowFilterType

from policyweaver.plugins.snowflake.model import (
    RowFilterDetailGroup,
    RowFilterDetails,
    SnowflakeColumnMask,
    SnowflakeColumnMaskExtraction,
    SnowflakeConnection,
    SnowflakeGrant,
    SnowflakeMaskingPolicy,
    SnowflakeRole,
    SnowflakeRoleMemberMap,
    SnowflakeRowFilter,
    SnowflakeUser,
    SnowflakeDatabaseMap,
    SnowflakeUserOrRole,
    SnowflakeTableWithPolicy
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
        self.masking_policies = []
        self.tables_with_masks = []



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

    def __get_database_map__(self, source: Source) -> SnowflakeDatabaseMap:
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

        self.grants = self.__get_grants__(source)

        # get column masks

        self.__get_column_masks__(source.name)

        # get row access policies
        self.__get_row_access_policies__(source.name)

        self.__get_unsupported_policies__(source.name)

        return SnowflakeDatabaseMap(users=self.users, roles=self.roles,
                                    grants=self.grants,
                                    masking_policies=self.masking_policies,
                                    tables_with_masks=self.tables_with_masks,
                                    row_access_policies=self.row_access_policies,
                                    tables_with_raps=self.tables_with_raps,
                                    unsupported_tables=self.unsupported_tables
                                    )


    def __get_unsupported_policies__(self, database: str) -> None:

        # AGGREGATION POLICIES
        query = f"""                            
                SELECT
                    rap.POLICY_BODY,
                    pr.POLICY_ID,
                    pr.POLICY_NAME,
                    pr.ref_database_name,
                    pr.ref_schema_name,
                    pr.ref_entity_name,
                    pr.ref_column_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
                JOIN SNOWFLAKE.ACCOUNT_USAGE.AGGREGATION_POLICIES rap
                    ON pr.POLICY_ID = rap.POLICY_ID
                AND pr.REF_DATABASE_NAME = '{database.upper()}' AND REF_ENTITY_DOMAIN = 'TABLE' AND POLICY_STATUS = 'ACTIVE';

                ;"""

        agg_policies = self.__run_query__(query, columns=["POLICY_BODY", "POLICY_ID",
                                                        "POLICY_NAME", "ref_database_name",
                                                        "ref_schema_name",
                                                        "ref_entity_name",
                                                        "ref_column_name"])
        
        # JOIN POLICIES

        query = f"""
                SELECT
                    rap.POLICY_BODY,
                    pr.POLICY_ID,
                    pr.POLICY_NAME,
                    pr.ref_database_name,
                    pr.ref_schema_name,
                    pr.ref_entity_name,
                    pr.ref_column_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
                JOIN SNOWFLAKE.ACCOUNT_USAGE.JOIN_POLICIES rap
                    ON pr.POLICY_ID = rap.POLICY_ID
                AND pr.REF_DATABASE_NAME = '{database.upper()}' AND REF_ENTITY_DOMAIN = 'TABLE' AND POLICY_STATUS = 'ACTIVE';          
                """
        
        join_policies = self.__run_query__(query, columns=["POLICY_BODY", "POLICY_ID",
                                                        "POLICY_NAME", "ref_database_name",
                                                        "ref_schema_name",
                                                        "ref_entity_name",
                                                        "ref_column_name"])

        # PROJECTION POLICIES

        query = f"""                            
                SELECT
                    rap.POLICY_BODY,
                    pr.POLICY_ID,
                    pr.POLICY_NAME,
                    pr.ref_database_name,
                    pr.ref_schema_name,
                    pr.ref_entity_name,
                    pr.ref_column_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
                JOIN SNOWFLAKE.ACCOUNT_USAGE.PROJECTION_POLICIES rap
                    ON pr.POLICY_ID = rap.POLICY_ID
                AND pr.REF_DATABASE_NAME = '{database.upper()}' AND REF_ENTITY_DOMAIN = 'TABLE' AND POLICY_STATUS = 'ACTIVE';

                ;"""

        projection_policies = self.__run_query__(query, columns=["POLICY_BODY", "POLICY_ID",
                                                        "POLICY_NAME", "ref_database_name",
                                                        "ref_schema_name",
                                                        "ref_entity_name",
                                                        "ref_column_name"])


        unsupported_policies = agg_policies + join_policies + projection_policies

        unsupported_tables = [SnowflakeTableWithPolicy(database_name=up["ref_database_name"],
                                                       schema_name=up["ref_schema_name"],
                                                       table_name=up["ref_entity_name"],
                                                       column_names=[]) for up in unsupported_policies]

        self.unsupported_tables = unsupported_tables

                                  

    def __get_grants__(self, source: Source) -> List[SnowflakeGrant]:

        query = f"""select   "PRIVILEGE", "GRANTED_ON", "TABLE_CATALOG", "TABLE_SCHEMA", "NAME", "GRANTEE_NAME"
                    from     SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                    where    DELETED_ON is null and
                            GRANTED_ON in ('TABLE','SCHEMA','DATABASE') and
                            TABLE_CATALOG = '{source.name}'"""
        
        grants_raw = self.__run_query__(query, columns=["PRIVILEGE", "GRANTED_ON", "TABLE_CATALOG", "TABLE_SCHEMA", "NAME", "GRANTEE_NAME"]) 

        database_grants = [grant for grant in grants_raw if grant["GRANTED_ON"] == "DATABASE"]
        schema_grants = [grant for grant in grants_raw if grant["GRANTED_ON"] == "SCHEMA"]
        table_grants = [grant for grant in grants_raw if grant["GRANTED_ON"] == "TABLE"]

        if source.schemas:
            # filter grants based on provided schemas and tables
            schema_names = [s.name for s in source.schemas]
            filtered_schema_grants = [grant for grant in schema_grants if grant["TABLE_SCHEMA"] in schema_names]
            filtered_table_grants = [grant for grant in table_grants if grant["TABLE_SCHEMA"] in schema_names]
            schema_grants = filtered_schema_grants
            table_grants = filtered_table_grants

            filtered_table_grants = []
            for s in source.schemas:
                if s.tables:
                    filtered_table_grants_per_schema = [grant for grant in table_grants if grant["TABLE_SCHEMA"] == s.name and grant["NAME"] in s.tables]
                else:
                    filtered_table_grants_per_schema = [grant for grant in table_grants if grant["TABLE_SCHEMA"] == s.name]
                filtered_table_grants.extend(filtered_table_grants_per_schema)
            
            table_grants = filtered_table_grants

        grants_raw = database_grants + schema_grants + table_grants

        grants = [SnowflakeGrant(privilege=grant["PRIVILEGE"],
                                 granted_on=grant["GRANTED_ON"],
                                 table_catalog=grant["TABLE_CATALOG"],
                                 table_schema=grant["TABLE_SCHEMA"],
                                 name=grant["NAME"],
                                 grantee_name=grant["GRANTEE_NAME"]) for grant in grants_raw]
        
        return grants
    
    def __get_row_access_policies__(self, database: str) -> None:
        """Retrieves the row access policies for a specific database.
        Args:
            database (str): The name of the database for which to retrieve row access policies.
        """
    
        query = f"""                            
                SELECT
                    rap.POLICY_BODY,
                    pr.POLICY_ID,
                    pr.POLICY_NAME,
                    pr.ref_database_name,
                    pr.ref_schema_name,
                    pr.ref_entity_name,
                    pr.ref_column_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
                JOIN SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES rap
                    ON pr.POLICY_ID = rap.POLICY_ID
                AND pr.REF_DATABASE_NAME = '{database.upper()}' AND REF_ENTITY_DOMAIN = 'TABLE' AND POLICY_STATUS = 'ACTIVE';

                ;"""

        row_access_policies = self.__run_query__(query, columns=["POLICY_BODY", "POLICY_ID",
                                                        "POLICY_NAME", "ref_database_name",
                                                        "ref_schema_name",
                                                        "ref_entity_name",
                                                        "ref_column_name"])
        
        self.row_access_policies = list()
        self.tables_with_raps = list()
        for rap in row_access_policies:
            extraction = self.__extract_logic_from_row_filter__(rap["POLICY_BODY"])
            mp = SnowflakeRowFilter(id=rap["POLICY_ID"],
                                    name=rap["POLICY_NAME"],
                                    database_name=rap["ref_database_name"],
                                    schema_name=rap["ref_schema_name"],
                                    table_name=rap["ref_entity_name"],
                                    routine_definition=rap["POLICY_BODY"],
                                    details=extraction
                                    )
            self.row_access_policies.append(mp)

            query = f"""SELECT COLUMN_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.COLUMNS WHERE TABLE_CATALOG = '{mp.database_name}' AND TABLE_SCHEMA = '{mp.schema_name}' AND TABLE_NAME = '{mp.table_name}';"""
            columns = self.__run_query__(query, columns=["COLUMN_NAME"])
            column_names = [c["COLUMN_NAME"] for c in columns]
            self.tables_with_raps.append(SnowflakeTableWithPolicy(
                database_name=mp.database_name,
                schema_name=mp.schema_name,
                table_name=mp.table_name,
                column_names=column_names
            ))
        
    def __extract_case_when_logic_row_filter__(self,sql_definition: str) -> RowFilterDetails:
            """
            Parse a CASE WHEN row filter definition to extract group memberships and their values.
            
            Args:
                sql_definition: The SQL CASE statement from a row filter
                
            Returns:
                Dictionary containing:
                - groups: List of dicts with 'group_name' and 'return_value'
                - default_value: The ELSE clause value
                - filter_type: The type of filter logic
            """
            result = RowFilterDetails(groups=[], default_value=None, row_filter_type=RowFilterType.EXPLICIT_GROUP_MEMBERSHIP)

            # Remove CASE and END
            content = sql_definition.replace('CASE', '').replace('END', '').strip()
            
            # Find all WHEN...THEN patterns
            when_pattern = r"WHENcurrent_role\(\)in\('([^']+)'\)THEN([^W]+?)(?=WHEN|ELSE|$)"
            when_matches = re.findall(when_pattern, content)
            
            # Find ELSE clause
            else_pattern = r"ELSE(.+?)$"
            else_match = re.search(else_pattern, content)
                        
            # Extract group and expression pairs
            for group, expression in when_matches:
                result.groups.append(RowFilterDetailGroup(group_name=group, return_value=expression.strip()))
            
            # Add ELSE clause if exists
            if else_match:
                result.default_value = else_match.group(1).strip()

            return result
            

    def __extract_if_logic_row_filter__(self, definition: str) -> RowFilterDetails:
        """
        Parse an IF row filter definition to extract group membership and their values.
        
        Args:
            sql_definition: The SQL IF statement from a row filter
        Returns:
            Dictionary containing:

        """
        
        group_name = definition[17:].split("'")[1]
        start_in = f"current_role()in('{group_name}'"
        equal = definition == f"current_role()=('{group_name}')"
        if not (definition.startswith(start_in) or equal):
            self.logger.warning("Unexpected format: does not match expected start")
            return result
        
        if equal:
            result = RowFilterDetails(
            groups=[RowFilterDetailGroup(
                group_name=group_name,
                return_value="true"
            )],
            default_value="false",
            row_filter_type=RowFilterType.EXPLICIT_GROUP_MEMBERSHIP)
            return result

        result = RowFilterDetails(
            groups=[],
            default_value="false",
            row_filter_type=RowFilterType.EXPLICIT_GROUP_MEMBERSHIP
        )
        group_names = definition[17:].split("'")
        for i, group_name in enumerate(group_names):
            if i % 2 == 0:
                continue
            else:
                rfdg = RowFilterDetailGroup(
                    group_name=group_name,
                    return_value="true"
                )
                result.groups.append(rfdg)

        return result


    def __extract_logic_from_row_filter__(self, sql_definition: str) -> RowFilterDetails:
        """
        Extracts the group name and mask pattern from a column mask function definition.
        
        Args:
            sql_definition (str): The SQL definition containing is_account_group_member function

        Returns:
            ColumnMaskExtraction: An object containing the extracted group name and mask pattern
        """

        result = RowFilterDetails(row_filter_type=RowFilterType.UNSUPPORTED)
        definition = sql_definition.replace("\n", " ").replace("\r", " ").replace(" ", "") 

        if definition.startswith("current_role()"):
            result_ = self.__extract_if_logic_row_filter__(definition)
        elif definition.startswith("CASEWHENcurrent_role()"):
            result_ = self.__extract_case_when_logic_row_filter__(definition)
        else:
            result_ = None
            
        
        if result_:
            return result_
        self.logger.warning("Unexpected format: does not start 'current_role()' or start with 'CASEWHENcurrent_role('")

        return result
    
    def __get_column_masks__(self, database: str) -> List[SnowflakeColumnMask]:
        """Retrieves the column masking policies for a specific database.
        Args:
            database (str): The name of the database for which to retrieve column masking policies.
        Returns:
            List[SnowflakeMaskingPolicy]: A list of SnowflakeMaskingPolicy objects representing the column masking policies.
        """

        query = f"""                            
                SELECT
                    mp.POLICY_BODY,
                    pr.POLICY_ID,
                    pr.POLICY_NAME,
                    pr.ref_database_name,
                    pr.ref_schema_name,
                    pr.ref_entity_name,
                    pr.ref_column_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
                JOIN SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES mp
                    ON pr.POLICY_ID = mp.POLICY_ID
                WHERE pr.POLICY_KIND = 'MASKING_POLICY'
                AND pr.REF_DATABASE_NAME = '{database.upper()}' AND REF_ENTITY_DOMAIN = 'TABLE' AND POLICY_STATUS = 'ACTIVE';

                ;"""

        masking_policies = self.__run_query__(query, columns=["POLICY_BODY", "POLICY_ID",
                                                                   "POLICY_NAME", "ref_database_name",
                                                                   "ref_schema_name",
                                                                   "ref_entity_name",
                                                                   "ref_column_name"])
        
        
        self.masking_policies = list()
        self.tables_with_masks = list()
        for mp in masking_policies:
            extraction = self.__process_masking_policy__(mp["POLICY_BODY"])
            mp = SnowflakeMaskingPolicy(id=mp["POLICY_ID"],
                                        name=mp["POLICY_NAME"],
                                        database_name=mp["ref_database_name"],
                                        schema_name=mp["ref_schema_name"],
                                        table_name=mp["ref_entity_name"],
                                        column_name=mp["ref_column_name"],
                                        group_names=extraction.group_names,
                                        mask_pattern=extraction.mask_pattern,
                                        column_mask_type=extraction.column_mask_type
                                        )
            self.masking_policies.append(mp)
  
            query = f"""SELECT COLUMN_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.COLUMNS WHERE TABLE_CATALOG = '{mp.database_name}' AND TABLE_SCHEMA = '{mp.schema_name}' AND TABLE_NAME = '{mp.table_name}'  AND DELETED is null;"""
            columns = self.__run_query__(query, columns=["COLUMN_NAME"])
            column_names = [c["COLUMN_NAME"] for c in columns]
            self.tables_with_masks.append(SnowflakeTableWithPolicy(
                database_name=mp.database_name,
                schema_name=mp.schema_name,
                table_name=mp.table_name,
                column_names=column_names
            ))
             

    def __process_masking_policy__(self, policy_body: str) -> SnowflakeColumnMaskExtraction:
        """
        Processes a masking policy dictionary to extract the mask type, group name, and mask pattern.
        Args:
            mp (dict): A dictionary representing a masking policy.
        Returns:
            SnowflakeColumnMask: A SnowflakeColumnMask object with the extracted information.
        """

        result = SnowflakeColumnMaskExtraction(column_mask_type=ColumnMaskType.UNSUPPORTED)

        definition = policy_body.replace("\n", " ").replace("\r", " ").replace(" ", "")

        if not(definition[:8] == "CASEWHEN" and definition[8:24] == "CURRENT_ROLE()IN"):
            self.logger.warning("Unexpected format: does not start with 'CASE WHEN CURRENT_ROLE() IN'")
            return result
        group_names = definition[25:].split(")")[0].replace("'", "").replace('"', '')

        index_ = 25 + len(group_names) + 3
        if definition[index_:index_+4] != "THEN":
            self.logger.warning("Unexpected format: 'THEN' not found where expected.")
            return result
        split_ = definition[index_ + 4 : ].split("ELSE")

        mask = None
        column_name_pos = None
        assigned_value = split_[0]
        if assigned_value[0] in ["'", '"']:
            assigned_value = assigned_value[1:-1]
            mask = assigned_value
        else:
            column_name_pos = 1

        unassigned_value = split_[1].replace("END", "")
        if unassigned_value[0] in ["'", '"']:
            unassigned_value = unassigned_value[1:-1]
            mask = unassigned_value
        else:
            column_name_pos = 2

        result.group_names = group_names.split(",")
        result.mask_pattern = mask
        if column_name_pos == 1:
            result.column_mask_type = ColumnMaskType.UNMASK_FOR_GROUP
        elif column_name_pos == 2:
            result.column_mask_type = ColumnMaskType.MASK_FOR_GROUP
        else:
            result.column_mask_type = ColumnMaskType.UNSUPPORTED

        
        return result



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
