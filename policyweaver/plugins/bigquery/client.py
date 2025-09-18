import json
import logging
import os
from pydantic.json import pydantic_encoder

from typing import List, Tuple

from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.bigquery.api import BigQueryAPIClient
from policyweaver.plugins.bigquery.model import BigQueryGrant, BigQueryRoleMemberMap, BigQuerySourceMap, BigQueryUser

from policyweaver.models.export import (
    PermissionScope, PolicyExport, Policy, Permission, PermissionObject, RolePolicy, RolePolicyExport
)

from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType
)

from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.bigquery.api import SnowflakeAPIClient

class BigQueryPolicyWeaver(PolicyWeaverCore):
    """
        BigQuery Policy Weaver for BigQuery Databases.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from BigQuery Database to the Policy Weaver framework.
    """
    bq_read_permissions = #TBD ["SELECT", "OWNERSHIP"]
    bq_database_read_prereqs = #TBD ["USAGE", "OWNERSHIP"]
    bq_schema_read_prereqs = #TBD ["USAGE", "OWNERSHIP"]

    def __init__(self, config:BigQuerySourceMap) -> None:
        """
        Initializes the BigQueryPolicyWeaver with the provided configuration.
        Args:
            config (BigQuerySourceMap): The configuration object containing the workspace URL, account ID, and API token.
        Raises:
            ValueError: If the configuration is not of type BigQuerySourceMap.
        """
        super().__init__(PolicyWeaverConnectorType.BIGQUERY, config)

        self.__config_validation(config)
        self.__init_environment(config)
        
        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = BigQueryAPIClient()

    def __init_environment(self, config:BigQuerySourceMap) -> None:
        ## TBD
        # os.environ["BIGQUERY_PROJECT"] = config.bigquery.project_id
        # os.environ["BIGQUERY_DATASET"] = config.bigquery.dataset_id
        # os.environ["BIGQUERY_LOCATION"] = config.bigquery.location
        # os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = config.bigquery.credentials_path
        #     os.environ["SNOWFLAKE_PRIVATE_KEY_FILE"] = config.snowflake.private_key_file

    def __config_validation(self, config:BigQuerySourceMap) -> None:
        """
        Validates the configuration for the BigQueryPolicyWeaver.
        This method checks if the configuration is of type BigQuerySourceMap and if all required fields are present.
        Args:
            config (BigQuerySourceMap): The configuration object to validate.
        Raises:
            ValueError: If the configuration is not of type BigQuerySourceMap or if any required fields are missing.
        """

        ### TBD

        # if not config.snowflake:
        #     raise ValueError("SnowflakeSourceMap configuration is required for SnowflakePolicyWeaver.")

        # if not config.snowflake.account_name:
        #     raise ValueError("Snowflake account name is required in the configuration.")

        # if not config.snowflake.user_name:
        #     raise ValueError("Snowflake user name is required in the configuration.")

        # if not config.snowflake.password:
        #     raise ValueError("Snowflake password is required in the configuration.")

        # if not config.snowflake.warehouse:
        #     raise ValueError("Snowflake warehouse is required in the configuration.")
    

    def __validate_grant__(self, grant_to_validate: BigQueryGrant) -> bool:

        grantee_name = grant_to_validate.grantee_name
        database = grant_to_validate.table_catalog
        schema = grant_to_validate.table_schema

        role_user = [role for role in self.map.roles if role.name == grantee_name]
        if not role_user:
            role_user = [user for user in self.map.users if user.name == grantee_name]
        if not role_user:
            return False
        role_user = role_user[0]

        # Check if the grantee has usage permission on database
        db_grants = [grant for grant in self.map.grants if grant.grantee_name == grantee_name 
                    # 
                    # # TBD
                    # 
                    #  and grant.granted_on == "DATABASE"
                     and grant.name == database]
        has_db_usage = any(grant.privilege in self.bq_database_read_prereqs for grant in db_grants)

        if not has_db_usage:
            # If not check privileges via role assignments
            for role_assignment in role_user.role_assignments:
                db_grants = [grant for grant in self.map.grants if grant.grantee_name == role_assignment.name
                             #
                             # # TBD
                             # 
                             # 
                             # and grant.granted_on == "DATABASE"
                             and grant.name == database]
                if any(grant.privilege in self.sf_database_read_prereqs for grant in db_grants):
                    has_db_usage = True
                    break

        # Check if the grantee has usage permission on schema
        schema_grants = [grant for grant in self.map.grants if grant.grantee_name == grantee_name
                          #
                          # # TBD
                          # 
                          # 
                          # 
                          # and grant.granted_on == "SCHEMA"
                          and grant.name == schema]
        has_schema_usage = any(grant.privilege in self.sf_schema_read_prereqs for grant in schema_grants)
        if not has_schema_usage:
            # If not check privileges via role assignments
            for role_assignment in role_user.role_assignments:
                schema_grants = [grant for grant in self.map.grants if grant.grantee_name == role_assignment.name
                                 #
                                 # # TBD
                                 # 
                                 # 
                                 # 
                                 # and grant.granted_on == "SCHEMA"
                                 and grant.name == schema]
                if any(grant.privilege in self.sf_schema_read_prereqs for grant in schema_grants):
                    has_schema_usage = True
                    break

        return has_db_usage and has_schema_usage

    def __compute_valid_grants__(self) -> list[BigQueryGrant]:

        valid_grants = []
        grants = self.map.grants
        table_grants = ### TBD [grant for grant in grants if grant.granted_on == "TABLE" and grant.privilege in self.sf_read_permissions]

        for grant in table_grants:
            if self.__validate_grant__(grant):
                valid_grants.append(grant)

        return valid_grants

    def __build_permission_object__(self, user: BigQueryUser) -> PermissionObject:

        if Utils.is_email(user.login_name):
            po = PermissionObject(name=user.id, email=user.login_name, type=IamType.USER)
            return po
        else:
            print(f"Invalid email format for user: {user.id} , {user.login_name}")

    def __get_all_permission_objects__(self, grantee_name: str) -> list[PermissionObject]:

        role_user = [user for user in self.map.users if user.name == grantee_name]
        is_user = True
        if not role_user:
            role_user = [role for role in self.map.roles if role.name == grantee_name]
            is_user = False
        if not role_user:
            raise ValueError(f"Role user not found for grantee: {grantee_name}")
        role_user = role_user[0]

        permission_objects = []
        if is_user:
            permission_object = self.__build_permission_object__(role_user)
            if permission_object:
                permission_objects.append(permission_object)
        else:
            users_added = list()
            for user in role_user.members_user:
                if user.name in users_added:
                    continue
                permission_object = self.__build_permission_object__(user)
                if permission_object:
                    permission_objects.append(permission_object)
                users_added.append(user.name)

        return permission_objects

    def _build_role_based_policy__(self, grantee_name: str, grants: list[BigQueryGrant]) -> RolePolicy:

        permission_scopes = []    
        for grant in grants:
            table_catalog = grant.table_catalog
            table_schema = grant.table_schema
            table_name = grant.name
            permission_scope = PermissionScope(catalog=table_catalog,
                                               catalog_schema=table_schema,
                                               table=table_name,
                                               name=PermissionType.SELECT,
                                               state=PermissionState.GRANT)
            permission_scopes.append(permission_scope)

        permission_objects = self.__get_all_permission_objects__(grantee_name)

        if not permission_objects:
            print(f"No valid permission objects found for grantee: {grantee_name}")
            return None
        if not permission_scopes:
            print(f"No valid permission scopes found for grantee: {grantee_name}")
            return None

        policy = RolePolicy(name=grantee_name,
                            permissionscopes=permission_scopes,
                            permissionobjects=permission_objects)
        return policy

    def __build_role_based_policy_export__(self) -> RolePolicyExport:
        policy_export = RolePolicyExport(source=self.config.source, type=self.config.type,
                                         policies=[])

        # group grants by granteename
        grants_by_grantee = {}
        for grant in self.valid_grants:
            if grant.grantee_name not in grants_by_grantee:
                grants_by_grantee[grant.grantee_name] = []
            grants_by_grantee[grant.grantee_name].append(grant)

        for grantee_name, grants in grants_by_grantee.items():
            policy = self._build_role_based_policy__(grantee_name, grants)
            if policy:
                policy_export.policies.append(policy)

        return policy_export


    @staticmethod
    def __deduplicate_permission_objects__(permission_objects: List[PermissionObject]) -> List[PermissionObject]:
        new_list = []
        for obj in permission_objects:
            if obj.lookup_id not in [o.lookup_id for o in new_list]:
                new_list.append(obj)
        return new_list

    def _build_table_based_policy__(self, table_catalog: str, table_schema: str, table_name: str, grants: List[BigQueryGrant]) -> Policy:
        policy = Policy(catalog=table_catalog,
                        catalog_schema=table_schema,
                        table=table_name, permissions=[])
        permission_objects = []
        for grant in grants:
            permission_objects.extend(self.__get_all_permission_objects__(grant.grantee_name))

        permission_objects = self.__deduplicate_permission_objects__(permission_objects)

        permission = Permission(name=PermissionType.SELECT, state=PermissionState.GRANT, objects=permission_objects)
        policy.permissions.append(permission)
        return policy

    def __build_table_based_policy_export__(self) -> PolicyExport:
        policy_export = PolicyExport(source=self.config.source, type=self.config.type,
                                     policies=[])

        # group grants by table
        grants_by_table = {}
        for grant in self.valid_grants:
            table_key = (grant.table_catalog, grant.table_schema, grant.name)
            if table_key not in grants_by_table:
                grants_by_table[table_key] = []
            grants_by_table[table_key].append(grant)

        for (table_catalog, table_schema, table_name), grants in grants_by_table.items():
            policy = self._build_table_based_policy__(table_catalog, table_schema, table_name, grants)
            if policy:
                policy_export.policies.append(policy)

        return policy_export

    def map_policy(self, policy_mapping = 'role_based'):
        self.map = self.api_client.__get_database_map__(self.config.source)
        
        # Filter out valid grants
        self.valid_grants = self.__compute_valid_grants__()

        if policy_mapping == 'role_based':
            return self.__build_role_based_policy_export__()
        elif policy_mapping == 'table_based':
            return self.__build_table_based_policy_export__()