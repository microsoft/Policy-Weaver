import json
import logging
import os
from pydantic.json import pydantic_encoder

from typing import List, Tuple

from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.snowflake.model import SnowflakeGrant, SnowflakeMaskingPolicy, SnowflakeRole, SnowflakeSourceMap, SnowflakeUser

from policyweaver.models.export import (
    PermissionScope, PolicyExport, Policy, Permission, PermissionObject, RolePolicy, RolePolicyExport, ColumnConstraint, RowConstraint
)

from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType, ColumnMaskType, RowFilterType
)

from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.snowflake.api import SnowflakeAPIClient

class SnowflakePolicyWeaver(PolicyWeaverCore):
    """
        Snowflake Policy Weaver for Snowflake Databases.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from Snowflake Database to the Policy Weaver framework.
    """
    sf_read_permissions = ["SELECT", "OWNERSHIP"]
    sf_database_read_prereqs = ["USAGE", "OWNERSHIP"]
    sf_schema_read_prereqs = ["USAGE", "OWNERSHIP"]

    def __init__(self, config:SnowflakeSourceMap) -> None:
        """
        Initializes the SnowflakePolicyWeaver with the provided configuration.
        Args:
            config (SnowflakeSourceMap): The configuration object containing the workspace URL, account ID, and API token.
        Raises:
            ValueError: If the configuration is not of type SnowflakeSourceMap.
        """
        super().__init__(PolicyWeaverConnectorType.SNOWFLAKE, config)

        self.__config_validation(config)
        self.__init_environment(config)
        
        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = SnowflakeAPIClient()

    def __init_environment(self, config:SnowflakeSourceMap) -> None:
        os.environ["SNOWFLAKE_ACCOUNT"] = config.snowflake.account_name
        os.environ["SNOWFLAKE_USER"] = config.snowflake.user_name
        os.environ["SNOWFLAKE_PASSWORD"] = config.snowflake.password
        os.environ["SNOWFLAKE_WAREHOUSE"] = config.snowflake.warehouse
        if config.snowflake.private_key_file:
            os.environ["SNOWFLAKE_PRIVATE_KEY_FILE"] = config.snowflake.private_key_file

    def __config_validation(self, config:SnowflakeSourceMap) -> None:
        """
        Validates the configuration for the SnowflakePolicyWeaver.
        This method checks if the configuration is of type SnowflakeSourceMap and if all required fields are present.
        Args:
            config (SnowflakeSourceMap): The configuration object to validate.
        Raises:
            ValueError: If the configuration is not of type SnowflakeSourceMap or if any required fields are missing.
        """
        if not config.snowflake:
            raise ValueError("SnowflakeSourceMap configuration is required for SnowflakePolicyWeaver.")

        if not config.snowflake.account_name:
            raise ValueError("Snowflake account name is required in the configuration.")

        if not config.snowflake.user_name:
            raise ValueError("Snowflake user name is required in the configuration.")

        if not config.snowflake.password:
            raise ValueError("Snowflake password is required in the configuration.")

        if not config.snowflake.warehouse:
            raise ValueError("Snowflake warehouse is required in the configuration.")
    
    def __validate_table_grant__(self, grant_to_validate: SnowflakeGrant, role: SnowflakeRole):

        role_grants = [g for g in self.map.grants if g.grantee_name == role.name
                and g.granted_on == "TABLE"
                and g.name == grant_to_validate.name
                and g.table_schema == grant_to_validate.table_schema
                and g.table_catalog == grant_to_validate.table_catalog]
        if any(g.privilege in self.sf_read_permissions for g in role_grants):
            return False
                
        for role_assignment in role.role_assignments:
            role_grants = [g for g in self.map.grants if g.grantee_name == role_assignment.name 
                           and g.granted_on == "TABLE"
                           and g.name == grant_to_validate.name
                           and g.table_schema == grant_to_validate.table_schema
                           and g.table_catalog == grant_to_validate.table_catalog]
            if any(g.privilege in self.sf_read_permissions for g in role_grants):
                return True
        return False


    def __validate_grant__(self, grant_to_validate: SnowflakeGrant):

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
                     and grant.granted_on == "DATABASE"
                     and grant.name == database]
        has_db_usage = any(grant.privilege in self.sf_database_read_prereqs for grant in db_grants)

        if not has_db_usage:
            # If not check privileges via role assignments
            for role_assignment in role_user.role_assignments:
                db_grants = [grant for grant in self.map.grants if grant.grantee_name == role_assignment.name
                             and grant.granted_on == "DATABASE"
                             and grant.name == database]
                if any(grant.privilege in self.sf_database_read_prereqs for grant in db_grants):
                    has_db_usage = True
                    break

        # Check if the grantee has usage permission on schema
        schema_grants = [grant for grant in self.map.grants if grant.grantee_name == grantee_name
                          and grant.granted_on == "SCHEMA"
                          and grant.name == schema]
        has_schema_usage = any(grant.privilege in self.sf_schema_read_prereqs for grant in schema_grants)
        if not has_schema_usage:
            # If not check privileges via role assignments
            for role_assignment in role_user.role_assignments:
                schema_grants = [grant for grant in self.map.grants if grant.grantee_name == role_assignment.name
                                 and grant.granted_on == "SCHEMA"
                                 and grant.name == schema]
                if any(grant.privilege in self.sf_schema_read_prereqs for grant in schema_grants):
                    has_schema_usage = True
                    break

        return has_db_usage and has_schema_usage

    def __build_special_grants__(self) -> list[SnowflakeGrant]:
        # Build special grants based on column masking policies
        special_grants = []

        for masking_policy in self.map.masking_policies:
            if masking_policy.column_mask_type == ColumnMaskType.UNSUPPORTED:
                continue
            sfg = SnowflakeGrant(table_catalog=masking_policy.database_name,
                                 table_schema=masking_policy.schema_name,
                                 name=masking_policy.table_name)
            for role_name in masking_policy.group_names:
                roles = [r for r in self.map.roles if r.name == role_name]
                if not roles:
                    self.logger.warning(f"Role {role_name} not found in roles list.")
                    continue
                role = roles[0]
                if self.__validate_table_grant__(sfg, role):
                    special_grant = SnowflakeGrant(grantee_name=role_name,
                                                   granted_on="TABLE",
                                                   privilege="SELECT",
                                                   table_catalog=masking_policy.database_name,
                                                   table_schema=masking_policy.schema_name,
                                                   name=masking_policy.table_name)
                    special_grants.append(special_grant)


        for row_filter_policy in self.map.row_access_policies:
            if row_filter_policy.details.row_filter_type == RowFilterType.UNSUPPORTED:
                self.logger.warning(f"Unsupported row filter type for row filter policy {row_filter_policy.name} on {row_filter_policy.database_name}.{row_filter_policy.schema_name}.{row_filter_policy.table_name}")
                self.logger.warning(f"Skipping special grant for this row filter policy.")
                continue

            sfg = SnowflakeGrant(table_catalog=row_filter_policy.database_name,
                                 table_schema=row_filter_policy.schema_name,
                                 name=row_filter_policy.table_name)

            for group_ in row_filter_policy.details.groups:
                roles = [r for r in self.map.roles if r.name == group_.group_name]
                if not roles:
                    self.logger.warning(f"Role {group_.group_name} not found in roles list.")
                    continue
                role = roles[0]
                if self.__validate_table_grant__(sfg, role):
                    special_grant = SnowflakeGrant(grantee_name=group_.group_name,
                                                   granted_on="TABLE",
                                                   privilege="SELECT",
                                                   table_catalog=row_filter_policy.database_name,
                                                   table_schema=row_filter_policy.schema_name,
                                                   name=row_filter_policy.table_name)
                    special_grants.append(special_grant)

        return special_grants

    def __compute_valid_grants__(self) -> list[SnowflakeGrant]:

        valid_grants = []
        grants = self.map.grants
        table_grants = [grant for grant in grants if grant.granted_on == "TABLE" and grant.privilege in self.sf_read_permissions]

        for grant in table_grants:
            if not self.__validate_grant__(grant):
                continue
            valid_grants.append(grant)

        filtered_grants = []
        for vg in valid_grants:
            duplicate = False
            for fg in filtered_grants:
                if (vg.grantee_name == fg.grantee_name and
                    vg.granted_on == fg.granted_on and
                    vg.privilege == fg.privilege and
                    vg.table_catalog == fg.table_catalog and
                    vg.table_schema == fg.table_schema and
                    vg.name == fg.name):
                    duplicate = True
                    break
            if not duplicate:
                filtered_grants.append(vg)

        return filtered_grants

    def __build_permission_object__(self, user: SnowflakeUser) -> PermissionObject:

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


    def __get_column_constraints__(self, role_assignments: List[SnowflakeRole],
                                   grants: List[SnowflakeGrant]):

        columnconstraints = []
        for grant in grants:
            table_catalog = grant.table_catalog
            table_schema = grant.table_schema
            table_name = grant.name
            matching_mask_policies = [mp for mp in self.map.masking_policies
                                        if mp.database_name == table_catalog and
                                            mp.schema_name == table_schema and
                                            mp.table_name == table_name]

            if not matching_mask_policies:
                continue

        
            table_w_mask = [t for t in self.map.tables_with_masks if t.database_name == table_catalog and
                                                        t.schema_name == table_schema and
                                                        t.table_name == table_name][0]
            all_columns = table_w_mask.column_names
            columns_to_deny = []

            for mp in matching_mask_policies:
                if mp.column_mask_type == ColumnMaskType.UNSUPPORTED:
                    self.logger.warning(f"Unsupported column mask type for masking policy {mp.name} on {mp.database_name}.{mp.schema_name}.{mp.table_name}.{mp.column_name}.")
                    self.logger.warning(f"Using fallback: {self.config.constraints.columns.fallback}")
                    if self.config.constraints.columns.fallback != "grant":
                        columns_to_deny.append(mp.column_name)
                elif mp.column_mask_type == ColumnMaskType.UNMASK_FOR_GROUP:
                    if not any([role for role in role_assignments if role.name in mp.group_names]):
                        columns_to_deny.append(mp.column_name)
                elif mp.column_mask_type == ColumnMaskType.MASK_FOR_GROUP:
                    if any([role for role in role_assignments if role.name in mp.group_names]):
                        columns_to_deny.append(mp.column_name)
                        
            filtered_columns = [col for col in all_columns if col not in columns_to_deny]        
            if len(filtered_columns) == len(all_columns):
                continue
            constraint = ColumnConstraint(catalog_name=mp.database_name,
                                            schema_name=mp.schema_name,
                                            table_name=mp.table_name,
                                            column_names=filtered_columns,
                                            column_effect=PermissionState.GRANT,
                                            column_actions=[PermissionType.SELECT])
            columnconstraints.append(constraint)

        return columnconstraints

    def __get_row_constraints__(self, role_assignments: List[SnowflakeRole], grants: List[SnowflakeGrant]):
        rowconstraints = []
        for grant in grants:
            table_catalog = grant.table_catalog
            table_schema = grant.table_schema
            table_name = grant.name
            matching_raps = [rap for rap in self.map.row_access_policies
                                    if rap.database_name == table_catalog and
                                        rap.schema_name == table_schema and
                                        rap.table_name == table_name]
            
            matching_unsupported_tables = [rap for rap in self.map.unsupported_tables
                                            if rap.database_name == table_catalog and
                                                rap.schema_name == table_schema and
                                                rap.table_name == table_name]
            
            if not matching_raps:
                continue

            table_objects = [(mp.database_name, mp.schema_name, mp.table_name) for mp in matching_raps]
            table_objects = list(set(table_objects))

            for (catalog, schema, table) in table_objects:

                matching_rls_policies_per_table = [mp for mp in matching_raps if mp.database_name == catalog and
                                                    mp.schema_name == schema and
                                                    mp.table_name == table]
                
                matching_unsupported_tables_per_table = [ut for ut in matching_unsupported_tables if ut.database_name == catalog and
                                                            ut.schema_name == schema and
                                                            ut.table_name == table]
                if matching_unsupported_tables_per_table:
                    self.logger.warning(f"Detecting unsupported policies like aggregation, join or projection policy on: {catalog}.{schema}.{table} . Using fallback: {self.config.constraints.rows.fallback}")
                                            
                    if self.config.constraints.rows.fallback != "grant":
                        constraint = RowConstraint(catalog_name=catalog,
                                                schema_name=schema,
                                                table_name=table,
                                                filter_condition="DENYALL")
                        rowconstraints.append(constraint)
                    continue

                for mp in matching_rls_policies_per_table:
                    if mp.details.row_filter_type == RowFilterType.UNSUPPORTED:
                        self.logger.warning(f"Unsupported row filter type for row filter policy {mp.name} on {mp.database_name}.{mp.schema_name}.{mp.table_name}")
                        self.logger.warning(f"Using fallback: {self.config.constraints.rows.fallback}")
                        if self.config.constraints.rows.fallback != "grant":
                            filter_condition = "DENYALL"  # Deny all
                        else:
                            continue
                    elif mp.details.row_filter_type == RowFilterType.EXPLICIT_GROUP_MEMBERSHIP:
                        filter_condition = None
                        for group in mp.details.groups:
                            if group.group_name in [role.name for role in role_assignments]:
                                filter_condition = group.return_value
                                break
                        if not filter_condition:
                            filter_condition = mp.details.default_value
                        if filter_condition == "false":
                            filter_condition = "DENYALL"
                        if filter_condition == "true":
                            continue


                    constraint = RowConstraint(catalog_name=mp.database_name,
                                            schema_name=mp.schema_name,
                                            table_name=mp.table_name,
                                            filter_condition=filter_condition)
                    rowconstraints.append(constraint)
        return rowconstraints


    def _build_role_based_policy__(self, grantee_name: str, grants: list[SnowflakeGrant],
                                   column_security: bool, row_security: bool) -> RolePolicy:

        permission_scopes = []    
        rowconstraints = []
        columnconstraints = []
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
    

        roles = [role for role in self.map.roles if role.name == grantee_name]
        if not roles:
            return None
        role = roles[0]
        role_assignments = [role] + role.role_assignments

        if column_security:
            columnconstraints = self.__get_column_constraints__(role_assignments, grants)
        if row_security:
            rowconstraints += self.__get_row_constraints__(role_assignments, grants)

        permission_objects = self.__get_all_permission_objects__(grantee_name)

        if not permission_objects:
            print(f"No valid permission objects found for grantee: {grantee_name}")
            return None
        if not permission_scopes:
            print(f"No valid permission scopes found for grantee: {grantee_name}")
            return None

        policy = RolePolicy(name=grantee_name,
                            permissionscopes=permission_scopes,
                            permissionobjects=permission_objects,
                            columnconstraints=columnconstraints if columnconstraints else None,
                            rowconstraints=rowconstraints if rowconstraints else None)
        return policy

    def __build_role_based_policy_export__(self) -> RolePolicyExport:
        policy_export = RolePolicyExport(source=self.config.source, type=self.config.type,
                                         policies=[])
        
        if not(self.config.constraints and self.config.constraints.columns and self.config.constraints.columns.columnlevelsecurity):
            self.logger.warning("Column level security is not enabled in the config.")
            column_security = False
        else:
            self.logger.info("Column level security is enabled in the config.")
            column_security = True

        if not(self.config.constraints and self.config.constraints.rows and self.config.constraints.rows.rowlevelsecurity):
            self.logger.warning("Row level security is not enabled in the config.")
            row_security = False
        else:
            self.logger.info("Row level security is enabled in the config.")
            row_security = True

        # group grants by granteename
        grants_by_grantee = {}
        for grant in self.valid_grants:
            if grant.grantee_name not in grants_by_grantee:
                grants_by_grantee[grant.grantee_name] = []
            grants_by_grantee[grant.grantee_name].append(grant)

        for grantee_name, grants in grants_by_grantee.items():
            policy = self._build_role_based_policy__(grantee_name, grants, column_security, row_security)
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

    def _build_table_based_policy__(self, table_catalog: str, table_schema: str, table_name: str, grants: List[SnowflakeGrant]) -> Policy:
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
        
        # Build special grants based on column masking policies
        self.map.grants.extend(self.__build_special_grants__())

        # Filter out valid grants
        self.valid_grants = self.__compute_valid_grants__()

        if policy_mapping == 'role_based':
            return self.__build_role_based_policy_export__()
        elif policy_mapping == 'table_based':
            return self.__build_table_based_policy_export__()