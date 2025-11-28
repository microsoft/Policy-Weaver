import json
import os
import re
from pydantic.json import pydantic_encoder

from typing import List, Tuple
from policyweaver.models.export import (
    CatalogItem, PolicyExport, Policy, Permission, PermissionObject, RolePolicy, RolePolicyExport,
    PermissionScope, ColumnConstraint, RowConstraint
)
from policyweaver.plugins.databricks.model import (
    Privilege, PrivilegeItem, PrivilegeSnapshot, DependencyMap, DatabricksSourceMap, TableObject
)
from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType, ColumnMaskType, RowFilterType
)

from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.databricks.api import DatabricksAPIClient

class DatabricksPolicyWeaver(PolicyWeaverCore):
    """
        Databricks Policy Weaver for Unity Catalog.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from Databricks Unity Catalog to the Policy Weaver framework.
    """
    dbx_account_users_group = "account users"
    dbx_all_permissions = ["ALL_PRIVILEGES"]
    dbx_read_permissions = ["SELECT"] + dbx_all_permissions
    dbx_catalog_read_prereqs = ["USE_CATALOG"] + dbx_all_permissions
    dbx_schema_read_prereqs = ["USE_SCHEMA"] + dbx_all_permissions

    def __init__(self, config:DatabricksSourceMap) -> None:
        """
        Initializes the DatabricksPolicyWeaver with the provided configuration.
        Args:
            config (DatabricksSourceMap): The configuration object containing the workspace URL, account ID, and API token.
        Raises:
            ValueError: If the configuration is not of type DatabricksSourceMap.
        """
        super().__init__(PolicyWeaverConnectorType.UNITY_CATALOG, config)

        self.__config_validation(config)
        self.__init_environment(config)
        
        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = DatabricksAPIClient()

    def __init_environment(self, config:DatabricksSourceMap) -> None:
        os.environ["DBX_HOST"] = config.databricks.workspace_url
        os.environ["DBX_ACCOUNT_ID"] = config.databricks.account_id
        os.environ["DBX_ACCOUNT_API_TOKEN"] = config.databricks.account_api_token

    def __config_validation(self, config:DatabricksSourceMap) -> None:
        """
        Validates the configuration for the DatabricksPolicyWeaver.
        This method checks if the configuration is of type DatabricksSourceMap and if all required fields are present.
        Args:
            config (DatabricksSourceMap): The configuration object to validate.
        Raises:
            ValueError: If the configuration is not of type DatabricksSourceMap or if any required fields are missing.
        """
        if not config.databricks:
            raise ValueError("DatabricksSourceMap configuration is required for DatabricksPolicyWeaver.")
        
        if not config.databricks.workspace_url:
            raise ValueError("Databricks workspace URL is required in the configuration.")
        
        if not config.databricks.account_id:
            raise ValueError("Databricks account ID is required in the configuration.")
        
        if not config.databricks.account_api_token:
            raise ValueError("Databricks account API token is required in the configuration.")

    def map_policy(self, policy_mapping: str = "table_based") -> PolicyExport:
        """
        Maps the policies from the Databricks Unity Catalog to the Policy Weaver framework.
        This method collects privileges from the workspace catalog, schemas, and tables,
        applies the access model, and builds the export policies.
        Returns:
            PolicyExport: An object containing the source, type, and policies mapped from the Databricks Unity Catalog.
        Raises:
            ValueError: If the source is not of type DatabricksSourceMap.
        """
        self.account, self.workspace = self.api_client.get_workspace_policy_map(self.config.source)
        self.__collect_privileges__(self.workspace.catalog.privileges, self.workspace.catalog.name)        

        for schema in self.workspace.catalog.schemas:
            self.__collect_privileges__(schema.privileges, self.workspace.catalog.name, schema.name)            

            for tbl in schema.tables:
                self.__collect_privileges__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name)                

        self.__apply_access_model__()

        if policy_mapping == "role_based":
            policies = self.__build_export_role_policies__()
            return RolePolicyExport(
                source=self.config.source,
                type=self.connector_type,
                policies=policies
        )
        else:

            policies = self.__build_export_policies__()
            return PolicyExport(source=self.config.source, type=self.connector_type, policies=policies)
        
    def __get_three_part_key__(self, catalog:str, schema:str=None, table:str=None) -> str:
        """
        Constructs a three-part key for the catalog, schema, and table.
        Args:
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            str: A string representing the three-part key in the format "catalog.schema.table".
        """
        schema = f".{schema}" if schema else ""
        table = f".{table}" if table else ""

        return f"{catalog}{schema}{table}"
    
    def __resolve_principal_type__(self, principal:str) -> IamType:
        """
        Resolves the type of the principal based on its format.
        Args:
            principal (str): The principal identifier (email, UUID, or group name).
        Returns:
            IamType: The type of the principal (USER, SERVICE_PRINCIPAL, or GROUP).
        """
        if Utils.is_email(principal):
            return IamType.USER
        elif Utils.is_uuid(principal):
            return IamType.SERVICE_PRINCIPAL
        else:
            return IamType.GROUP
        
    def __collect_privileges__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> None:
        """
        Collects privileges from the provided list and maps them to the snapshot.
        This method creates a DependencyMap for each privilege and adds it to the snapshot.
        Args:
            privileges (List[Privilege]): A list of Privilege objects to collect.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        """
        for privilege in privileges:
            dependency_map = DependencyMap(
                catalog=catalog,
                schema=schema,
                table=table
                )

            if privilege.privileges:
                for p in privilege.privileges:
                    dependency_map.privileges.append(p)
                    
                    if privilege.principal not in self.snapshot:
                        self.snapshot[privilege.principal] = PrivilegeSnapshot(
                                principal=privilege.principal,
                                type=self.__resolve_principal_type__(privilege.principal),
                                maps={dependency_map.key: dependency_map}
                            )
                    else:
                        if dependency_map.key not in self.snapshot[privilege.principal].maps:
                            self.snapshot[privilege.principal].maps[dependency_map.key] = dependency_map
                        else:
                            if p not in self.snapshot[privilege.principal].maps[dependency_map.key].privileges:
                                self.snapshot[privilege.principal].maps[dependency_map.key].privileges.append(p)
    
    def __search_privileges__(self, snapshot:PrivilegeSnapshot, key:str, prereqs:List[str]) -> bool:
        """
        Searches for privileges in the snapshot that match the given key and prerequisites.
        Args:
            snapshot (PrivilegeSnapshot): The snapshot containing the privileges.
            key (str): The key to search for in the snapshot.
            prereqs (List[str]): A list of prerequisite privileges to check against.
        Returns:
            bool: True if any privileges match the key and prerequisites, False otherwise.
        """
        if key in snapshot.maps:
            if [p for p in snapshot.maps[key].privileges if p in prereqs]:
                return True
        
        return False
    
    def __apply_access_model__(self) -> None:
        """
        Applies the access model to the snapshot by ensuring that all users, service principals, and groups
        are represented in the snapshot. It also applies privilege inheritance and group membership.
        This method ensures that all principals have a PrivilegeSnapshot and that their privileges are inherited correctly.
        It also collects group memberships for each principal.
        Returns:
            None
        """
        for workspace_user in self.workspace.users:
            if workspace_user.email not in self.snapshot:
                self.snapshot[workspace_user.email] = PrivilegeSnapshot(
                    principal=workspace_user.email,
                    type=IamType.USER,
                    maps={}
                )
        
        for workspace_service_principal in self.workspace.service_principals:
            if workspace_service_principal.application_id not in self.snapshot:
                self.snapshot[workspace_service_principal.application_id] = PrivilegeSnapshot(
                    principal=workspace_service_principal.application_id,
                    type=IamType.SERVICE_PRINCIPAL,
                    maps={}
                )
                
        for workspace_group in self.workspace.groups:
            if workspace_group.name not in self.snapshot:
                self.snapshot[workspace_group.name] = PrivilegeSnapshot(
                    principal=workspace_group.name,
                    type=IamType.GROUP,
                    maps={}
                )

        for principal in self.snapshot:
            self.snapshot[principal] = self.__apply_privilege_inheritence__(self.snapshot[principal])

            object_id = self.workspace.lookup_object_id(principal, self.snapshot[principal].type)
            
            if object_id:
                self.snapshot[principal].group_membership = self.workspace.get_user_groups(object_id)
            
            self.snapshot[principal].group_membership.append(self.dbx_account_users_group)
            #self.logger.debug(f"DBX Snapshot - Principal ({principal}) - {self.snapshot[principal].model_dump_json(indent=4)}") 

    def __apply_privilege_inheritence__(self, privilege_snapshot:PrivilegeSnapshot) -> PrivilegeSnapshot:
        """
        Applies privilege inheritance to the given PrivilegeSnapshot.
        This method ensures that catalog and schema prerequisites are set for each map in the snapshot.
        Args:
            privilege_snapshot (PrivilegeSnapshot): The PrivilegeSnapshot to apply inheritance to.
        Returns:
            PrivilegeSnapshot: The updated PrivilegeSnapshot with applied privilege inheritance.
        """
        for map_key in privilege_snapshot.maps:
            map = privilege_snapshot.maps[map_key]
            catalog_key = None if not map.catalog else self.__get_three_part_key__(map.catalog)
            schema_key = None if not map.catalog_schema else self.__get_three_part_key__(map.catalog, map.catalog_schema)

            if catalog_key in privilege_snapshot.maps:
                privilege_snapshot.maps[map_key].catalog_all_cascade = \
                    self.__search_privileges__(privilege_snapshot, catalog_key, self.dbx_all_permissions)
                privilege_snapshot.maps[map_key].catalog_prerequisites = \
                    privilege_snapshot.maps[map_key].catalog_all_cascade if privilege_snapshot.maps[map_key].catalog_all_cascade else \
                        self.__search_privileges__(privilege_snapshot, catalog_key, self.dbx_catalog_read_prereqs)
                
            sk = schema_key if schema_key and schema_key in privilege_snapshot.maps else map_key

            privilege_snapshot.maps[map_key].schema_all_cascade = \
                self.__search_privileges__(privilege_snapshot, sk, self.dbx_all_permissions)    
            privilege_snapshot.maps[map_key].schema_prerequisites = \
                privilege_snapshot.maps[map_key].schema_all_cascade if privilege_snapshot.maps[map_key].schema_all_cascade else \
                    self.__search_privileges__(privilege_snapshot, sk, self.dbx_schema_read_prereqs)
                
            privilege_snapshot.maps[map_key].read_permissions = \
                self.__search_privileges__(privilege_snapshot, map_key, self.dbx_read_permissions)
   
        return privilege_snapshot
    

    def __build_special_grants__(self) -> List[TableObject]:

        mps = self.workspace.catalog.column_masks
        rls = self.workspace.catalog.row_filters

        special_grants = []

        for masking_policy in mps:
            if masking_policy.mask_type == ColumnMaskType.UNSUPPORTED:
                self.logger.warning(f"Unsupported column mask type for masking policy {masking_policy.name} on {masking_policy.catalog_name}.{masking_policy.schema_name}.{masking_policy.table_name}.{masking_policy.column_name}.")
                self.logger.warning(f"Skipping special grant for this masking policy.")
                continue
            key = self.__get_three_part_key__(catalog=masking_policy.catalog_name,
                                              schema=masking_policy.schema_name,
                                              table=masking_policy.table_name)
            if self.__has_read_permissions__(masking_policy.group_name, key):
                to = TableObject(catalog_name=masking_policy.catalog_name,
                    schema_name=masking_policy.schema_name,
                    table_name=masking_policy.table_name,
                    privileges=[Privilege(principal=masking_policy.group_name, privileges=["SELECT"])]
                )
                special_grants.append(to)

        for row_filter_policy in rls:
            if row_filter_policy.details.row_filter_type == RowFilterType.UNSUPPORTED:
                self.logger.warning(f"Unsupported row filter type for row filter policy {row_filter_policy.name} on {row_filter_policy.catalog_name}.{row_filter_policy.schema_name}.{row_filter_policy.table_name}")
                self.logger.warning(f"Skipping special grant for this row filter policy.")
                continue

            key = self.__get_three_part_key__(catalog=row_filter_policy.catalog_name,
                                              schema=row_filter_policy.schema_name,
                                              table=row_filter_policy.table_name)
            for group in row_filter_policy.details.groups:
                if self.__has_read_permissions__(group.group_name, key):
                    to = TableObject(catalog_name=row_filter_policy.catalog_name,
                        schema_name=row_filter_policy.schema_name,
                        table_name=row_filter_policy.table_name,
                        privileges=[Privilege(principal=group.group_name, privileges=["SELECT"])]
                    )
                    special_grants.append(to)

        return special_grants



    

    def __get_all_read_permissions__(self) -> List[PrivilegeItem]:

        permissions = []

        special_table_privileges = self.__build_special_grants__()

        if self.workspace.catalog.privileges:
            catalog_permissions = self.__get_read_permissions__(self.workspace.catalog.privileges, self.workspace.catalog.name)
            for cp in catalog_permissions:
                permissions.append(PrivilegeItem(catalog=self.workspace.catalog.name, catalog_schema=None, table=None,
                                                 role=cp[0], type="catalog", permission="read", grant=cp[1]))

        for schema in self.workspace.catalog.schemas:
            if schema.privileges:
                schema_permissions = self.__get_read_permissions__(schema.privileges, self.workspace.catalog.name, schema.name)
                for sp in schema_permissions:
                    permissions.append(PrivilegeItem(catalog=self.workspace.catalog.name, catalog_schema=schema.name, table=None,
                                                      role=sp[0], type="schema", permission="read", grant=sp[1]))

            stp_for_schema = [stp for stp in special_table_privileges if stp.catalog_name == self.workspace.catalog.name and stp.schema_name == schema.name]
                    

            for tbl in schema.tables:

                table_permissions = []
                if tbl.privileges:
                    table_permissions = self.__get_read_permissions__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name)
                for tp in table_permissions:
                    permissions.append(PrivilegeItem(catalog=self.workspace.catalog.name, catalog_schema=schema.name, table=tbl.name,
                                                        role=tp[0], type="table", permission="read", grant=tp[1]))
                        
                stp_for_table = [stp for stp in stp_for_schema if stp.table_name == tbl.name]

                for stp in stp_for_table:
                    for sp in stp.privileges:
                        matches = [tp for tp in table_permissions if tp[0] == sp.principal]
                        if matches and matches[0][1] == "direct":
                            continue
                        else:
                            permissions.append(PrivilegeItem(catalog=stp.catalog_name, catalog_schema=stp.schema_name, table=stp.table_name,
                                                            role=sp.principal, type="table", permission="read", grant="direct"))

        return permissions

    def __get_role_based_privileges__(self, permissions: List[PrivilegeItem], principal: str) -> List[CatalogItem]:
        """Returns a list of CatalogItem objects representing the role-based privileges for a specific principal.
        Args:
            permissions (List[PrivilegeItem]): The list of privilege items to filter.
            principal (str): The principal (user or group) for which to retrieve role-based privileges.
        Returns:
            List[CatalogItem]: A list of CatalogItem objects representing the role-based privileges.
        """
        catalog_items = []
        for perm in permissions:
            if perm.role == principal and perm.grant == "direct":
                catalog_items.append(CatalogItem(catalog=perm.catalog, catalog_schema=perm.catalog_schema, table=perm.table))
        return catalog_items

    def __build_export_role_policies__(self) -> List[RolePolicy]:
        """
        Builds the export group policies from the collected privileges in the snapshot.
        This method constructs RolePolicy objects for each group and its associated permissions.
        Returns:
            List[RolePolicy]: A list of RolePolicy objects representing the export group policies.
        """

        policies = []

        permissions = self.__get_all_read_permissions__()
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

        for principal, snapshot in self.snapshot.items():
            policy = self.__build_role_policy(principal, snapshot.type, permissions,
                                              column_security=column_security, row_security=row_security)
            if policy:
                policies.append(policy)

        return policies
    
    def __get_permission_scopes__(self, cat_item:CatalogItem) -> PermissionScope:

        if cat_item.catalog and not cat_item.catalog_schema and not cat_item.table:
            ps = []
            for schema in self.workspace.catalog.schemas:
                inherited_cat_item = CatalogItem(catalog=cat_item.catalog, catalog_schema=schema.name, table=None)
                ps_schema = self.__get_permission_scopes__(inherited_cat_item)
                ps.extend(ps_schema)
            return ps

        if cat_item.catalog and cat_item.catalog_schema and not cat_item.table:
            ps = []
            s = [s for s in self.workspace.catalog.schemas if s.name == cat_item.catalog_schema][0]
            for table in [t  for t in s.tables]:
                inherited_cat_item = CatalogItem(catalog=cat_item.catalog, catalog_schema=cat_item.catalog_schema, table=table.name)
                ps_table = self.__get_permission_scopes__(inherited_cat_item)
                ps.extend(ps_table)
            return ps

        ps = PermissionScope()
        ps.catalog = cat_item.catalog
        ps.catalog_schema = cat_item.catalog_schema
        ps.table = cat_item.table
        ps.name = PermissionType.SELECT
        ps.state = PermissionState.GRANT

        return [ps]

    def __fix_spn_name__(self, sp_name:str) -> Tuple[bool, str]:
        overlap = [group.name for group in self.workspace.groups if group.name == sp_name]
        if overlap:
            sp_name = f"SPN{sp_name}"
            return True, sp_name
        return False, sp_name


    def __get_column_constraints__(self, catalog_items:List[CatalogItem], 
                                   principal:str) -> List[ColumnConstraint]:
        columnconstraints = []

        for cat_item in catalog_items:


            matching_mask_policies = [mp for mp in self.workspace.catalog.column_masks
                                      if mp.catalog_name == cat_item.catalog and
                                         (mp.schema_name == cat_item.catalog_schema or cat_item.catalog_schema is None) and
                                         (mp.table_name == cat_item.table or cat_item.table is None)]
            


            if not matching_mask_policies:
                continue

            table_objects = [(mp.catalog_name, mp.schema_name, mp.table_name) for mp in matching_mask_policies]
            table_objects = list(set(table_objects))

            role_assignments = self.snapshot[principal].group_membership
            role_assignments = [principal] + role_assignments

            for (catalog, schema, table) in table_objects:
                table_w_mask = [t for t in self.workspace.catalog.tables_with_masks if t.catalog_name == catalog and
                                                        t.schema_name == schema and
                                                        t.table_name == table][0]
                matching_mask_policies_per_table = [mp for mp in matching_mask_policies if mp.catalog_name == catalog and
                                                    mp.schema_name == schema and
                                                    mp.table_name == table]                
                all_columns = table_w_mask.columns
                columns_to_deny = []
                for mp in matching_mask_policies_per_table:
                    if mp.mask_type == ColumnMaskType.UNSUPPORTED:
                        self.logger.warning(f"Unsupported column mask type for masking policy {mp.name} on {mp.catalog_name}.{mp.schema_name}.{mp.table_name}.{mp.column_name}.")
                        self.logger.warning(f"Using fallback: {self.config.constraints.columns.fallback}")
                        if self.config.constraints.columns.fallback != "grant":
                            columns_to_deny.append(mp.column_name)
                    elif mp.mask_type == ColumnMaskType.UNMASK_FOR_GROUP:
                        if not any([role for role in role_assignments if role == mp.group_name]):
                            columns_to_deny.append(mp.column_name)
                    elif mp.mask_type == ColumnMaskType.MASK_FOR_GROUP:
                        if any([role for role in role_assignments if role == mp.group_name]):
                            columns_to_deny.append(mp.column_name)
                            
                filtered_columns = [col for col in all_columns if col not in columns_to_deny]
                if len(filtered_columns) == len(all_columns):
                    continue        
                constraint = ColumnConstraint(catalog_name=mp.catalog_name,
                                                schema_name=mp.schema_name,
                                                table_name=mp.table_name,
                                                column_names=filtered_columns,
                                                column_effect=PermissionState.GRANT,
                                                column_actions=[PermissionType.SELECT])
                columnconstraints.append(constraint)
        
        return columnconstraints

    def __get_row_constraints__(self, catalog_items:List[CatalogItem], principal:str):# -> List[RowConstraint]:
        rowconstraints = []
        for cat_item in catalog_items:
            rls = self.workspace.catalog.row_filters
            matching_rls_policies = [rf for rf in rls
                                      if rf.catalog_name == cat_item.catalog and
                                         (rf.schema_name == cat_item.catalog_schema or cat_item.catalog_schema is None) and
                                         (rf.table_name == cat_item.table or cat_item.table is None)]
            if not matching_rls_policies:
                continue

            table_objects = [(mp.catalog_name, mp.schema_name, mp.table_name) for mp in matching_rls_policies]
            table_objects = list(set(table_objects))

            role_assignments = self.snapshot[principal].group_membership
            role_assignments = [principal] + role_assignments

            for (catalog, schema, table) in table_objects:

                matching_rls_policies_per_table = [mp for mp in matching_rls_policies if mp.catalog_name == catalog and
                                                    mp.schema_name == schema and
                                                    mp.table_name == table]

                for mp in matching_rls_policies_per_table:
                    if mp.details.row_filter_type == RowFilterType.UNSUPPORTED:
                        self.logger.warning(f"Unsupported row filter type for row filter policy {mp.name} on {mp.catalog_name}.{mp.schema_name}.{mp.table_name}")
                        self.logger.warning(f"Using fallback: {self.config.constraints.rows.fallback}")
                        if self.config.constraints.rows.fallback != "grant":
                            filter_condition = "DENYALL"  # Deny all
                        else:
                            continue
                    elif mp.details.row_filter_type == RowFilterType.EXPLICIT_GROUP_MEMBERSHIP:
                        filter_condition = None
                        for group in mp.details.groups:
                            if group.group_name in role_assignments:
                                filter_condition = group.return_value
                                break
                        if not filter_condition:
                            filter_condition = mp.details.default_value
                        if filter_condition == "false":
                            filter_condition = "DENYALL"
                        if filter_condition == "true":
                            continue

                               
                    constraint = RowConstraint(catalog_name=mp.catalog_name,
                                            schema_name=mp.schema_name,
                                            table_name=mp.table_name,
                                            filter_condition=filter_condition)
                    rowconstraints.append(constraint)
        return rowconstraints

    def __build_role_policy(self, principal:str, iam_type:IamType, permissions:List[PrivilegeItem],
                            column_security:bool, row_security:bool) -> RolePolicy:
        """
        Builds a RolePolicy object from the provided principal and iam_type and catalog items.
        Args:
            principal (str): The principal (user or group) for the role policy.
            iam_type (IamType): The IAM type (user, group, service principal) for the role policy.
            cat_items (List[CatalogItem]): The catalog items associated with the role policy.
        Returns:
            RolePolicy: A RolePolicy object representing the role and its associated permissions.
        """
        cat_items = self.__get_role_based_privileges__(permissions, principal)
        if not cat_items:
            return None
        permission_scopes = []
        
        rowconstraints = []
        columnconstraints = []
        for cat_item in cat_items:
            ps = self.__get_permission_scopes__(cat_item)
            permission_scopes.extend(ps)
        if column_security:
            columnconstraints = self.__get_column_constraints__(cat_items, principal)
        if row_security:
            rowconstraints = self.__get_row_constraints__(cat_items, principal)
        members = []

        role_name = principal
        if iam_type == IamType.GROUP:
            for group in self.workspace.groups:
                if group.name == principal:
                    if group.external_id:
                        members = [group.id]
                        role_name = group.name
                    else:
                        members = [member.id for member in group.members]
                        role_name = group.name
                    break
        elif iam_type == IamType.USER:
            for u in self.workspace.users:
                if u.email == principal:
                    members = [u.id]
                    role_name = u.email
                    break
        elif iam_type == IamType.SERVICE_PRINCIPAL:
            for s in self.workspace.service_principals:
                if s.application_id == principal:
                    members = [s.id]

                    adjusted, sp_name = self.__fix_spn_name__(s.name)
                    while adjusted:
                        adjusted, sp_name = self.__fix_spn_name__(sp_name)
                    
                    role_name = sp_name
                    break

        permissionobjects = []
        for member_id in members:
            po = PermissionObject()
            member = None
            for u in self.workspace.users:
                if u.id == member_id:
                    member = u.id
                    po.id = u.external_id
                    type = IamType.USER
                    po.email = u.email
                    po.entra_object_id = u.external_id
                    break
            if not member:
                for s in self.workspace.service_principals:
                    if s.id == member_id:
                        member = s.id
                        type = IamType.SERVICE_PRINCIPAL
                        po.id = s.external_id
                        po.app_id = s.application_id
                        po.entra_object_id = s.external_id
                        break
            if not member:
                for g in self.workspace.groups:
                    if g.id == member_id and g.external_id:
                        member = g.id
                        type = IamType.GROUP
                        po.id = g.external_id
                        po.entra_object_id = g.external_id
                        break
            if member:
                po.type = type
                permissionobjects.append(po)

        if not permissionobjects:
            return None

        policy = RolePolicy(
            permissionobjects=permissionobjects,
            permissionscopes=permission_scopes,
            name=role_name,
            columnconstraints=columnconstraints if columnconstraints else None,
            rowconstraints=rowconstraints if rowconstraints else None
        )


        return policy


    def __build_export_policies__(self) -> List[Policy]:
        """
        Builds the export policies from the collected privileges in the snapshot.
        This method constructs Policy objects for each catalog, schema, and table,
        applying the read permissions and prerequisites.
        Returns:
            List[Policy]: A list of Policy objects representing the export policies.
        """
        policies = []

        if self.workspace.catalog.privileges:
            catalog_permissions = self.__get_read_permissions__(self.workspace.catalog.privileges, self.workspace.catalog.name)
            catalog_permissions = [t[0] for t in catalog_permissions]
            policies.append(
                self.__build_policy__(
                    catalog_permissions,
                    self.workspace.catalog.name))
        
        for schema in self.workspace.catalog.schemas:
            if schema.privileges:
                schema_permissions = self.__get_read_permissions__(schema.privileges, self.workspace.catalog.name, schema.name)
                schema_permissions = [t[0] for t in schema_permissions]
                policies.append(
                    self.__build_policy__(
                        schema_permissions,
                        self.workspace.catalog.name, schema.name))

            for tbl in schema.tables:
                if tbl.privileges:
                    table_permissions = self.__get_read_permissions__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name)
                    table_permissions = [t[0] for t in table_permissions]
                    policies.append(
                        self.__build_policy__(
                            table_permissions,
                            self.workspace.catalog.name, schema.name, tbl.name))
        

        return policies

    def __build_policy__(self, table_permissions, catalog, schema=None, table=None) -> Policy:
        """
        Builds a Policy object from the provided table permissions, catalog, schema, and table.
        Args:
            table_permissions (List[str]): A list of user or service principal identifiers with read permissions.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            Policy: A Policy object containing the catalog, schema, table, and permissions."""
        policy = Policy(
            catalog=catalog,
            catalog_schema=schema,
            table=table,
            permissions=[]
        )

        permission = Permission(
                    name=PermissionType.SELECT,
                    state=PermissionState.GRANT,
                    objects=[])
        
        for p in table_permissions:
            po = PermissionObject() 
            if Utils.is_email(p):
                po.type=IamType.USER
            else:
                po.type=IamType.SERVICE_PRINCIPAL
                for g in self.workspace.groups:
                    if g.name == p:
                        po.type=IamType.GROUP
                        break
                
            if po.type == IamType.USER:
                u = self.workspace.lookup_user_by_email(p)
        
                if u:
                    po.id = u.external_id
                    po.email = p
                    po.entra_object_id = u.external_id
                    self.logger.debug(f"DBX User Lookup {p} - ID {u.external_id}")
                else:
                    self.logger.debug(f"DBX User Lookup {p} - not found, using email...")
                    po.email = p
            elif po.type == IamType.SERVICE_PRINCIPAL:
                s = self.workspace.lookup_service_principal_by_id(p)

                if s:
                    po.id = s.external_id
                    po.app_id = p
                    po.entra_object_id = s.external_id
                    self.logger.debug(f"DBX Service Principal ID Lookup {p} - ID {s.external_id}")
                else:
                    self.logger.debug(f"DBX Service Principal ID Lookup {p} - not found...")
                    po.app_id = p
            elif po.type == IamType.GROUP:
                g = self.workspace.lookup_group_by_name(p)

                if g:
                    po.id = g.external_id
                    po.email = None
                    po.app_id = None
                    po.entra_object_id = g.external_id
                    self.logger.debug(f"DBX Group Lookup {p} - ID {g.external_id}")
                else:
                    self.logger.debug(f"DBX Group Lookup {p} - not found...")
            else:
                po.id = None
                po.email = None
                po.app_id = None

            if not po.id and not po.email and not po.app_id:
                self.logger.debug(f"DBX Policy Export - {policy.catalog}.{policy.catalog_schema}.{policy.table} - No valid ID found for {p}")
            else:            
                permission.objects.append(po)

        if len(permission.objects) > 0:
            policy.permissions.append(permission)

        self.logger.debug(f"DBX Policy Export - {policy.catalog}.{policy.catalog_schema}.{policy.table} - {json.dumps(policy, default=pydantic_encoder, indent=4)}")
        return policy

    def __get_key_set__(self, key) -> List[str]:
        """
        Generates a set of keys from a given key string by splitting it on periods.
        Args:
            key (str): The key string to split into a set of keys.
        Returns:
            List[str]: A list of keys generated from the input key string.
        """
        keys = key.split(".")
        key_set = []

        for i in range(0, len(keys)):
            key_set.append(".".join(keys[0:i+1]))

        return key_set
    
    def __get_user_key_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
        """
        Retrieves the permissions for a user or service principal for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            Tuple[bool, bool, bool]: A tuple containing three boolean values indicating:
                - Whether the principal has catalog prerequisites.
                - Whether the principal has schema prerequisites.
                - Whether the principal has read permissions.
        """
        if principal in self.snapshot and key in self.snapshot[principal].maps:
            catalog_prereq = self.snapshot[principal].maps[key].catalog_prerequisites
            schema_prereq = self.snapshot[principal].maps[key].schema_prerequisites
            read_permission = self.snapshot[principal].maps[key].read_permissions

            self.logger.debug(f"DBX Evaluate - Principal ({principal}) Key ({key}) - {catalog_prereq}|{schema_prereq}|{read_permission}")
            
            if self.snapshot[principal].maps[key].catalog_all_cascade or self.snapshot[principal].maps[key].schema_all_cascade:
                return True, True, True

            return catalog_prereq, schema_prereq, read_permission
        else:
            return False, False, False 

    def __coalesce_user_group_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
        """
        Coalesces the permissions of a user or service principal with their group memberships for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            Tuple[bool, bool, bool]: A tuple containing three boolean values indicating:
                - Whether the principal has catalog prerequisites.
                - Whether the principal has schema prerequisites.
                - Whether the principal has read permissions.
        """
        catalog_prereq = False
        schema_prereq = False
        read_permission = False

        for member_group in self.snapshot[principal].group_membership:
            key_set = self.__get_key_set__(key)
            for k in key_set:
                c, s, r = self.__get_user_key_permissions__(member_group, k)                

                catalog_prereq = catalog_prereq if catalog_prereq else c
                schema_prereq = schema_prereq if schema_prereq else s
                read_permission = read_permission if read_permission else r
                self.logger.debug(f"DBX Evaluate - Principal ({principal}) Group ({member_group}) Key ({k}) - {catalog_prereq}|{schema_prereq}|{read_permission}")

                if catalog_prereq and schema_prereq and read_permission:
                    break
            
            if catalog_prereq and schema_prereq and read_permission:
                    break
        
        return catalog_prereq, schema_prereq, read_permission

    def __has_read_permissions__(self, principal:str, key:str) -> bool:
        """
        Checks if a user or service principal has read permissions for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            bool: True if the principal has read permissions for the key, False otherwise.
        """
        catalog_prereq, schema_prereq, read_permission = self.__get_user_key_permissions__(principal, key)

        if not (catalog_prereq and schema_prereq and read_permission):
            group_catalog_prereq, _group_schema_prereq, group_read_permission = self.__coalesce_user_group_permissions__(principal, key)

            catalog_prereq = catalog_prereq if catalog_prereq else group_catalog_prereq
            schema_prereq = schema_prereq if schema_prereq else _group_schema_prereq
            read_permission = read_permission if read_permission else group_read_permission

        return catalog_prereq and schema_prereq and read_permission
    
    def __is_in_group__(self, principal:str, group:str) -> bool:
        """
        Checks if a user or service principal is a member of a specified group.
        Args:
            principal (str): The principal identifier (email or UUID).
            group (str): The name of the group to check membership against.
        Returns:
            bool: True if the principal is a member of the group, False otherwise.
        """
        if principal in self.snapshot:            
            if group in self.snapshot[principal].group_membership:
                return True

        return False

    def __get_read_permissions__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> List[Tuple[str, str]]:
        """
        Retrieves the read permissions for a given catalog, schema, and table.
        This method checks the privileges for each principal and returns a list of user or service principal identifiers
        that have read permissions for the specified key.
        Args:
            privileges (List[Privilege]): A list of Privilege objects to check for read permissions.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            List[str]: A list of user or service principal identifiers that have read permissions for the specified key.
        """
        user_permissions = []

        key = self.__get_three_part_key__(catalog, schema, table)

        for r in privileges:
            if any(p in self.dbx_read_permissions for p in r.privileges):
                if self.__has_read_permissions__(r.principal, key):
                    if r.get_principal_type() == IamType.GROUP: 
                        identities = self.workspace.get_workspace_identities(include_entra_groups=True)

                        for identity in identities:
                            if self.__is_in_group__(identity, r.principal):
                                if not identity in user_permissions:
                                    self.logger.debug(f"DBX User/Entra Group ({identity}) added by {r.principal} group for {key}...")
                                    user_permissions.append((identity, "indirect"))
                    if not r.principal in user_permissions:
                        self.logger.debug(f"DBX Principal ({r.principal}) direct add for {key}...")
                        user_permissions.append((r.principal, "direct"))
                else:
                    self.logger.debug(f"DBX Principal ({r.principal}) does not have read permissions for {key}...")

        return user_permissions