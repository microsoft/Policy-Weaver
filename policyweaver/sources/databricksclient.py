import logging

from databricks.sdk import WorkspaceClient
from typing import List, Tuple
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import SecurableType

from policyweaver.models.databricksmodel import *
from policyweaver.models.common import *

from policyweaver.weavercore import PolicyWeaverCore
from policyweaver.auth import ServicePrincipal

class DatabricksAPIClient:
    logger = logging.getLogger("POLICY_WEAVER")

    def __init__(self, workspace: str, service_principal: ServicePrincipal):
        self.workspace_client = WorkspaceClient(host=workspace,
                                                azure_tenant_id=service_principal.tenant_id,
                                                azure_client_id=service_principal.client_id,
                                                azure_client_secret=service_principal.client_secret)

    def get_workspace_policy_map(self, source: Source) -> Workspace:
        try:
            api_catalog = self.workspace_client.catalogs.get(source.name)

            self.logger.debug(f"Policy Export for {api_catalog.name}...")

            return Workspace(
                catalog=Catalog(
                    name=api_catalog.name,
                    schemas=self.__get_catalog_schemas__(
                        api_catalog.name, source.schemas
                    ),
                    privileges=self.__get_privileges__(
                        SecurableType.CATALOG, api_catalog.name
                    ),
                ),
                users=self.__get_workspace_users__(),
                groups=self.__get_workspace_groups__(),
            )
            return
        except NotFound:
            return None

    def __get_workspace_users__(self):
        return [
            WorkspaceUser(
                id=u.id,
                name=u.display_name,
                email="".join([e.value for e in u.emails if e.primary]),
            )
            for u in self.workspace_client.users.list()
        ]

    def __get_workspace_groups__(self):
        return [
            WorkspaceGroup(
                id=g.id,
                name=g.display_name,
                members=[
                    WorkspaceGroupMember(
                        id=m.value,
                        name=m.display,
                        type=IamType.USER if m.ref.find("Users") > -1 else IamType.GROUP,
                    )
                    for m in g.members
                ],
            )
            for g in self.workspace_client.groups.list()
        ]

    def __get_privileges__(self, type: SecurableType, name) -> List[Privilege]:
        api_privileges = self.workspace_client.grants.get(
            securable_type=type, full_name=name
        )

        return [
            Privilege(principal=p.principal, privileges=[e.value for e in p.privileges])
            for p in api_privileges.privilege_assignments
        ]

    def __get_schema_from_list__(self, schema_list, schema):
        if schema_list:
            search = [s for s in schema_list if s.name == schema]

            if search:
                return search[0]

        return None

    def __get_catalog_schemas__(
        self, catalog: str, schema_filters: List[SourceSchema]
    ) -> List[Schema]:
        api_schemas = self.workspace_client.schemas.list(catalog_name=catalog)

        if schema_filters:
            filter = [s.name for s in schema_filters]
            api_schemas = [s for s in api_schemas if s.name in filter]

        schemas = []

        for s in api_schemas:
            if s.name != "information_schema":
                self.logger.debug(f"Policy Export for schema {s.name}...")
                schema_filter = self.__get_schema_from_list__(schema_filters, s.name)

                tbls = self.__get_schema_tables__(
                    catalog=catalog,
                    schema=s.name,
                    table_filters=None if not schema_filters else schema_filter.tables,
                )

                schemas.append(
                    Schema(
                        name=s.name,
                        tables=tbls,
                        privileges=self.__get_privileges__(
                            SecurableType.SCHEMA, s.full_name
                        ),
                        mask_functions=self.__get_column_mask_functions__(
                            catalog, s.name, tbls
                        ),
                    )
                )

        return schemas

    def __get_schema_tables__(
        self, catalog: str, schema: str, table_filters: List[str]
    ) -> List[Table]:
        api_tables = self.workspace_client.tables.list(
            catalog_name=catalog, schema_name=schema
        )

        if table_filters:
            api_tables = [t for t in api_tables if t.name in table_filters]

        return [
            Table(
                name=t.name,
                row_filter=None
                if not t.row_filter
                else FunctionMap(
                    name=t.row_filter.function_name,
                    columns=t.row_filter.input_column_names,
                ),
                column_masks=[
                    FunctionMap(
                        name=c.mask.function_name, columns=c.mask.using_column_names
                    )
                    for c in t.columns
                    if c.mask
                ],
                privileges=self.__get_privileges__(SecurableType.TABLE, t.full_name),
            )
            for t in api_tables
        ]

    def __get_column_mask_functions__(
        self, catalog: str, schema: str, tables: List[Table]
    ) -> List[Function]:
        inscope = []

        for t in tables:
            if t.row_filter:
                if t.row_filter.name not in inscope:
                    inscope.append(t.row_filter.name)

            if t.column_masks:
                for m in t.column_masks:
                    if m.name not in inscope:
                        inscope.append(m.name)

        return [
            Function(
                name=f.full_name,
                sql=f.routine_definition,
                privileges=self.__get_privileges__(SecurableType.FUNCTION, f.full_name),
            )
            for f in self.workspace_client.functions.list(
                catalog_name=catalog, schema_name=schema
            )
            if f.full_name in inscope
        ]

class DatabricksPolicyWeaver(PolicyWeaverCore):
    dbx_account_users_group = "account users"
    dbx_read_permissions = ["SELECT", "ALL_PRIVILEGES"]
    dbx_catalog_read_prereqs = ["USE_CATALOG", "ALL_PRIVILEGES"]
    dbx_schema_read_prereqs = ["USE_SCHEMA", "ALL_PRIVILEGES"]

    def map_policy(self) -> PolicyExport:
        self.workspace = self.api_client.get_workspace_policy_map(self.config.source)
        self.__collect_privileges__(self.workspace.catalog.privileges, self.workspace.catalog.name)        

        for schema in self.workspace.catalog.schemas:
            self.__collect_privileges__(schema.privileges, self.workspace.catalog.name, schema.name)            

            for tbl in schema.tables:
                self.__collect_privileges__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name)                

        self.__apply_access_model__()

        policies = self.__build_export_policies__()

        self.__write_to_log__(self.connector_type, self.workspace.model_dump())

        return PolicyExport(source=self.config.source, type=self.connector_type, policies=policies)
    
    def __init__(self, config:DatabricksSourceMap, service_principal: ServicePrincipal) -> None:
        super().__init__(PolicyWeaverConnectorType.UNITY_CATALOG, config, service_principal)

        self.workspace = None
        self.snapshot = {}
        self.api_client = DatabricksAPIClient(config.workspace_url, service_principal)

    def __get_three_part_key__(self, catalog:str, schema:str=None, table:str=None) -> str:
        schema = f".{schema}" if schema else ""
        table = f".{table}" if table else ""

        return f"{catalog}{schema}{table}"
    
    def __collect_privileges__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> None:
        for privilege in privileges:
            dependency_map = DependencyMap(
                catalog=catalog,
                schema=schema,
                table=table,
                )

            if privilege.privileges:
                for p in privilege.privileges:
                    dependency_map.privileges.append(p)
                    
                    if privilege.principal not in self.snapshot:
                        self.snapshot[privilege.principal] = PrivilegeSnapshot(
                                principal=privilege.principal,
                                type=IamType.USER if Utils.is_email(privilege.principal) else IamType.GROUP,
                                maps={dependency_map.key: dependency_map}
                            )
                    else:
                        if dependency_map.key not in self.snapshot[privilege.principal].maps:
                            self.snapshot[privilege.principal].maps[dependency_map.key] = dependency_map
                        else:
                            if p not in self.snapshot[privilege.principal].maps[dependency_map.key].privileges:
                                self.snapshot[privilege.principal].maps[dependency_map.key].privileges.append(p)
    
    def __search_privileges__(self, snapshot:PrivilegeSnapshot, key:str, prereqs:List[str]) -> bool:
        if key in snapshot.maps:
            if [p for p in snapshot.maps[key].privileges if p in prereqs]:
                return True
        
        return False
    
    def __apply_access_model__(self) -> None:
        for self.workspace_user in self.workspace.users:
            if self.workspace_user.email not in self.snapshot:
                self.snapshot[self.workspace_user.email] = PrivilegeSnapshot(
                    principal=self.workspace_user.email,
                    type=IamType.USER,
                    maps={}
                )
        
        for self.workspace_group in self.workspace.groups:
            if self.workspace_group.name not in self.snapshot:
                self.snapshot[self.workspace_group.name] = PrivilegeSnapshot(
                    principal=self.workspace_group.name,
                    type=IamType.GROUP,
                    maps={}
                )

        for principal in self.snapshot:
            self.snapshot[principal] = self.__apply_privilege_inheritence__(self.snapshot[principal])

            object_id = self.workspace.lookup_object_id(principal, self.snapshot[principal].type)
            
            if object_id:
                self.snapshot[principal].group_membership = self.workspace.get_user_groups(object_id)
            
            self.snapshot[principal].group_membership.append(self.dbx_account_users_group)

    def __apply_privilege_inheritence__(self, privilege_snapshot:PrivilegeSnapshot) -> PrivilegeSnapshot:
        for map_key in privilege_snapshot.maps:
            map = privilege_snapshot.maps[map_key]
            catalog_key = None if not map.catalog else self.__get_three_part_key__(map.catalog)
            schema_key = None if not map.catalog_schema else self.__get_three_part_key__(map.catalog, map.catalog_schema)

            if catalog_key in privilege_snapshot.maps:
                privilege_snapshot.maps[map_key].catalog_prerequisites = \
                    self.__search_privileges__(privilege_snapshot, catalog_key, self.dbx_catalog_read_prereqs)
                
            if schema_key and schema_key in privilege_snapshot.maps:
                privilege_snapshot.maps[map_key].schema_prerequisites = \
                    self.__search_privileges__(privilege_snapshot, schema_key, self.dbx_schema_read_prereqs)
            else:
                privilege_snapshot.maps[map_key].schema_prerequisites = \
                    self.__search_privileges__(privilege_snapshot, map_key, self.dbx_schema_read_prereqs)
                
            privilege_snapshot.maps[map_key].read_permissions = \
                self.__search_privileges__(privilege_snapshot, map_key, self.dbx_read_permissions)
            
        return privilege_snapshot

    def __build_export_policies__(self) -> List[Policy]:
        policies = []

        if self.workspace.catalog.privileges:
            policies.append(
                self.__build_policy__(
                    self.__get_read_permissions__(self.workspace.catalog.privileges, self.workspace.catalog.name),
                    self.workspace.catalog.name))
        
        for schema in self.workspace.catalog.schemas:
            if schema.privileges:
                policies.append(
                    self.__build_policy__(
                        self.__get_read_permissions__(schema.privileges, self.workspace.catalog.name, schema.name),
                        self.workspace.catalog.name, schema.name))

            for tbl in schema.tables:
                if tbl.privileges:
                    policies.append(
                        self.__build_policy__(
                            self.__get_read_permissions__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name),
                            self.workspace.catalog.name, schema.name, tbl.name))
        

        return policies

    def __build_policy__(self, table_permissions, catalog, schema=None, table=None) -> Policy:
        return Policy(
            catalog=catalog,
            catalog_schema=schema,
            table=table,
            permissions=[
                Permission(
                    name=PermissionType.SELECT,
                    state=PermissionState.GRANT,
                    objects=[
                        PermissionObject(id=p, type=IamType.USER)
                        for p in table_permissions
                    ],
                )
            ],
        )

    def __get_key_set__(self, key) -> List[str]:
        keys = key.split(".")
        key_set = []

        for i in range(0, len(keys)):
            key_set.append(".".join(keys[0:i+1]))

        return key_set
    
    def __get_user_key_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
        if principal in self.snapshot and key in self.snapshot[principal].maps:
            catalog_prereq = self.snapshot[principal].maps[key].catalog_prerequisites
            schema_prereq = self.snapshot[principal].maps[key].schema_prerequisites
            read_permission = self.snapshot[principal].maps[key].read_permissions

            self.logger.debug(f"Evaluate - Principal ({principal}) Key ({key}) - {catalog_prereq}|{schema_prereq}|{read_permission}")
            
            return catalog_prereq, schema_prereq, read_permission
        else:
            return False, False, False 

    def __coalesce_user_group_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
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
                self.logger.debug(f"Evaluate - Principal ({principal}) Group ({member_group}) Key ({k}) - {catalog_prereq}|{schema_prereq}|{read_permission}")

                if catalog_prereq and schema_prereq and read_permission:
                    break
            
            if catalog_prereq and schema_prereq and read_permission:
                    break
        
        return catalog_prereq, schema_prereq, read_permission

    def __has_read_permissions__(self, principal:str, key:str) -> bool:
        catalog_prereq, schema_prereq, read_permission = self.__get_user_key_permissions__(principal, key)

        if not (catalog_prereq and schema_prereq and read_permission):
            group_catalog_prereq, _group_schema_prereq, group_read_permission = self.__coalesce_user_group_permissions__(principal, key)

            catalog_prereq = catalog_prereq if catalog_prereq else group_catalog_prereq
            schema_prereq = schema_prereq if schema_prereq else _group_schema_prereq
            read_permission = read_permission if read_permission else group_read_permission

        return catalog_prereq and schema_prereq and read_permission
    
    def __is_in_group__(self, principal:str, group:str) -> bool:
        if principal in self.snapshot:            
            if group in self.snapshot[principal].group_membership:
                return True

        return False
    
    def __get_read_permissions__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> List[str]:
        user_permissions = []

        key = self.__get_three_part_key__(catalog, schema, table)

        for r in privileges:
            if any(p in self.dbx_read_permissions for p in r.privileges):
                if self.__has_read_permissions__(r.principal, key):
                    if Utils.is_email(r.principal):                    
                        if not r.principal in user_permissions:
                            self.logger.debug(f"Principal ({r.principal}) direct add for {key}...")
                            user_permissions.append(r.principal)
                    else:
                        for user in self.workspace.users:
                            self.logger.debug(f"Membership Check - User ({user.email}) | Group({r.principal}) for Key({key})")
                            if self.__is_in_group__(user.email, r.principal):
                                if not user.email in user_permissions:
                                    self.logger.debug(f"Principal ({user.email}) added by {r.principal} group for {key}...")
                                    user_permissions.append(user.email)
                else:
                    self.logger.debug(f"Principal ({r.principal}) does not have read permissions for {key}...")

        return user_permissions