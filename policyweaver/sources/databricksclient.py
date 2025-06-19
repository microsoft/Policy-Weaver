import logging
import json
import os
from pydantic.json import pydantic_encoder

from databricks.sdk import (
    WorkspaceClient, AccountClient
)

from typing import List, Tuple
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import SecurableType

from policyweaver.models.databricksmodel import *
from policyweaver.models.common import *

from policyweaver.weavercore import PolicyWeaverCore
from policyweaver.auth import ServicePrincipal

class DatabricksAPIClient:
    """
    Databricks API Client for fetching account and workspace policies.
    This client uses the Databricks SDK to interact with the Databricks account and workspace
    and retrieve users, service principals, groups, catalogs, schemas, tables, and privileges.
    This class is designed to be used within the Policy Weaver framework to gather and map policies
    from Databricks workspaces and accounts.
    """
    def __init__(self):
        """
        Initializes the Databricks API Client with account and workspace clients.
        Sets up the logger for the client.
        Raises:
            EnvironmentError: If required environment variables are not set.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")

        self.account_client = AccountClient(host="https://accounts.azuredatabricks.net",
                                            client_id=ServicePrincipal.ClientId,
                                            client_secret=os.environ["DBX_ACCOUNT_API_TOKEN"],
                                            account_id=os.environ["DBX_ACCOUNT_ID"])
        
        self.workspace_client = WorkspaceClient(host=os.environ["DBX_HOST"],
                                                azure_tenant_id=ServicePrincipal.TenantId,
                                                azure_client_id=ServicePrincipal.ClientId,
                                                azure_client_secret=ServicePrincipal.ClientSecret)

    def __get_account(self) -> Account:
        """
        Fetches the account details including users, service principals, and groups.
        Returns:
            Account: An Account object containing the account ID, users, service principals, and groups.
        """
        account = Account(
            id = self.account_client.api_client.account_id,
            users=self.__get_account_users__(),
            service_principals=self.__get_account_service_principals__(),
            groups=self.__get_account_groups__()
        )

        self.logger.debug(f"DBX Account: {json.dumps(account, default=pydantic_encoder, indent=4)}")

        return account

    def __get_account_users__(self) -> List[DatabricksUser]:
        """
        Retrieves the list of users in the account.
        Returns:
            List[DatabricksUser]: A list of DatabricksUser objects representing the users in the account.
        """
        users = [
            DatabricksUser(
                id=u.id,
                name=u.display_name,
                email="".join([e.value for e in u.emails if e.primary]),
                external_id=u.external_id
            )
            for u in self.account_client.users.list()
        ]

        self.logger.debug(f"DBX ACCOUNT Users: {json.dumps(users, default=pydantic_encoder, indent=4)}")

        return users

    def __get_account_service_principals__(self) -> List[DatabricksServicePrincipal]:
        """
        Retrieves the list of service principals in the account.
        Returns:
            List[DatabricksServicePrincipal]: A list of DatabricksServicePrincipal objects representing
        """
        service_principals = [
            DatabricksServicePrincipal(
                id=s.id,
                name=s.display_name,
                application_id=s.application_id,
                external_id=s.external_id
            )
            for s in self.account_client.service_principals.list()
        ]

        self.logger.debug(f"DBX ACCOUNT Service Principals: {json.dumps(service_principals, default=pydantic_encoder, indent=4)}")

        return service_principals
    
    def __get_account_groups__(self) -> List[DatabricksGroup]:
        """
        Retrieves the list of groups in the account.
        Returns:
            List[DatabricksGroup]: A list of DatabricksGroup objects representing the groups in the account.
        """
        groups = []

        for g in self.account_client.groups.list():
            group = DatabricksGroup(
                id=g.id,
                name=g.display_name,
                members=[]
            )

            for m in g.members:
                gm = DatabricksGroupMember(
                        id=m.value,
                        name=m.display
                    )
                
                if m.ref.find("Users") > -1:
                    gm.type = IamType.USER
                elif m.ref.find("ServicePrincipals") > -1:
                    gm.type = IamType.SERVICE_PRINCIPAL
                else:
                    gm.type = IamType.GROUP

                group.members.append(gm)
            
            groups.append(group)

        self.logger.debug(f"DBX ACCOUNT Groups: {json.dumps(groups, default=pydantic_encoder, indent=4)}")
        return groups
        
    def get_workspace_policy_map(self, source: Source) -> Workspace:
        """
        Fetches the workspace policy map for a given source.
        Args:
            source (Source): The source object containing the workspace URL, account ID, and API token.
        Returns:
            Tuple[Account, Workspace]: A tuple containing the Account and Workspace objects.
        Raises:
            NotFound: If the catalog specified in the source is not found in the workspace.
        """
        try:
            self.__account = self.__get_account()
            api_catalog = self.workspace_client.catalogs.get(source.name)

            self.logger.debug(f"DBX Policy Export for {api_catalog.name}...")

            self.__workspace = Workspace(
                users=self.__get_workspace_users__(),
                groups=self.__get_workspace_groups__(),
                service_principals=self.__get_workspace_service_principals__()
            )

            self.__workspace.users.extend([u for u in self.__account.users if u.email not in [w.email for w in self.__workspace.users]])
            self.__workspace.service_principals.extend([s for s in self.__account.service_principals if s.application_id not in [w.application_id for w in self.__workspace.service_principals]])
            self.__workspace.groups.extend([g for g in self.__account.groups if g.name not in [w.name for w in self.__workspace.groups]])

            self.__workspace.catalog = Catalog(
                    name=api_catalog.name,
                    schemas=self.__get_catalog_schemas__(
                        api_catalog.name, source.schemas
                    ),
                    privileges=self.__get_privileges__(
                        SecurableType.CATALOG, api_catalog.name
                    ),
                )
            
            self.logger.debug(f"DBX WORKSPACE Policy Map for {api_catalog.name}: {json.dumps(self.__workspace, default=pydantic_encoder, indent=4)}")
            return (self.__account, self.__workspace)
        except NotFound:
            return None

    def __get_workspace_users__(self) -> List[DatabricksUser]:
        """
        Retrieves the list of users in the workspace.
        Returns:
            List[DatabricksUser]: A list of DatabricksUser objects representing the users in the workspace.
        """
        users = [
            DatabricksUser(
                id=u.id,
                name=u.display_name,
                email="".join([e.value for e in u.emails if e.primary]),
                external_id=u.external_id
            )
            for u in self.workspace_client.users.list()
        ]

        self.logger.debug(f"DBX WORKSPACE Users: {json.dumps(users, default=pydantic_encoder, indent=4)}")

        return users

    def __get_workspace_service_principals__(self) -> List[DatabricksServicePrincipal]:
        """
        Retrieves the list of service principals in the workspace.
        Returns:
            List[DatabricksServicePrincipal]: A list of DatabricksServicePrincipal objects representing
            the service principals in the workspace.
        """
        service_principals = [
            DatabricksServicePrincipal(
                id=s.id,
                name=s.display_name,
                application_id=s.application_id,
                external_id=s.external_id
            )
            for s in self.workspace_client.service_principals.list()
        ]

        self.logger.debug(f"DBX WORKSPACE Service Principals: {json.dumps(service_principals, default=pydantic_encoder, indent=4)}")

        return service_principals
    
    def __get_workspace_groups__(self) -> List[DatabricksGroup]:
        """
            Retrieves the list of groups in the workspace.
        Returns:
            List[DatabricksGroup]: A list of DatabricksGroup objects representing the groups in the workspace.
        """
        groups = []

        for g in self.workspace_client.groups.list():
            group = DatabricksGroup(
                id=g.id,
                name=g.display_name,
                members=[]
            )

            for m in g.members:
                gm = DatabricksGroupMember(
                        id=m.value,
                        name=m.display
                    )
                
                if m.ref.find("Users") > -1:
                    gm.type = IamType.USER
                elif m.ref.find("ServicePrincipals") > -1:
                    gm.type = IamType.SERVICE_PRINCIPAL
                else:
                    gm.type = IamType.GROUP

                group.members.append(gm)
            
            groups.append(group)

        self.logger.debug(f"DBX WORKSPACE Groups: {json.dumps(groups, default=pydantic_encoder, indent=4)}")
        return groups

    def __get_privileges__(self, type: SecurableType, name) -> List[Privilege]:
        """
        Retrieves the privileges for a given securable type and name.
        Args:
            type (SecurableType): The type of the securable (e.g., C
            atalog, Schema, Table, Function).
            name (str): The full name of the securable.
        Returns:
            List[Privilege]: A list of Privilege objects representing the privileges assigned to the securable.
        """
        api_privileges = self.workspace_client.grants.get(
            securable_type=type, full_name=name
        )

        privileges =  []

        for p in api_privileges.privilege_assignments:
            privilege = Privilege(principal=p.principal, privileges=[e.value for e in p.privileges])
   
            privileges.append(privilege)

        self.logger.debug(f"DBX WORKSPACE Privileges for {name}-{type}: {json.dumps(privileges, default=pydantic_encoder, indent=4)}")
        return privileges

    def __get_schema_from_list__(self, schema_list, schema) -> Schema:
        if schema_list:
            search = [s for s in schema_list if s.name == schema]

            if search:
                return search[0]

        return None

    def __get_catalog_schemas__(self, catalog: str, schema_filters: List[SourceSchema]) -> List[Schema]:
        """
        Retrieves the schemas for a given catalog, applying any filters specified in the schema_filters.
        Args:
            catalog (str): The name of the catalog to retrieve schemas from.
            schema_filters (List[SourceSchema]): A list of SourceSchema objects containing filters for schemas.
        Returns:
            List[Schema]: A list of Schema objects representing the schemas in the catalog.
        """
        api_schemas = self.workspace_client.schemas.list(catalog_name=catalog)

        if schema_filters:
            self.logger.debug(f"DBX WORKSPACE Policy Export Schema Filters for {catalog}: {json.dumps(schema_filters, default=pydantic_encoder, indent=4)}")
            
            filter = [s.name for s in schema_filters]
            api_schemas = [s for s in api_schemas if s.name in filter]

        schemas = []

        for s in api_schemas:
            if s.name != "information_schema":
                self.logger.debug(f"DBX WORKSPACE Policy Export for schema {catalog}.{s.name}...")
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

        self.logger.debug(f"DBX WORKSPACE Schemas for {catalog}: {json.dumps(schemas, default=pydantic_encoder, indent=4)}")

        return schemas

    def __get_schema_tables__(self, catalog: str, schema: str, table_filters: List[str]) -> List[Table]:
        """
        Retrieves the tables for a given catalog and schema, applying any filters specified in the table_filters
        Args:
            catalog (str): The name of the catalog to retrieve tables from.
            schema (str): The name of the schema to retrieve tables from.
            table_filters (List[str]): A list of table names to filter the results.
        Returns:
            List[Table]: A list of Table objects representing the tables in the catalog and schema.
        """
        api_tables = self.workspace_client.tables.list(
            catalog_name=catalog, schema_name=schema
        )

        if table_filters:
            api_tables = [t for t in api_tables if t.name in table_filters]

        tables = [
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

        self.logger.debug(f"DBX WORKSPACE Tables for {catalog}.{schema}: {json.dumps(tables, default=pydantic_encoder, indent=4)}")

        return tables

    def __get_column_mask_functions__(self, catalog: str, schema: str, tables: List[Table]) -> List[Function]:
        """
        Retrieves the column mask functions for a given catalog and schema.
        Args:
            catalog (str): The name of the catalog to retrieve column mask functions from.
            schema (str): The name of the schema to retrieve column mask functions from.
            tables (List[Table]): A list of Table objects to check for column masks.
        Returns:
            List[Function]: A list of Function objects representing the column mask functions in the catalog and schema.
        """
        inscope = []

        for t in tables:
            if t.row_filter:
                if t.row_filter.name not in inscope:
                    inscope.append(t.row_filter.name)

            if t.column_masks:
                for m in t.column_masks:
                    if m.name not in inscope:
                        inscope.append(m.name)

        functions = [
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

        self.logger.debug(f"DBX WORKSPACE Functions for {catalog}.{schema}: {json.dumps(functions, default=pydantic_encoder, indent=4)}") 
        return functions

class DatabricksPolicyWeaver(PolicyWeaverCore):
    """
        Databricks Policy Weaver for Unity Catalog.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from Databricks Unity Catalog to the Policy Weaver framework.
    """
    dbx_account_users_group = "account users"
    dbx_read_permissions = ["SELECT", "ALL_PRIVILEGES"]
    dbx_catalog_read_prereqs = ["USE_CATALOG", "ALL_PRIVILEGES"]
    dbx_schema_read_prereqs = ["USE_SCHEMA", "ALL_PRIVILEGES"]

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
        
        os.environ["DBX_HOST"] = config.databricks.workspace_url
        os.environ["DBX_ACCOUNT_ID"] = config.databricks.account_id
        os.environ["DBX_ACCOUNT_API_TOKEN"] = config.databricks.account_api_token

        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = DatabricksAPIClient()

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

    def map_policy(self) -> PolicyExport:
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

        policies = self.__build_export_policies__()

        self.__write_to_log__(self.connector_type, self.workspace.model_dump())

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
        """
        Builds the export policies from the collected privileges in the snapshot.
        This method constructs Policy objects for each catalog, schema, and table,
        applying the read permissions and prerequisites.
        Returns:
            List[Policy]: A list of Policy objects representing the export policies.
        """
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
            po.type=IamType.USER if Utils.is_email(p) else IamType.SERVICE_PRINCIPAL

            if po.type == IamType.USER:
                u = self.workspace.lookup_user_by_email(p)
        
                if u:
                    self.logger.debug(f"DBX User Lookup - {p} - {u.model_dump_json(indent=4)}")
                    po.id = u.external_id if u.external_id else p
                else:
                    self.logger.debug(f"DBX User Lookup - {p} - not found, using email...")
                    po.id = p
            elif po.type == IamType.SERVICE_PRINCIPAL:
                s = self.workspace.lookup_service_principal_by_id(p)

                if s:
                    po.id = s.external_id if s.external_id else p
            
            permission.objects.append(po)

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
    
    def __get_read_permissions__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> List[str]:
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
                        indentities = self.workspace.get_workspace_identities()

                        for identity in indentities:
                            if self.__is_in_group__(identity, r.principal):
                                if not identity in user_permissions:
                                    self.logger.debug(f"DBX User ({identity}) added by {r.principal} group for {key}...")
                                    user_permissions.append(identity)
                    else:
                        if not r.principal in user_permissions:
                            self.logger.debug(f"DBX Principal ({r.principal}) direct add for {key}...")
                            user_permissions.append(r.principal)
                else:
                    self.logger.debug(f"DBX Principal ({r.principal}) does not have read permissions for {key}...")

        return user_permissions