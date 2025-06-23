import logging
import json
import os
from pydantic.json import pydantic_encoder

from databricks.sdk import (
    WorkspaceClient, AccountClient
)

from typing import List
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import SecurableType

from policyweaver.models.config import (
    SourceSchema, Source
)
from policyweaver.plugins.databricks.model import (
    DatabricksUser, DatabricksServicePrincipal, DatabricksGroup,
    DatabricksGroupMember, Account, Workspace, Catalog, Schema, Table,
    Function, FunctionMap, Privilege
)
from policyweaver.core.enum import (
    IamType
)

from policyweaver.core.auth import ServicePrincipal

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

            for u in self.__account.users:
                if u.email not in [w.email for w in self.__workspace.users]:
                    self.logger.debug(f"DBX WORKSPACE User {u.email} not found in workspace, adding...")
                    self.__workspace.users.append(u)
                else:
                    x = self.__workspace.lookup_user_by_email(u.email)

                    if not x.external_id:
                        self.logger.debug(f"DBX WORKSPACE User {u.email} found in workspace, but external_id is missing, updating...")
                        x.external_id = u.external_id
            
            for s in self.__account.service_principals:
                if s.application_id not in [w.application_id for w in self.__workspace.service_principals]:
                    self.logger.debug(f"DBX WORKSPACE Service Principal {s.application_id} not found in workspace, adding...")
                    self.__workspace.service_principals.append(s)
                else:
                    x = self.__workspace.lookup_service_principal_by_id(s.application_id)

                    if not x.external_id:
                        self.logger.debug(f"DBX WORKSPACE Service Principal {s.application_id} found in workspace, but external_id is missing, updating...")
                        x.external_id = s.external_id

            self.__workspace.groups.extend([g for g in self.__account.groups if g.name not in [w.name for w in self.__workspace.groups]])

            self.__workspace.catalog = Catalog(
                    name=api_catalog.name,
                    schemas=self.__get_catalog_schemas__(
                        api_catalog.name, source.schemas
                    ),
                    privileges=self.__get_privileges__(
                        SecurableType.CATALOG.value, api_catalog.name
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

    def __get_privileges__(self, type:str, name) -> List[Privilege]:
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
                            SecurableType.SCHEMA.value, s.full_name
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
                privileges=self.__get_privileges__(SecurableType.TABLE.value, t.full_name),
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
                privileges=self.__get_privileges__(SecurableType.FUNCTION.value, f.full_name),
            )
            for f in self.workspace_client.functions.list(
                catalog_name=catalog, schema_name=schema
            )
            if f.full_name in inscope
        ]

        self.logger.debug(f"DBX WORKSPACE Functions for {catalog}.{schema}: {json.dumps(functions, default=pydantic_encoder, indent=4)}") 
        return functions