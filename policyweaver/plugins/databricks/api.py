import logging
import json
import os
import re
from pydantic.json import pydantic_encoder

from databricks.sdk import (
    WorkspaceClient, AccountClient
)
from typing import List, Dict, Any
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import SecurableType

from policyweaver.models.config import (
    SourceSchema, Source
)
from policyweaver.plugins.databricks.model import (
    DatabricksColumnMask, DatabricksRowFilter, ColumnMaskExtraction, RowFilterDetails, RowFilterDetailGroup, DatabricksUser, DatabricksServicePrincipal, DatabricksGroup,
    DatabricksGroupMember, Account, RowFilterFunctionInfo, TableObject, Workspace, Catalog, Schema, Table,
    Function, FunctionMap, Privilege
)
from policyweaver.core.enum import (
    ColumnMaskType, RowFilterType,
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
        
        self.row_filter_func_maps = []

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

    @staticmethod
    def get_members(group_id, dbx_groups):
        dbx_group = dbx_groups.get(group_id)
        if not dbx_group:
            print("Group not found")
            return []
        members = list()
        if not ("members" in dbx_group):
            return members

        for member in dbx_group["members"]:
            if "Groups" in member["$ref"]:
                subgroup_id = member["value"]
                subgroup = dbx_groups.get(subgroup_id)
                if subgroup.get("externalId"):
                    member["externalId"] = subgroup["externalId"]
                else:
                    sub_group_members = DatabricksAPIClient.get_members(member["value"], dbx_groups)
                    members.extend(sub_group_members)
        
            member["byGroup"] = dbx_group["displayName"]
            members.append(member)
        return members

    def __get_account_groups__(self) -> List[DatabricksGroup]:
        """
        Retrieves the list of groups in the account.
        Returns:
            List[DatabricksGroup]: A list of DatabricksGroup objects representing the groups in the account.
        """
        groups = []
        dbx_groups = dict()
        for g in self.account_client.groups.list():
            dbx_groups[g.id] = g.as_dict()

        for g in dbx_groups.values():
            if g.get("externalId"):
                group = DatabricksGroup(
                id=g["id"],
                name=g["displayName"],
                members=[],
                external_id=g["externalId"]
            )
            else:
                members = DatabricksAPIClient.get_members(g["id"], dbx_groups)

                group = DatabricksGroup(
                    id=g["id"],
                    name=g["displayName"],
                    members=[]
                )

                member_ids = list()
                for m in members:
                    if m["value"] in member_ids:
                        continue

                    gm = DatabricksGroupMember(
                            id=m["value"],
                            name=m["display"],
                            external_id=m.get("externalId")
                        )

                    if m["$ref"].find("Users") > -1:
                        gm.type = IamType.USER
                    elif m["$ref"].find("ServicePrincipals") > -1:
                        gm.type = IamType.SERVICE_PRINCIPAL
                    else:
                        gm.type = IamType.GROUP

                    group.members.append(gm)
                    member_ids.append(m["value"])

            groups.append(group)

        self.logger.debug(f"DBX ACCOUNT Groups: {json.dumps(groups, default=pydantic_encoder, indent=4)}")
        return groups
    
    def __get_functions__(self) -> List[RowFilterFunctionInfo]:
        """
        Retrieves the list of functions in the workspace.
        Returns:
            List[Function]: A list of Function objects representing the functions in the workspace.
        """
        row_filters = []
        for row_filter_func_map in self.row_filter_func_maps:
            func = self.workspace_client.functions.get(row_filter_func_map.name)
            rf = RowFilterFunctionInfo(
                fullname=func.full_name,
                name=func.name,
                full_data_type=func.full_data_type,
                routine_definition=func.routine_definition
            )
            row_filters.append(rf)

        return row_filters



    def get_workspace_policy_map(self, source: Source) -> tuple[Account, Workspace]:
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
                users=self.__account.users,
                groups=self.__account.groups,
                service_principals=self.__account.service_principals
            )

            self.__workspace.catalog = Catalog(name=api_catalog.name,
                                               column_masks=[], tables_with_masks=[],
                                               row_filters=[], tables_with_rls=[])
            self.__workspace.catalog.schemas = self.__get_catalog_schemas__(api_catalog.name, source.schemas)
            self.__workspace.catalog.privileges = self.__get_privileges__(SecurableType.CATALOG.value, api_catalog.name)

            #self.__workspace.catalog.row_filters = self.__get_functions__()

            self.logger.debug(f"DBX WORKSPACE Policy Map for {api_catalog.name}: {json.dumps(self.__workspace, default=pydantic_encoder, indent=4)}")
            return (self.__account, self.__workspace)
        except NotFound:
            self.logger.error(f"DBX WORKSPACE Catalog {source.name} not found in workspace {source.url}.")
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
        dbx_groups = dict()
        for g in self.workspace_client.groups.list():
            dbx_groups[g.id] = g.as_dict()

        for g in dbx_groups.values():
            if g.get("externalId"):
                group = DatabricksGroup(
                id=g["id"],
                name=g["displayName"],
                members=[],
                external_id=g["externalId"]
            )
            else:
                members = DatabricksAPIClient.get_members(g["id"], dbx_groups)

                group = DatabricksGroup(
                    id=g["id"],
                    name=g["displayName"],
                    members=[]
                )

                member_ids = list()
                for m in members:
                    if m["value"] in member_ids:
                        continue
                    gm = DatabricksGroupMember(
                            id=m["value"],
                            name=m["display"],
                            external_id=m.get("externalId")
                        )

                    if m["$ref"].find("Users") > -1:
                        gm.type = IamType.USER
                    elif m["$ref"].find("ServicePrincipals") > -1:
                        gm.type = IamType.SERVICE_PRINCIPAL
                    else:
                        gm.type = IamType.GROUP

                    group.members.append(gm)
                    member_ids.append(m["value"])

            
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
    
    def __extract_group_from_mask_function__(self, sql_definition: str, column_name: str) -> ColumnMaskExtraction:
        """
        Extracts the group name and mask pattern from a column mask function definition.
        
        Args:
            sql_definition (str): The SQL definition containing is_account_group_member function
        Returns:
            dict: Dictionary containing 'group_name' and 'mask_pattern', or None values if not found
        """
        result = ColumnMaskExtraction(column_mask_type=ColumnMaskType.UNSUPPORTED)
                
        definition = sql_definition.replace("\n", " ").replace("\r", " ").replace(" ", "")
        if not(definition[:8] == "CASEWHEN" and definition[8:31] == "is_account_group_member"):
            self.logger.warning("Unexpected format: does not start with 'CASE WHEN is_account_group_member'")
            return result
        group_name = definition[32:].split(")")[0].replace("'", "").replace('"', '')
        index_ = 32 + len(group_name) + 3
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
        elif column_name == assigned_value:
            column_name_pos = 1

        unassigned_value = split_[1].replace("END", "")
        if unassigned_value[0] in ["'", '"']:
            unassigned_value = unassigned_value[1:-1]
            mask = unassigned_value
        elif column_name == unassigned_value:
            column_name_pos = 2

        result.group_name = group_name
        result.mask_pattern = mask
        if column_name_pos == 1:
            result.column_mask_type = ColumnMaskType.UNMASK_FOR_GROUP
        elif column_name_pos == 2:
            result.column_mask_type = ColumnMaskType.MASK_FOR_GROUP
        else:
            result.column_mask_type = ColumnMaskType.UNSUPPORTED

        
        return result

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
        pattern = r"IS_ACCOUNT_GROUP_MEMBER\('([^']+)'\)THEN([^W]+?)(?:WHEN|ELSE)"
        
        matches = re.findall(pattern, sql_definition, re.IGNORECASE)
        
        for match in matches:
            group_name = match[0]
            # match[1] is string value (like 'T001'), match[2] is boolean value (true/false)
            return_value = match[1] if match[1] else match[2]
            if not group_name or not return_value:
                continue
            
            result.groups.append(RowFilterDetailGroup(
                group_name=group_name,
                return_value=return_value
            ))
        
        # Extract ELSE clause
        else_pattern = r"ELSE(.+?)END"
        else_match = re.search(else_pattern, sql_definition, re.IGNORECASE)
        if else_match:
            result.default_value = else_match.group(1) if else_match.group(1) else else_match.group(2)
        
        if not result.default_value or not result.groups:
            self.logger.warning("Could not fully parse row filter definition.")
            return None
        return result

    def __extract_if_logic_row_filter__(self, definition: str) -> RowFilterDetails:
        """
        Parse an IF row filter definition to extract group membership and their values.
        
        Args:
            sql_definition: The SQL IF statement from a row filter
        Returns:
            Dictionary containing:

        """
        
        group_name = definition[27:].split("'")[1]
        start = f"IF(IS_ACCOUNT_GROUP_MEMBER('{group_name}'),"
        if not definition.startswith(start):
            self.logger.warning("Unexpected format: does not match expected start")
            return result
        condition_for_group, condition_for_others = definition[len(start):].split(",")
        condition_for_group = condition_for_group.strip()
        condition_for_others = condition_for_others.strip()
        if condition_for_others.endswith(")"):
            condition_for_others = condition_for_others[:-1].strip()
        else:
            self.logger.warning("Unexpected format: does not match expected start")
            return result        

        result = RowFilterDetails(
            groups=[RowFilterDetailGroup(
                group_name=group_name,
                return_value=condition_for_group
            )],
            default_value=condition_for_others,
            row_filter_type=RowFilterType.EXPLICIT_GROUP_MEMBERSHIP
        )

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
        if not definition.startswith("IF(IS_ACCOUNT_GROUP_MEMBER(") and not definition.startswith("CASEWHENIS_ACCOUNT_GROUP_MEMBER("):
            self.logger.warning("Unexpected format: does not start with 'IF(IS_ACCOUNT_GROUP_MEMBER(' or 'CASEWHENIS_ACCOUNT_GROUP_MEMBER('")
            return result

        if definition.startswith("CASEWHENIS_ACCOUNT_GROUP_MEMBER("):
            result_ = self.__extract_case_when_logic_row_filter__(definition)
        else:
            result_ = self.__extract_if_logic_row_filter__(definition)
        
        if result_:
            return result_
        
        return result
    
    def __get_column_mask__(self, catalog_name: str, schema_name: str, table_name: str, column_name: str, func_map: FunctionMap) -> DatabricksColumnMask:
        """Retrieves the column mask for a given function map.
        Args:
            column_name (str): The name of the column to retrieve the mask for.
            func_map (FunctionMap): The FunctionMap object containing the name and columns of the column mask function.
        Returns:
            ColumnMask: A ColumnMask object representing the column mask function.
        """
        func = self.workspace_client.functions.get(func_map.name)
        extraction = self.__extract_group_from_mask_function__(sql_definition=func.routine_definition, column_name=column_name)
        col_mask = DatabricksColumnMask(name=func_map.name,
                              routine_definition=func.routine_definition,
                              column_name=column_name,
                              catalog_name=catalog_name,
                              schema_name=schema_name,
                              table_name=table_name)
        if extraction:
            col_mask.group_name = extraction.group_name
            col_mask.mask_pattern = extraction.mask_pattern
            col_mask.mask_type = extraction.column_mask_type
        return col_mask

    def __get_row_filter__(self, catalog_name: str, schema_name: str, table_name: str, func_map: FunctionMap) -> DatabricksRowFilter:
        """Retrieves the row filter for a given table.
        Args:
            catalog_name (str): The name of the catalog.
            schema_name (str): The name of the schema.
            table_name (str): The name of the table.
            column_name (str): The name of the column to retrieve the row filter for.
            func_map (FunctionMap): The FunctionMap object containing the name and columns of the row filter function.
        Returns:
            DatabricksRowFilter: A DatabricksRowFilter object representing the row filter for the table.
        """
        func = self.workspace_client.functions.get(func_map.name)
        details = self.__extract_logic_from_row_filter__(sql_definition=func.routine_definition)
        row_filter = DatabricksRowFilter(name=func_map.name,
                                         sql=func.routine_definition,
                                         catalog_name=catalog_name,
                                         schema_name=schema_name,
                                         table_name=table_name,
                                         details=details)

        return row_filter

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

        tables = []
        for t in api_tables:

            cms = [self.__get_column_mask__(catalog_name=catalog, schema_name=schema, table_name=t.name, column_name=c.name, func_map=FunctionMap(
                                name=c.mask.function_name, columns=c.mask.using_column_names
                            ))
                            for c in t.columns
                            if c.mask
                        ]
            
            rlsfilter = None
            if t.row_filter:
                rlsfilter = self.__get_row_filter__(catalog_name=catalog, schema_name=schema, table_name=t.name, func_map=FunctionMap(
                                    name=t.row_filter.function_name, columns=t.row_filter.input_column_names
                                ))
            if rlsfilter:
                self.__workspace.catalog.row_filters.append(rlsfilter)
                self.__workspace.catalog.tables_with_rls.append(TableObject(catalog_name=catalog,
                                                                            schema_name=schema,
                                                                            table_name=t.name,
                                                                            columns=[c.name for c in t.columns]))
        
            self.__workspace.catalog.column_masks.extend(cms)
            if cms:
                self.__workspace.catalog.tables_with_masks.append(TableObject(catalog_name=catalog,
                                                                              schema_name=schema,
                                                                              table_name=t.name,
                                                                              columns=[c.name for c in t.columns]))

            t_ = Table(
                        name=t.name,
                        row_filter=rlsfilter,
                        column_masks=cms,
                        privileges=self.__get_privileges__(SecurableType.TABLE.value, t.full_name),
                    )
            tables.append(t_)

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