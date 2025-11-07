from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import List, Dict

import json
import re
import logging

from policyweaver.core.utility import Utils
from policyweaver.core.exception import PolicyWeaverError
from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.conf import Configuration
from policyweaver.core.api.fabric import FabricAPI
from policyweaver.core.api.microsoftgraph import MicrosoftGraphClient
from policyweaver.plugins.databricks.client import DatabricksPolicyWeaver
from policyweaver.plugins.snowflake.client import SnowflakePolicyWeaver
from policyweaver.models.fabric import (
    DataAccessPolicy,
    PolicyDecisionRule,
    PolicyEffectType,
    PolicyPermissionScope,
    PolicyAttributeType,
    PolicyMembers,
    EntraMember,
    FabricMemberObjectType,
    FabricPolicyAccessType,
    ColumnConstraint,
    Constraints,
    RowConstraint
)
from policyweaver.models.export import PolicyExport, RolePolicyExport, RolePolicy, PermissionObject
from policyweaver.models.config import SourceMap
from policyweaver.core.enum import (
    PolicyWeaverConnectorType,
    PermissionType,
    PermissionState,
    IamType
)

class WeaverAgent:
    """
    WeaverAgen class for applying policies to Microsoft Fabric.
    This class is responsible for synchronizing policies from a source (e.g., Databricks
    Unity Catalog) to Microsoft Fabric by creating or updating data access policies.
    It uses the Fabric API to manage data access policies and the Microsoft Graph API
    to resolve user identities.
    Example usage:
        config = SourceMap(...)
        weaver = Weaver(config)
        await weaver.apply(policy_export)
    """
    __FABRIC_POLICY_ROLE_SUFFIX = "PolicyWeaver"
    __FABRIC_DEFAULT_READER_ROLE = "DefaultReader"

    @property
    def FabricPolicyRoleSuffix(self) -> str:
        """
        Get the Fabric policy role suffix from the configuration.
        If the suffix is not set in the configuration, it defaults to "PolicyWeaver".
        Returns:
            str: The Fabric policy role suffix.
        """
        if self.config and self.config.fabric and self.config.fabric.fabric_role_suffix:
            return self.config.fabric.fabric_role_suffix
        else:
            return self.__FABRIC_POLICY_ROLE_SUFFIX
    
    @staticmethod
    async def run(config: SourceMap, source_snapshot_hndlr:callable = None, 
                  fabric_snaphot_hndlr:callable = None, unmapped_policy_hndlr:callable = None) -> None:
        """
        Run the Policy Weaver synchronization process.
        This method initializes the environment, sets up the service principal,
        and applies policies based on the provided configuration.
        Args:
            config (SourceMap): The configuration for the Policy Weaver, including service principal credentials and source
            type.
        """
        Configuration.configure_environment(config)
        logger = logging.getLogger("POLICY_WEAVER")
        logger.info("Policy Weaver Sync started...")

        ServicePrincipal.initialize(
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret
        )
    
        weaver = WeaverAgent(config)

        if source_snapshot_hndlr:
            weaver.set_source_snaphot_handler(source_snapshot_hndlr)
        
        if fabric_snaphot_hndlr:
            weaver.set_fabric_snapshot_handler(fabric_snaphot_hndlr)
        
        if unmapped_policy_hndlr:
            weaver.set_unmapped_policy_handler(unmapped_policy_hndlr)
        
        match config.type:
            case PolicyWeaverConnectorType.UNITY_CATALOG:
                src = DatabricksPolicyWeaver(config)
            case PolicyWeaverConnectorType.SNOWFLAKE:
                src = SnowflakePolicyWeaver(config)
            case _:
                pass
        
        logger.info(f"Running Policy Export for {config.type}: {config.source.name}...")
        policy_mapping = config.fabric.policy_mapping

        policy_export = src.map_policy(policy_mapping)
        
        if policy_export:
            weaver.source_snapshot_handler(policy_export)
            if policy_mapping == "role_based":
                await weaver.apply_role(policy_export)
            else:
                await weaver.apply(policy_export)
            logger.info("Policy Weaver Sync complete!")
        else:
            logger.info("No policies found to apply. Exiting...")

    def __init__(self, config: SourceMap) -> None:
        """
        Initialize the Weaver with the provided configuration.
        This method sets up the logger, Fabric API client, and Microsoft Graph client.
        Args:
            config (SourceMap): The configuration for the Policy Weaver, including service principal credentials and source type.
        """
        self.config = config
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.fabric_api = FabricAPI(config.fabric.workspace_id, self.config.type)
        self.graph_client = MicrosoftGraphClient()

        self._source_snapshot_handler = None
        self._fabric_snapshot_handler = None
        self._unmapped_policy_handler = None
        self.__graph_map = dict()
        self.used_role_names = []

    async def apply(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """

        if not self.config.fabric.tenant_id:
            self.config.fabric.tenant_id = ServicePrincipal.TenantId

        self.logger.info(f"Tenant ID: {self.config.fabric.tenant_id}...")
        self.logger.info(f"Workspace ID: {self.config.fabric.workspace_id}...")
        self.logger.info(f"Mirror ID: {self.config.fabric.mirror_id}...")
        self.logger.info(f"Mirror Name: {self.config.fabric.mirror_name}...")

        if not self.config.fabric.workspace_name:
            self.config.fabric.workspace_name = self.fabric_api.get_workspace_name()

        self.logger.info(f"Applying Fabric Policies to {self.config.fabric.workspace_name}...")
        self.__get_current_access_policy__()
        await self.__apply_policies__(policy_export)

    async def apply_role(self, policy_export: RolePolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """

        if not self.config.fabric.tenant_id:
            self.config.fabric.tenant_id = ServicePrincipal.TenantId

        self.logger.info(f"Tenant ID: {self.config.fabric.tenant_id}...")
        self.logger.info(f"Workspace ID: {self.config.fabric.workspace_id}...")
        self.logger.info(f"Mirror ID: {self.config.fabric.mirror_id}...")
        self.logger.info(f"Mirror Name: {self.config.fabric.mirror_name}...")

        if not self.config.fabric.workspace_name:
            self.config.fabric.workspace_name = self.fabric_api.get_workspace_name()

        self.logger.info(f"Applying Fabric Policies to {self.config.fabric.workspace_name}...")
        self.__get_current_access_policy__()
        await self.__apply_role_policies__(policy_export)

    async def __apply_role_policies__(self, policy_export: RolePolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric by creating or updating data access policies.
        This method builds data access policies based on the permissions in the policy export
        and applies them to the Fabric workspace.
        Args:
            policy_export (RolePolicyExport): The exported policies from the source, containing permissions and objects.
        """
        access_policies = []

        for policy in policy_export.policies:
            access_policy = await self.__build_data_access_role_policy__(
                policy, FabricPolicyAccessType.READ
            )
            if not access_policy:
                continue
            self.fabric_snapshot_handler(access_policy)
            access_policies.append(access_policy)

        inserted_policies = len(access_policies)
        updated_policies = 0
        deleted_policies = 0
        unmanaged_policies = 0

        # Append policies not managed by PolicyWeaver
        if self.current_fabric_policies:
            for p in self.current_fabric_policies:
                if not self.FabricPolicyRoleSuffix in p.name:
                    continue

                # Check if the policy already exists
                existing_policy = next((ap for ap in access_policies if ap.name.lower() == p.name.lower()), None)

                if existing_policy:
                    # Update existing policy
                    self.logger.debug(f"Updating Policy: {p.name}")
                    existing_policy.id = p.id
                    updated_policies += 1
                    inserted_policies -= 1
                else:
                    self.logger.debug(f"Removing Policy: {p.name}")

            xapply = [p for p in self.current_fabric_policies if not p.name.lower().endswith(self.FabricPolicyRoleSuffix.lower())]

            if xapply:
                self.logger.debug(f"Unmanaged Policies: {len(xapply)}")

                if self.config.fabric.delete_default_reader_role:
                    self.logger.debug("Deleting default reader role as configured...")
                    for p in xapply:
                        xapply = [p for p in xapply if not p.name.lower() == self.__FABRIC_DEFAULT_READER_ROLE.lower()]

                unmanaged_policies += len(xapply)
                access_policies.extend(xapply)
            
            for p in self.current_fabric_policies:
                if p.name not in [ap.name for ap in access_policies]:
                    deleted_policies += 1
        else:
            self.logger.debug("No current Fabric policies found.")

        self.logger.info(f"Policies Summary - Inserted: {inserted_policies}, Updated: {updated_policies}, Deleted: {deleted_policies}, Unmanaged: {unmanaged_policies}")

        if (inserted_policies + updated_policies + deleted_policies + unmanaged_policies) > 0:
            dap_request = {
                "value": [
                    p.model_dump(exclude_none=True, exclude_unset=True)
                    for p in access_policies
                ]
            }

            self.fabric_api.put_data_access_policy(
                self.config.fabric.mirror_id, json.dumps(dap_request)
            )

            self.logger.info(f"Total Data Access Polices Synced: {len(access_policies)}")
        else:
            self.logger.info("No Data Access Policies to sync...")

    async def __apply_policies__(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric by creating or updating data access policies.
        This method builds data access policies based on the permissions in the policy export
        and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """
        access_policies = []

        for policy in policy_export.policies:
            for permission in policy.permissions:
                if (
                    permission.name == PermissionType.SELECT
                    and permission.state == PermissionState.GRANT
                ):
                    access_policy = await self.__build_data_access_policy__(
                        policy, permission, FabricPolicyAccessType.READ
                    )
                    if not access_policy:
                        continue

                    self.fabric_snapshot_handler(access_policy)
                    access_policies.append(access_policy)

        inserted_policies = len(access_policies)
        updated_policies = 0
        deleted_policies = 0
        unmanaged_policies = 0

        # Append policies not managed by PolicyWeaver
        if self.current_fabric_policies:
            for p in self.current_fabric_policies:
                if not self.FabricPolicyRoleSuffix in p.name:
                    continue

                # Check if the policy already exists
                existing_policy = next((ap for ap in access_policies if ap.name.lower() == p.name.lower()), None)

                if existing_policy:
                    # Update existing policy
                    self.logger.debug(f"Updating Policy: {p.name}")
                    existing_policy.id = p.id
                    updated_policies += 1
                    inserted_policies -= 1
                else:
                    self.logger.debug(f"Removing Policy: {p.name}")

            xapply = [p for p in self.current_fabric_policies if not p.name.lower().endswith(self.FabricPolicyRoleSuffix.lower())]

            if xapply:
                self.logger.debug(f"Unmanaged Policies: {len(xapply)}")

                if self.config.fabric.delete_default_reader_role:
                    self.logger.debug("Deleting default reader role as configured...")
                    for p in xapply:
                        xapply = [p for p in xapply if not p.name.lower() == self.__FABRIC_DEFAULT_READER_ROLE.lower()]

                unmanaged_policies += len(xapply)
                access_policies.extend(xapply)
            
            for p in self.current_fabric_policies:
                if p.name not in [ap.name for ap in access_policies]:
                    deleted_policies += 1
        else:
            self.logger.debug("No current Fabric policies found.")

        self.logger.info(f"Policies Summary - Inserted: {inserted_policies}, Updated: {updated_policies}, Deleted: {deleted_policies}, Unmanaged: {unmanaged_policies}")

        if (inserted_policies + updated_policies + deleted_policies + unmanaged_policies) > 0:
            dap_request = {
                "value": [
                    p.model_dump(exclude_none=True, exclude_unset=True)
                    for p in access_policies
                ]
            }

            self.fabric_api.put_data_access_policy(
                self.config.fabric.mirror_id, json.dumps(dap_request)
            )

            self.logger.info(f"Total Data Access Polices Synced: {len(access_policies)}")
        else:
            self.logger.info("No Data Access Policies to sync...")

    def __get_current_access_policy__(self) -> None:
        """
        Retrieve the current data access policies from the Fabric Mirror.
        This method fetches the existing data access policies from the Fabric Mirror
        and stores them in the current_fabric_policies attribute.
        Raises:
            PolicyWeaverError: If Data Access Policies are not enabled on the Fabric Mirror.
            HTTPError: If there is an error retrieving the policies from the Fabric API.
        """
        try:
            result = self.fabric_api.list_data_access_policy(self.config.fabric.mirror_id)
            type_adapter = TypeAdapter(List[DataAccessPolicy])
            self.current_fabric_policies = type_adapter.validate_python(result["value"])
        except HTTPError as e:
            if e.response.status_code == 400:
                raise PolicyWeaverError("ERROR: Please ensure Data Access Policies are enabled on the Fabric Mirror.")
            else:
                raise e
            
    def __get_table_mapping__(self, catalog:str, schema:str, table:str) -> str:
        """
        Get the table mapping for the specified catalog, schema, and table.
        This method checks if the table is mapped in the configuration and returns
        the appropriate table path for the Fabric API.
        Args:
            catalog (str): The catalog name.
            schema (str): The schema name.
            table (str): The table name.
        Returns:
            str: The table path in the format "Tables/{schema}/{table}" if mapped, otherwise None.
        """
        if not table:
            if schema:
                return f"Tables/{schema}"
            return "*"

        if self.config.mapped_items:
            matched_tbl = next(
                (tbl for tbl in self.config.mapped_items
                    if tbl.catalog == catalog and tbl.catalog_schema == schema and tbl.table == table),
                None
            )
        else:
            matched_tbl = None

        table_nm = table if not matched_tbl else matched_tbl.mirror_table_name
        table_path = f"Tables/{schema}/{table_nm}"         

        return table_path

    async def __get_graph_map__(self, policy_export: PolicyExport) -> Dict[str, str]:
        """
        Retrieve a mapping of user and service principal IDs from the Microsoft Graph API.
        This method iterates through the permissions in the policy export and retrieves
        the corresponding user or service principal IDs based on their lookup IDs.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        Returns:
            Dict[str, str]: A dictionary mapping lookup IDs to user or service principal IDs.
        """
        graph_map = dict()

        for policy in policy_export.policies:
            for permission in policy.permissions:
                for object in permission.objects:
                    if object.lookup_id not in graph_map:
                        match object.type:
                            case IamType.USER:
                                if not object.id:
                                    graph_map[object.lookup_id] = await self.graph_client.get_user_by_email(object.email)
                                else:
                                    graph_map[object.lookup_id] = object.id
                            case IamType.SERVICE_PRINCIPAL:
                                if not object.id:
                                    graph_map[object.lookup_id] = await self.graph_client.get_service_principal_by_id(object.app_id)
                                else:
                                    graph_map[object.lookup_id] = object.id
                            
        return graph_map
    
    async def __get_graph_map_role__(self, policy_export: RolePolicyExport) -> Dict[str, str]:
        """
        Retrieve a mapping of user and service principal IDs from the Microsoft Graph API.
        This method iterates through the permissions in the policy export and retrieves
        the corresponding user or service principal IDs based on their lookup IDs.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        Returns:
            Dict[str, str]: A dictionary mapping lookup IDs to user or service principal IDs.
        """
        graph_map = dict()

        for policy in policy_export.policies:
            for object in policy.permissionobjects:
                if object.lookup_id not in graph_map:
                    match object.type:
                        case IamType.USER:
                            if not object.id:
                                graph_map[object.lookup_id] = await self.graph_client.get_user_by_email(object.email.lower())
                            else:
                                graph_map[object.lookup_id] = object.id
                        case IamType.SERVICE_PRINCIPAL:
                            if not object.id:
                                graph_map[object.lookup_id] = await self.graph_client.get_service_principal_by_id(object.app_id)
                            else:
                                graph_map[object.lookup_id] = object.id
                            
        return graph_map

    def __get_role_name__(self, policy:PolicyExport) -> str:
        """
        Generate a role name based on the policy's catalog, schema, and table.
        This method constructs a role name by concatenating the catalog, schema, and table
        information, ensuring it adheres to the naming conventions for Fabric policies.
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
        Returns:
            str: The generated role name in the format "xxPOLICYWEAVERxx<CATALOG><SCHEMA><TABLE>".
        """
        if policy.catalog_schema:
            role_description = f"{policy.catalog_schema.replace(' ', '')} {'' if not policy.table else policy.table.replace(' ', '')}"
        else:
            role_description = policy.catalog.replace(" ", "")


        role_name = f"{role_description.title()}{self.config.fabric.fabric_role_suffix}"
        # replace all signs
        role_name = role_name.replace("-", "").replace("_", "").replace(" ", "").replace(".", "")
        role_name = role_name.replace("@", "").replace("'", "").replace("`", "").replace("!", "")
        # replace all non alphanumeric signs
        role_name = re.sub(r'\W+', '', role_name)

        return re.sub(r'[^a-zA-Z0-9]', '', role_name)

    async def __build_data_access_policy__(self, policy:PolicyExport, permission:PermissionType, access_policy_type:FabricPolicyAccessType) -> DataAccessPolicy:
        """
        Build a Data Access Policy based on the provided policy and permission.
        This method constructs a Data Access Policy object that includes the role name,
        decision rules, and members based on the policy's catalog, schema, table, and permissions
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
            permission (PermissionType): The permission type to be applied (e.g., SELECT).
            access_policy_type (FabricPolicyAccessType): The type of access policy (e.g., READ).
        Returns:
            DataAccessPolicy: The constructed Data Access Policy object.
        """
        role_name = self.__get_role_name__(policy)

        table_path = self.__get_table_mapping__(
            policy.catalog, policy.catalog_schema, policy.table
        )
        if table_path and table_path != "*":
            table_path = f"/{table_path}"

        dap = DataAccessPolicy(
            name=role_name,
            decision_rules=[
                PolicyDecisionRule(
                    effect=PolicyEffectType.PERMIT,
                    permission=[
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.PATH,
                            attribute_value_included_in=[
                                table_path
                            ],
                        ),
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.ACTION,
                            attribute_value_included_in=[access_policy_type],
                        ),
                    ],
                )
            ],
            members=PolicyMembers(
                entra_members=[]
            ),
        )

        for o in permission.objects:
            object_id = await self.__lookup_entra_object_id__(o)
            if object_id:
                if o.type == IamType.GROUP:
                    object_type = FabricMemberObjectType.GROUP
                else:
                    object_type=FabricMemberObjectType.USER if o.type == IamType.USER else FabricMemberObjectType.SERVICE_PRINCIPAL
                
                dap.members.entra_members.append(
                    EntraMember(
                        object_id=object_id,
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=object_type
                    ))
            else:
                self.logger.warning(f"POLICY WEAVER - {o.lookup_id} not found in Microsoft Graph. Skipping...")
                if self._unmapped_policy_handler:
                    self._unmapped_policy_handler(o.lookup_id, policy)
                continue

        if dap.members.entra_members == []:
            self.logger.warning(f"POLICY WEAVER - No valid members found for policy {policy.name}. Skipping...")
            return None
        
        self.logger.debug(f"POLICY WEAVER - Data Access Policy - {dap.name}: {dap.model_dump_json(indent=4)}")
        
        return dap
    
    async def __lookup_entra_object_id__(self, object:PermissionObject) -> str:
            """
            Looks up the Entra object ID for a given policy object.
            Args:
                policy_object (PermissionObject): The policy object to look up.
            Returns:
                Optional[str]: The Entra object ID if found, otherwise None.
            """
            object_id = object.entra_object_id
            if object_id:
                return object_id
            
            if object.lookup_id in self.__graph_map:
                return self.__graph_map[object.lookup_id]

            if object.type not in [IamType.USER, IamType.SERVICE_PRINCIPAL]:
                return None

            match object.type:
                case IamType.USER:
                    if not object.id:
                        self.__graph_map[object.lookup_id] = await self.graph_client.get_user_by_email(object.email)
                    else:
                        self.__graph_map[object.lookup_id] = object.id
                case IamType.SERVICE_PRINCIPAL:
                    if not object.id:
                        self.__graph_map[object.lookup_id] = await self.graph_client.get_service_principal_by_id(object.app_id)
                    else:
                        self.__graph_map[object.lookup_id] = object.id

            return self.__graph_map[object.lookup_id]

    @staticmethod
    def __generate_rls_value__(schema_name:str, table_name:str, filter_condition:str) -> str:

        start = f"SELECT * FROM {schema_name}.{table_name}"
        if filter_condition == "true":
            return False
        else:
            return f"{start} WHERE {filter_condition}"


    async def __build_data_access_role_policy__(self, policy:RolePolicy, access_policy_type:FabricPolicyAccessType) -> DataAccessPolicy:
        """
        Build a Data Access Policy based on the provided policy and permission.
        This method constructs a Data Access Policy object that includes the role name,
        decision rules, and members based on the policy's catalog, schema, table, and permissions
        Args:
            policy (PolicyExport): The policy object containing catalog, schema, and table information.
            permission (PermissionType): The permission type to be applied (e.g., SELECT).
            access_policy_type (FabricPolicyAccessType): The type of access policy (e.g., READ).
        Returns:
            DataAccessPolicy: The constructed Data Access Policy object.
        """

        len_suffix = len(self.config.fabric.fabric_role_suffix)

        role_name = f"{policy.name}{self.config.fabric.fabric_role_suffix}"
        # replace all signs
        role_name = role_name.replace("-", "").replace("_", "").replace(" ", "").replace(".", "")
        role_name = role_name.replace("@", "").replace("'", "").replace("`", "").replace("!", "")
        # replace all non alphanumeric signs
        role_name = re.sub(r'\W+', '', role_name)

        if role_name[0] in [str(i) for i in range(10)]:
            role_name = f"ID{role_name}"

        if role_name in self.used_role_names:
            suffix = 1
            new_role_name = role_name[:-len_suffix] + str(suffix) + self.config.fabric.fabric_role_suffix
            while new_role_name in self.used_role_names:
                suffix += 1
                new_role_name = role_name[:-len_suffix] + str(suffix) + self.config.fabric.fabric_role_suffix
            role_name = new_role_name

        self.used_role_names.append(role_name)

        table_paths = []
        for permission_scope in policy.permissionscopes:
            if (permission_scope.name == PermissionType.SELECT and permission_scope.state == PermissionState.GRANT):
                table_path = self.__get_table_mapping__(permission_scope.catalog, permission_scope.catalog_schema, permission_scope.table)
                if table_path:
                    if table_path != "*":
                        table_path = f"/{table_path}"
                    table_paths.append(table_path)
        
        columnconstraints = []
        rowconstraints = []
        tables_with_all_columns_denied = []
        tables_with_all_rows_denied = []

        if policy.columnconstraints and self.config.constraints and self.config.constraints.columns and self.config.constraints.columns.columnlevelsecurity:
            for cc in policy.columnconstraints:
                if PermissionType.SELECT in cc.column_actions and cc.column_effect == PermissionState.GRANT:
                    table_path = self.__get_table_mapping__(cc.catalog_name, cc.schema_name, cc.table_name)
                    if table_path and table_path != "*":
                        table_path = f"/{table_path}"
                    column_names = cc.column_names
                    if not column_names:
                        tables_with_all_columns_denied.append(table_path)
                        continue

                    columnconstraints.append(ColumnConstraint(table_path=table_path,
                                                            column_names=column_names,
                                                            column_effect=PolicyEffectType.PERMIT,
                                                            column_action=[FabricPolicyAccessType.READ]))

        if policy.rowconstraints and self.config.constraints and self.config.constraints.rows and self.config.constraints.rows.rowlevelsecurity:
            for rc in policy.rowconstraints:
                table_path = self.__get_table_mapping__(rc.catalog_name, rc.schema_name, rc.table_name)
                if table_path and table_path != "*":
                    table_path = f"/{table_path}"
                if rc.filter_condition == "DENYALL":
                    tables_with_all_rows_denied.append(table_path)
                    continue
                value = self.__generate_rls_value__(
                    schema_name=rc.schema_name,
                    table_name=rc.table_name,
                    filter_condition=rc.filter_condition
                )
                if not value:
                    continue

                rowconstraints.append(RowConstraint(
                                            table_path=table_path,
                                            value=value))


        # Remove all tablepaths that have all columns denied
        table_paths = [tp for tp in table_paths if tp not in tables_with_all_columns_denied]
        table_paths = [tp for tp in table_paths if tp not in tables_with_all_rows_denied]
                                                        
        if not table_paths:
            self.logger.warning(f"POLICY WEAVER - No valid table mappings found for policy {policy.name}. Skipping...")
            return None

        permission_scopes = [
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.PATH,
                            attribute_value_included_in=table_paths,
                        ),
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.ACTION,
                            attribute_value_included_in=[access_policy_type],
                        ),
                    ]
   
        pdr = PolicyDecisionRule(
                    effect=PolicyEffectType.PERMIT,
                    permission=permission_scopes,
                )
        
        if columnconstraints or rowconstraints:
            constraints = Constraints()
            if columnconstraints:
                constraints.columns = columnconstraints
            if rowconstraints:
                constraints.rows = rowconstraints
            pdr.constraints = constraints

        dap = DataAccessPolicy(
            name=role_name,
            decision_rules=[pdr],
            members=PolicyMembers(
                entra_members=[]
            ),
        )

        for o in policy.permissionobjects:
            object_id = await self.__lookup_entra_object_id__(o)
            if object_id:
                if o.type == IamType.GROUP:
                    object_type = FabricMemberObjectType.GROUP
                else:
                    object_type=FabricMemberObjectType.USER if o.type == IamType.USER else FabricMemberObjectType.SERVICE_PRINCIPAL
                
                dap.members.entra_members.append(
                    EntraMember(
                        object_id=object_id,
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=object_type
                    ))
            else:
                self.logger.warning(f"POLICY WEAVER - {o.lookup_id} not found in Microsoft Graph. Skipping...")
                if self._unmapped_policy_handler:
                    self._unmapped_policy_handler(o.lookup_id, policy)
                continue
        
        if dap.members.entra_members == []:
            self.logger.warning(f"POLICY WEAVER - No valid members found for policy {policy.name}. Skipping...")
            return None

        self.logger.debug(f"POLICY WEAVER - Data Access Policy - {dap.name}: {dap.model_dump_json(indent=4)}")
        
        return dap
        
    def source_snapshot_handler(self, policy_export:PolicyExport) -> None:
        """
        Handle the source snapshot after it is generated.
        This method is called to process the source snapshot, allowing for external archival,
        logging or further processing of the snapshot.
        Args:
            policy_export (PolicyExport): The PolicyExport object containing the source snapshot data.
        """
        if self._source_snapshot_handler:
            if policy_export:
                snapshot = policy_export.model_dump_json(exclude_none=True, exclude_unset=True, indent=4)
                self._source_snapshot_handler(snapshot)
            else:
                self._source_snapshot_handler(None)
        else:
            self.logger.debug("No source snapshot handler set. Skipping snapshot processing.")
    
    def fabric_snapshot_handler(self, access_policy:DataAccessPolicy) -> None:
        """
        Handle the fabric snapshot after it is generated.
        This method is called to process the fabric snapshot, allowing for external archival,
        logging or further processing of the snapshot.
        Args:
            access_policy (DataAccessPolicy): The DataAccessPolicy object containing the fabric snapshot data.
        """
        if self._fabric_snapshot_handler:
            if access_policy:
                snapshot = access_policy.model_dump_json(exclude_none=True, exclude_unset=True, indent=4)
                self._fabric_snapshot_handler(snapshot)
            else:
                self._fabric_snapshot_handler(None)
        else:
            self.logger.debug("No fabric snapshot handler set. Skipping snapshot processing.")
    
    def unmapped_policy_handler(self, object_id:str, policy:PolicyExport) -> None:
        """
        Handle the unmapped policies after they are identified.
        This method is called to process the unmapped policies, allowing for external archival,
        logging or further processing of the unmapped policies.
        Args:
            json_unmapped_policies (str): The JSON string representation of the unmapped policies.
        """
        if self._unmapped_policy_handler:
            if object_id and policy:
                unmapped_policy = {
                    "unmapped_object_id": object_id,
                    "policy": policy.model_dump_json(exclude_none=True, exclude_unset=True, indent=4)
                }
                self._unmapped_policy_handler(unmapped_policy)
            else:
                self._unmapped_policy_handler(None)
        else:
            self.logger.debug("No unmapped policy handler set. Skipping unmapped policy processing.")
        
    def set_source_snaphot_handler(self, handler):
        """
        Set the source snapshot handler for the core class.
        This handler is called after the snapshot is generated to allow for
        external archival, logging or further processing of the snapshot.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing snapshots.
            The handler should accept a single dictionary argument containing the snapshot data.
            Example: def handler(snapshot: Dict): ...
        """
        self._source_snapshot_handler = handler

    def set_fabric_snapshot_handler(self, handler):
        """
        Set the fabric snapshot handler for the core class.
        This handler is called after the fabric snapshot is generated to allow for
        external archival, logging or further processing of the snapshot.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing fabric snapshots.
            The handler should accept a single dictionary argument containing the snapshot data.
            Example: def handler(snapshot: Dict): ...
        """
        self._fabric_snapshot_handler = handler
    
    def set_unmapped_policy_handler(self, handler):
        """
        Set the unmapped policy handler for the core class.
        This handler is called after unmapped policies are identified to allow for
        external archival, logging or further processing of the unmapped policies.
        This is useful for integrating with external systems or for custom logging.
        Args:
            handler: The handler to set for processing unmapped policies.
            The handler should accept a single dictionary argument containing the unmapped policy data.
            Example: def handler(unmapped_policy: Dict): ...
        """
        self._unmapped_policy_handler = handler