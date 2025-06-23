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
)
from policyweaver.models.export import PolicyExport
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
    fabric_policy_role_prefix = "xxPOLICYWEAVERxx"

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
            case _:
                pass
        
        logger.info(f"Running Policy Export for {config.type}: {config.source.name}...")
        policy_export = src.map_policy()
        
        weaver.source_snapshot_handler(policy_export)

        await weaver.apply(policy_export)
        logger.info("Policy Weaver Sync complete!")

    def __init__(self, config: SourceMap) -> None:
        """
        Initialize the Weaver with the provided configuration.
        This method sets up the logger, Fabric API client, and Microsoft Graph client.
        Args:
            config (SourceMap): The configuration for the Policy Weaver, including service principal credentials and source type.
        """
        self.config = config
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.fabric_api = FabricAPI(config.fabric.workspace_id)
        self.graph_client = MicrosoftGraphClient()

        self._source_snapshot_handler = None
        self._fabric_snapshot_handler = None
        self._unmapped_policy_handler = None

    async def apply(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """
        self.__graph_map = await self.__get_graph_map__(policy_export)

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
        self.__apply_policies__(policy_export)

    def __apply_policies__(self, policy_export: PolicyExport) -> None:
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
                    access_policy = self.__build_data_access_policy__(
                        policy, permission, FabricPolicyAccessType.READ
                    )

                    self.fabric_snapshot_handler(access_policy)
                    access_policies.append(access_policy)

        inserted_policies = 0
        updated_policies = 0
        deleted_policies = 0
        unmanaged_policies = 0

        # Append policies not managed by PolicyWeaver
        if self.current_fabric_policies:
            for p in self.current_fabric_policies:
                if not p.name.startswith(self.fabric_policy_role_prefix):
                    continue

                # Check if the policy already exists
                existing_policy = next((ap for ap in access_policies if ap.name == p.name), None)

                if existing_policy:
                    # Update existing policy
                    self.logger.debug(f"Updating Policy: {p.name}")
                    existing_policy.id = p.id
                    updated_policies += 1
                else:
                    # Add new policy
                    self.logger.debug(f"Inserting Policy: {p.name}")
                    access_policies.append(p)
                    inserted_policies += 1                   

            xapply = [p for p in self.current_fabric_policies if not p.name.startswith(self.fabric_policy_role_prefix)]

            if xapply:
                self.logger.debug(f"Unmanaged Policies: {len(xapply)}")
                unmanaged_policies += len(xapply)
                access_policies.extend(xapply)
            
            for p in self.current_fabric_policies:
                if p.name not in [ap.name for ap in access_policies]:
                    deleted_policies += 1
        else:
            self.logger.debug("No current Fabric policies found.")
            inserted_policies = len(access_policies)

        self.logger.info(f"Policies Summary - Inserted: {inserted_policies}, Updated: {updated_policies}, Deleted: {deleted_policies}, Unmanaged: {unmanaged_policies}")

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
            return None

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
            role_description = f"{policy.catalog_schema.upper()}x{'' if not policy.table else policy.table.upper()}"
        else:
            role_description = policy.catalog.upper()

        return re.sub(r'[^a-zA-Z0-9]', '', f"{self.fabric_policy_role_prefix}{role_description}")
    
    def __build_data_access_policy__(self, policy:PolicyExport, permission:PermissionType, access_policy_type:FabricPolicyAccessType) -> DataAccessPolicy:
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

        dap = DataAccessPolicy(
            name=role_name,
            decision_rules=[
                PolicyDecisionRule(
                    effect=PolicyEffectType.PERMIT,
                    permission=[
                        PolicyPermissionScope(
                            attribute_name=PolicyAttributeType.PATH,
                            attribute_value_included_in=[
                                f"/{table_path}" if table_path else "*"
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
            if o.lookup_id in self.__graph_map:
                dap.members.entra_members.append(
                    EntraMember(
                        object_id=self.__graph_map[o.lookup_id],
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=FabricMemberObjectType.USER if o.type == IamType.USER else FabricMemberObjectType.SERVICE_PRINCIPAL,
                    ))
            else:
                self.logger.warning(f"POLICY WEAVER - {o.lookup_id} not found in Microsoft Graph. Skipping...")
                self._unmapped_policy_handler(o.lookup_id, policy)
                continue

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