from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import List, Dict

import json
import re
import logging

from policyweaver.models.common import Utils
from policyweaver.auth import ServicePrincipal
from policyweaver.conf import Configuration
from policyweaver.support.fabricapiclient import FabricAPI
from policyweaver.support.microsoftgraphclient import MicrosoftGraphClient
from policyweaver.sources.databricksclient import DatabricksPolicyWeaver
from policyweaver.models.fabricmodel import (
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
from policyweaver.models.common import (
    PolicyExport,
    PermissionType,
    PermissionState,
    IamType,
    SourceMap,
    PolicyWeaverError,
    PolicyWeaverConnectorType,
)

class Weaver:
    """
    Weaver class for applying policies to Microsoft Fabric.
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
    async def run(config: SourceMap) -> None:
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

        ServicePrincipal.initialize(
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret
        )
    
        logger.info("Policy Weaver Sync started...")
        match config.type:
            case PolicyWeaverConnectorType.UNITY_CATALOG:
                src = DatabricksPolicyWeaver(config)
            case _:
                pass
        
        logger.info(f"Running Policy Export for {config.type}: {config.source.name}...")
        policy_export = src.map_policy()
        
        #self.logger.debug(policy_export.model_dump_json(indent=4))

        weaver = Weaver(config)
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

    async def apply(self, policy_export: PolicyExport) -> None:
        """
        Apply the policies to Microsoft Fabric based on the provided policy export.
        This method retrieves the current access policies, builds new data access policies
        based on the policy export, and applies them to the Fabric workspace.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        """
        self.user_map = await self.__get_user_map__(policy_export)

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

                    if len(access_policy.members.entra_members) > 0:
                        access_policies.append(access_policy)

        # Append policies not managed by PolicyWeaver
        if self.current_fabric_policies:
            xapply = [p for p in self.current_fabric_policies if not p.name.startswith(self.fabric_policy_role_prefix)]
            access_policies.extend(xapply)

        dap_request = {
            "value": [
                p.model_dump(exclude_none=True, exclude_unset=True)
                for p in access_policies
            ]
        }

        self.logger.debug(json.dumps(dap_request))

        self.fabric_api.put_data_access_policy(
            self.config.fabric.mirror_id, json.dumps(dap_request)
        )

        self.logger.info(f"Access Polices Updated: {len(access_policies)}")

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
            
    def __get_table_mapping__(self, catalog, schema, table) -> str:
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

    async def __get_user_map__(self, policy_export: PolicyExport) -> Dict[str, str]:
        """
        Get a mapping of user IDs to their corresponding Entra object IDs.
        This method iterates through the policies in the policy export and resolves
        user identities using the Microsoft Graph API.
        Args:
            policy_export (PolicyExport): The exported policies from the source, containing permissions and objects.
        Returns:
            Dict[str, str]: A dictionary mapping user IDs (emails) to their corresponding Entra object IDs.
        """
        user_map = dict()

        for policy in policy_export.policies:
            for permission in policy.permissions:
                for object in permission.objects:
                    if object.type == "USER" and object.id not in user_map:
                        user_map[
                            object.id
                        ] = await self.graph_client.lookup_user_id_by_email(object.id)

        return user_map

    def __get_role_name__(self, policy) -> str:
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

        return re.sub(r'[^a-zA-Z0-9]', '', f"xxPOLICYWEAVERxx{role_description}")
    
    def __build_data_access_policy__(self, policy, permission, access_policy_type) -> DataAccessPolicy:
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
                entra_members=[
                    EntraMember(
                        object_id=self.user_map[o.id] if Utils.is_email(o.id) else o.id,
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=FabricMemberObjectType.USER if Utils.is_email(o.id) else FabricMemberObjectType.SERVICE_PRINCIPAL,
                    )
                    for o in permission.objects
                    if o.type == IamType.USER
                ]
            ),
        )

        self.logger.debug(f"POLICY WEAVER - Data Access Policy - {dap.name}: {dap.model_dump_json(indent=4)}")
        
        return dap