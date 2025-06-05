from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import List, Dict
import json
import re
import logging

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
    fabric_policy_role_prefix = "xxPOLICYWEAVERxx"

    @staticmethod
    async def run(config: SourceMap) -> None:
        Configuration.configure_environment(config)
        logger = logging.getLogger(config.application_name)

        service_principal = ServicePrincipal(
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret
        )
    
        logger.info("Policy Weaver Sync started...")
        match config.type:
            case PolicyWeaverConnectorType.UNITY_CATALOG:
                src = DatabricksPolicyWeaver(config, service_principal)
            case _:
                pass
        
        logger.info(f"Running Policy Export for {config.type}: {config.source.name}...")
        policy_export = src.map_policy()
        
        #self.logger.debug(policy_export.model_dump_json(indent=4))

        weaver = Weaver(config, service_principal)
        await weaver.apply(policy_export)
        logger.info("Policy Weaver Sync complete!")

    def __init__(self, config: SourceMap, service_principal: ServicePrincipal) -> None:
        self.config = config
        self.logger = logging.getLogger(config.application_name)
        self.service_principal = service_principal
        self.fabric_api = FabricAPI(config.fabric.workspace_id, service_principal)
        self.graph_client = MicrosoftGraphClient(service_principal)

    async def apply(self, policy_export: PolicyExport) -> None:
        self.user_map = await self.__get_user_map__(policy_export)

        if not self.config.fabric.tenant_id:
            self.config.fabric.tenant_id = self.service_principal.tenant_id

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

        #self.logger.debug(json.dumps(dap_request))

        self.fabric_api.put_data_access_policy(
            self.config.fabric.mirror_id, json.dumps(dap_request)
        )

        self.logger.info(f"Access Polices Updated: {len(access_policies)}")

    def __get_current_access_policy__(self) -> None:
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
        if policy.catalog_schema:
            role_description = f"{policy.catalog_schema.upper()}x{'' if not policy.table else policy.table.upper()}"
        else:
            role_description = policy.catalog.upper()

        return re.sub(r'[^a-zA-Z0-9]', '', f"xxPOLICYWEAVERxx{role_description}")
    
    def __build_data_access_policy__(self, policy, permission, access_policy_type) -> DataAccessPolicy:
        
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
                                table_path if table_path else "*"
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
                        object_id=self.user_map[o.id],
                        tenant_id=self.config.fabric.tenant_id,
                        object_type=FabricMemberObjectType.USER,
                    )
                    for o in permission.objects
                    if o.type == IamType.USER
                ]
            ),
        )

        return dap