from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import List
from policyweaver.support.fabricapiclient import FabricAPI
from policyweaver.support.microsoftgraphclient import MicrosoftGraphClient
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
)

import json


class PolicyWeaverError(Exception):
    pass


class Weaver:
    fabric_policy_role_prefix = "xxPOLICYWEAVERxx"

    def __init__(self, config: SourceMap):
        self.config = config

        self.fabric_api = FabricAPI(
            workspace_id=config.fabric.workspace_id, api_token=config.fabric.api_token
        )
        self.graph_client = MicrosoftGraphClient(
            tenant=config.service_principal.tenant_id,
            id=config.service_principal.client_id,
            secret=config.service_principal.client_secret,
        )

    async def run(self, policy_export: PolicyExport):
        self.user_map = await self.__get_user_map__(policy_export)

        if not self.config.fabric.lakehouse_id:
            self.config.fabric.lakehouse_id = self.fabric_api.get_lakehouse_id(
                self.config.fabric.lakehouse_name
            )

        if not self.config.fabric.workspace_name:
            self.config.fabric.workspace_name = self.fabric_api.get_workspace_name()

        self.__get_current_access_policy__()
        self.__apply_policies__(policy_export)

    def __apply_policies__(self, policy_export: PolicyExport):
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

        self.fabric_api.put_data_access_policy(
            self.config.fabric.lakehouse_id, json.dumps(dap_request)
        )

        print(f"Access Polices Updated: {len(access_policies)}")

    def __get_current_access_policy__(self):
        try:
            result = self.fabric_api.list_data_access_policy(self.config.fabric.lakehouse_id)
            type_adapter = TypeAdapter(List[DataAccessPolicy])
            self.current_fabric_policies = type_adapter.validate_python(result["value"])
        except HTTPError as e:
            if e.response.status_code == 400:
                PolicyWeaverError("ERROR: Please ensure Data Access Policies are enabled on the lakehouse.")
            else:
                raise e
            
    def __get_table_mapping__(self, catalog, schema, table) -> tuple():
        if not table:
            return None

        matched_tbls = [
            tbl
            for tbl in self.config.mapped_items
            if tbl.catalog == catalog
            and tbl.catalog_schema == schema
            and tbl.table == table
        ]

        if matched_tbls:
            table_path = f"Tables/{matched_tbls[0].lakehouse_table_name}"
        else:
            table_path = f"Tables/{table}"

        return table_path

    async def __get_user_map__(self, policy_export: PolicyExport):
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

        return f"xxPOLICYWEAVERxx{role_description}"
    
    def __build_data_access_policy__(
        self, policy, permission, access_policy_type
    ) -> DataAccessPolicy:

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
                        tenant_id=self.config.service_principal.tenant_id,
                        object_type=FabricMemberObjectType.USER,
                    )
                    for o in permission.objects
                    if o.type == IamType.USER
                ]
            ),
        )

        return dap
