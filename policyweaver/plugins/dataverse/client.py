import json
import os
from typing import List, Dict, Tuple

from pydantic.json import pydantic_encoder

from policyweaver.models.export import (
    PolicyExport, Policy, Permission, PermissionObject,
    RolePolicyExport, RolePolicy, PermissionScope,
    ColumnConstraint, RowConstraint
)
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap, DataverseEnvironment, DataverseTablePermission,
    DataverseUser, DataverseTeam, DataverseFieldSecurityProfile
)
from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType
)
from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.dataverse.api import DataverseAPIClient


class DataversePolicyWeaver(PolicyWeaverCore):
    """
    Dataverse Policy Weaver for Microsoft Dynamics 365 / Dataverse.
    This class extends the PolicyWeaverCore to implement the mapping of policies
    from Dataverse security model to the Policy Weaver framework.

    Dataverse security model includes:
    - Security Roles: Table-level CRUD privileges assigned to users/teams.
    - Field-Level Security: Column-level read restrictions via profiles.
    - Teams: Group users together, can have AAD-backed groups with Entra object IDs.
    """

    def __init__(self, config: DataverseSourceMap) -> None:
        super().__init__(PolicyWeaverConnectorType.DATAVERSE, config)
        self.config = config

        os.environ["DATAVERSE_ENVIRONMENT_URL"] = config.dataverse.environment_url

        self.api_client = DataverseAPIClient()
        self.environment: DataverseEnvironment = None

    def map_policy(self, policy_mapping: str = "table_based") -> PolicyExport | RolePolicyExport:
        """
        Map Dataverse security policies to the common PolicyExport format.
        Args:
            policy_mapping (str): The policy mapping mode ('table_based' or 'role_based').
        Returns:
            PolicyExport or RolePolicyExport: The mapped policies.
        """
        self.logger.info(f"Dataverse Policy Export for {self.config.source.name}...")

        self.environment = self.api_client.get_environment_security_map(self.config.source)

        if not self.environment.table_permissions:
            self.logger.warning("No table-level read permissions found in Dataverse environment.")
            return None

        if policy_mapping == "role_based":
            return self.__build_role_based_export__()
        else:
            return self.__build_table_based_export__()

    def __build_table_based_export__(self) -> PolicyExport:
        """
        Build a table-based PolicyExport.
        Groups permissions by table, where each table policy has a list of
        users/teams who can read it.
        """
        # Group permissions by table
        table_map: Dict[str, List[DataverseTablePermission]] = {}
        for perm in self.environment.table_permissions:
            table_map.setdefault(perm.table_name, []).append(perm)

        policies = []
        catalog_name = self.config.source.name
        schema_name = self.__get_schema_name__()

        for table_name, perms in table_map.items():
            permission_objects = self.__build_permission_objects__(perms)

            if not permission_objects:
                continue

            policy = Policy(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                permissions=[
                    Permission(
                        name=PermissionType.SELECT,
                        state=PermissionState.GRANT,
                        objects=permission_objects,
                    )
                ],
            )
            policies.append(policy)

        if not policies:
            self.logger.warning("No policies generated from Dataverse permissions.")
            return None

        export = PolicyExport(
            source=self.config.source,
            type=PolicyWeaverConnectorType.DATAVERSE,
            policies=policies,
        )

        self.logger.info(f"Generated {len(policies)} table-based policies from Dataverse.")
        return export

    def __build_role_based_export__(self) -> RolePolicyExport:
        """
        Build a role-based RolePolicyExport.
        Groups permissions by security role, where each role policy contains:
        - The principals (users/teams) assigned to that role
        - The table-level permission scopes (read)
        - Column constraints from field-level security
        """
        # Build role -> {principals, tables} mapping
        role_map: Dict[str, Dict] = {}
        catalog_name = self.config.source.name
        schema_name = self.__get_schema_name__()

        for perm in self.environment.table_permissions:
            role_name = perm.role_name or "UnknownRole"
            if role_name not in role_map:
                role_map[role_name] = {
                    "principals": set(),
                    "tables": set(),
                    "perms": [],
                }
            role_map[role_name]["principals"].add(
                (perm.principal_id, perm.principal_type)
            )
            role_map[role_name]["tables"].add(perm.table_name)
            role_map[role_name]["perms"].append(perm)

        policies = []
        for role_name, data in role_map.items():
            permission_objects = []
            for principal_id, principal_type in data["principals"]:
                po = self.__resolve_permission_object__(principal_id, principal_type)
                if po:
                    permission_objects.append(po)

            if not permission_objects:
                continue

            permission_scopes = []
            for table_name in data["tables"]:
                permission_scopes.append(
                    PermissionScope(
                        catalog=catalog_name,
                        catalog_schema=schema_name,
                        table=table_name,
                        name=PermissionType.SELECT,
                        state=PermissionState.GRANT,
                    )
                )

            # Get column constraints from field-level security for the principals in this role
            column_constraints = self.__get_column_constraints_for_principals__(
                data["principals"], data["tables"], catalog_name, schema_name
            )

            role_policy = RolePolicy(
                name=role_name,
                permissionobjects=permission_objects,
                permissionscopes=permission_scopes,
                columnconstraints=column_constraints if column_constraints else None,
                rowconstraints=None,
            )
            policies.append(role_policy)

        if not policies:
            self.logger.warning("No role-based policies generated from Dataverse permissions.")
            return None

        export = RolePolicyExport(
            source=self.config.source,
            type=PolicyWeaverConnectorType.DATAVERSE,
            policies=policies,
        )

        self.logger.info(f"Generated {len(policies)} role-based policies from Dataverse.")
        return export

    def __get_schema_name__(self) -> str:
        """Get the schema name from config, defaulting to 'dbo'."""
        if self.config.source.schemas and len(self.config.source.schemas) > 0:
            return self.config.source.schemas[0].name
        return "dbo"

    def __build_permission_objects__(
        self, perms: List[DataverseTablePermission]
    ) -> List[PermissionObject]:
        """
        Build deduplicated PermissionObject list from table permissions.
        Resolves users and teams to their Entra identities.
        """
        seen = set()
        objects = []

        for perm in perms:
            if perm.principal_id in seen:
                continue
            seen.add(perm.principal_id)

            po = self.__resolve_permission_object__(perm.principal_id, perm.principal_type)
            if po:
                objects.append(po)

        return objects

    def __resolve_permission_object__(
        self, principal_id: str, principal_type: IamType
    ) -> PermissionObject:
        """
        Resolve a Dataverse principal to a PermissionObject with Entra identity.
        """
        if principal_type == IamType.USER:
            user = self.environment.lookup_user_by_id(principal_id)
            if not user:
                self.logger.warning(f"User {principal_id} not found in environment.")
                return None

            return PermissionObject(
                id=user.azure_ad_object_id or user.id,
                email=user.email,
                type=IamType.USER,
                entra_object_id=user.azure_ad_object_id,
            )

        elif principal_type == IamType.GROUP:
            team = self.environment.lookup_team_by_id(principal_id)
            if not team:
                self.logger.warning(f"Team {principal_id} not found in environment.")
                return None

            # AAD-backed teams (type 2 or 3) have Entra group object IDs
            if team.azure_ad_object_id:
                return PermissionObject(
                    id=team.azure_ad_object_id,
                    type=IamType.GROUP,
                    entra_object_id=team.azure_ad_object_id,
                )
            else:
                # Owner or Access teams - expand to individual users
                expanded = []
                for member_id in (team.member_ids or []):
                    user = self.environment.lookup_user_by_id(member_id)
                    if user and user.azure_ad_object_id:
                        expanded.append(
                            PermissionObject(
                                id=user.azure_ad_object_id,
                                email=user.email,
                                type=IamType.USER,
                                entra_object_id=user.azure_ad_object_id,
                            )
                        )
                # Return first for single user, or None for empty
                # For table-based mode the caller handles dedup
                if len(expanded) == 1:
                    return expanded[0]
                elif len(expanded) > 1:
                    # Return team representation - members resolved at apply time
                    return PermissionObject(
                        id=team.id,
                        type=IamType.GROUP,
                    )
                return None

        return None

    def __get_column_constraints_for_principals__(
        self,
        principals: set,
        tables: set,
        catalog_name: str,
        schema_name: str,
    ) -> List[ColumnConstraint]:
        """
        Build column constraints from field-level security profiles.
        For each principal in this role, check which field security profiles they belong to,
        and which columns they can read.
        """
        constraints = []
        principal_ids = {pid for pid, _ in principals}

        for profile in self.environment.field_security_profiles:
            # Check if any of the principals are assigned to this profile
            profile_principals = set(profile.user_ids or [])
            for team_id in (profile.team_ids or []):
                team = self.environment.lookup_team_by_id(team_id)
                if team:
                    profile_principals.update(team.member_ids or [])

            if not principal_ids.intersection(profile_principals):
                continue

            # Group permissions by table
            table_columns: Dict[str, List[str]] = {}
            for perm in (profile.permissions or []):
                if perm.entity_name in tables and perm.can_read == 4:  # 4 = Allowed
                    table_columns.setdefault(perm.entity_name, []).append(
                        perm.attribute_logical_name
                    )

            for table_name, columns in table_columns.items():
                constraints.append(
                    ColumnConstraint(
                        column_actions=[PermissionType.SELECT],
                        column_effect=PermissionState.GRANT,
                        column_names=columns,
                        table_name=table_name,
                        schema_name=schema_name,
                        catalog_name=catalog_name,
                    )
                )

        return constraints
