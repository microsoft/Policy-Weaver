import json
import os
from typing import List, Dict, Tuple, Set

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
        - Row constraints from BU depth (when enabled)
        """
        if not(self.config.constraints and self.config.constraints.columns and self.config.constraints.columns.columnlevelsecurity):
            self.logger.warning("Column level security is not enabled in the config.")
            column_security = False
        else:
            self.logger.info("Column level security is enabled in the config.")
            column_security = True

        if not(self.config.constraints and self.config.constraints.rows and self.config.constraints.rows.rowlevelsecurity):
            self.logger.warning("Row level security is not enabled in the config.")
            row_security = False
        else:
            self.logger.info("Row level security is enabled in the config.")
            row_security = True

        # Build (role instance + BU context) -> {principals, tables} mapping
        role_map: Dict[Tuple[str, str], Dict] = {}
        catalog_name = self.config.source.name
        schema_name = self.__get_schema_name__()

        for perm in self.environment.table_permissions:
            role_name = perm.role_name or "UnknownRole"
            role_key = (perm.role_id or role_name, perm.role_business_unit_id or "")
            if role_key not in role_map:
                role_map[role_key] = {
                    "role_name": role_name,
                    "role_business_unit_id": perm.role_business_unit_id,
                    "principals": set(),
                    "tables": set(),
                    "perms": [],
                }
            role_map[role_key]["principals"].add(
                (perm.principal_id, perm.principal_type)
            )
            role_map[role_key]["tables"].add(perm.table_name)
            role_map[role_key]["perms"].append(perm)

        policies = []
        for _, data in role_map.items():
            role_name = data["role_name"]
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
            ) if column_security else []

            row_constraints = self.__get_row_constraints_for_role__(
                data["perms"], catalog_name, schema_name
            ) if row_security else []

            role_name_with_context = role_name
            if data["role_business_unit_id"]:
                bu_label = self.__get_role_business_unit_label__(data["role_business_unit_id"])
                role_name_with_context = f"{role_name}_{bu_label}"

            role_policy = RolePolicy(
                name=role_name_with_context,
                permissionobjects=permission_objects,
                permissionscopes=permission_scopes,
                columnconstraints=column_constraints if column_constraints else None,
                rowconstraints=row_constraints if row_constraints else None,
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

    def __get_role_business_unit_label__(self, role_business_unit_id: str) -> str:
        """Return a readable BU label for role naming, with stable fallback."""
        if not role_business_unit_id:
            return ""

        bu = self.environment.lookup_business_unit_by_id(role_business_unit_id)
        if bu and bu.name:
            return bu.name

        return role_business_unit_id[:8]

    def __get_depth_rank__(self, depth: str) -> int:
        rank_map = DataverseAPIClient.DEPTH_RANK
        return rank_map.get((depth or "Global").title(), rank_map["Global"])

    def __get_descendant_business_unit_ids__(self, business_unit_id: str) -> List[str]:
        if not business_unit_id:
            return []

        children_map: Dict[str, List[str]] = {}
        for bu in self.environment.business_units:
            if not bu.parent_business_unit_id:
                continue
            if bu.parent_business_unit_id not in children_map:
                children_map[bu.parent_business_unit_id] = []
            children_map[bu.parent_business_unit_id].append(bu.id)

        descendants: Set[str] = set()
        stack = [business_unit_id]
        while stack:
            current = stack.pop()
            if current in descendants:
                continue
            descendants.add(current)
            stack.extend(children_map.get(current, []))

        return list(descendants)

    def __build_row_filter_condition__(
        self,
        effective_depth: str,
        role_business_unit_id: str,
        principal_ids: Set[str],
    ) -> str:
        depth = (effective_depth or "Global").title()

        if depth == "Global":
            return None

        if depth == "Deep":
            descendants = self.__get_descendant_business_unit_ids__(role_business_unit_id)
            if not descendants:
                return "false"
            escaped = "','".join(descendants)
            return f"_owningbusinessunit_value in ('{escaped}')"

        if depth == "Local":
            if not role_business_unit_id:
                return "false"
            return f"_owningbusinessunit_value = '{role_business_unit_id}'"

        if depth == "Basic":
            if not principal_ids:
                return "false"
            escaped = "','".join(sorted(principal_ids))
            return f"_ownerid_value in ('{escaped}')"

        return None

    def __get_row_constraints_for_role__(
        self,
        perms: List[DataverseTablePermission],
        catalog_name: str,
        schema_name: str,
    ) -> List[RowConstraint]:
        """
        Build BU-aware row constraints by mapping Dataverse read depth to Fabric row filters:
        - Global: no filter
        - Deep: _owningbusinessunit_value in role BU and descendants
        - Local: _owningbusinessunit_value equals role BU
        - Basic: _ownerid_value equals one of the role principals
        """
        constraints: List[RowConstraint] = []
        table_to_perms: Dict[str, List[DataverseTablePermission]] = {}

        for perm in perms:
            table_to_perms.setdefault(perm.table_name, []).append(perm)

        for table_name, table_perms in table_to_perms.items():
            ranked = sorted(
                table_perms,
                key=lambda p: self.__get_depth_rank__(p.depth),
                reverse=True,
            )
            effective_depth = (ranked[0].depth or "Global").title()
            role_business_unit_id = ranked[0].role_business_unit_id
            principal_ids = {p.principal_id for p in table_perms if p.principal_id}

            filter_condition = self.__build_row_filter_condition__(
                effective_depth=effective_depth,
                role_business_unit_id=role_business_unit_id,
                principal_ids=principal_ids,
            )

            if not filter_condition:
                continue

            constraints.append(
                RowConstraint(
                    catalog_name=catalog_name,
                    schema_name=schema_name,
                    table_name=table_name,
                    filter_condition=filter_condition,
                )
            )

        return constraints

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

            if not user.azure_ad_object_id:
                self.logger.warning(
                    f"Skipping Dataverse user {principal_id} because azure_ad_object_id is missing."
                )
                return None

            return PermissionObject(
                id=user.azure_ad_object_id,
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
