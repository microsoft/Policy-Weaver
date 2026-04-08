import os
from typing import List, Dict, Tuple, Set

from policyweaver.models.export import (
    PermissionObject,
    RolePolicyExport,
    RolePolicy,
    PermissionScope,
    ColumnConstraint,
    RowConstraint,
)
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap,
    DataverseEnvironment,
    DataverseTablePermission,
)
from policyweaver.core.enum import (
    IamType,
    PermissionType,
    PermissionState,
    PolicyWeaverConnectorType,
)
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
        self.__config_validation(config)
        self.config = config

        os.environ["DATAVERSE_ENVIRONMENT_URL"] = config.dataverse.environment_url

        self.api_client = DataverseAPIClient()
        self.environment: DataverseEnvironment = None

    def __config_validation(self, config: DataverseSourceMap) -> None:
        """Validate the Dataverse plugin configuration."""
        if not config.dataverse:
            raise ValueError(
                "DataverseSourceMap configuration is required for DataversePolicyWeaver."
            )

        if not config.dataverse.environment_url:
            raise ValueError(
                "Dataverse environment_url is required in the configuration."
            )

        if not config.dataverse.environment_url.startswith("https://"):
            raise ValueError("Dataverse environment_url must start with 'https://'.")

    def map_policy(self, policy_mapping: str = "role_based") -> RolePolicyExport:
        """
        Map Dataverse security policies to a role-based RolePolicyExport.

        Only 'role_based' mode is supported.  table_based mode cannot express
        row-level or column-level constraints and would over-grant access for
        non-Global privilege depths.

        Args:
            policy_mapping (str): Must be 'role_based'.
        Returns:
            RolePolicyExport: The mapped policies.
        """
        if policy_mapping != "role_based":
            raise ValueError(
                "Dataverse connector requires policy_mapping='role_based'. "
                "table_based mode cannot express row-level or column-level "
                "constraints and would over-grant access for non-Global "
                "privilege depths."
            )

        self.logger.info(f"Dataverse Policy Export for {self.config.source.name}...")

        self.environment = self.api_client.get_environment_security_map(
            self.config.source
        )

        if not self.environment.table_permissions:
            self.logger.warning(
                "No table-level read permissions found in Dataverse environment."
            )
            return None

        return self.__build_role_based_export__()

    def __build_role_based_export__(self) -> RolePolicyExport:
        """
        Build a role-based RolePolicyExport.
        Groups permissions by security role, where each role policy contains:
        - The principals (users/teams) assigned to that role
        - The table-level permission scopes (read)
        - Column constraints from field-level security
        - Row constraints from BU depth (when enabled)
        """
        if not (
            self.config.constraints
            and self.config.constraints.columns
            and self.config.constraints.columns.columnlevelsecurity
        ):
            self.logger.warning("Column level security is not enabled in the config.")
            column_security = False
        else:
            self.logger.info("Column level security is enabled in the config.")
            column_security = True

        # Note on constraints.rows.rowlevelsecurity:
        # For the Dataverse connector, row filters are ALWAYS applied for
        # non-Global depths to maintain exact access parity with Dataverse.
        # The toggle does NOT disable row filtering — it is advisory only.
        # Omitting BU-depth row filters would over-grant access.
        rls_config_on = bool(
            self.config.constraints
            and self.config.constraints.rows
            and self.config.constraints.rows.rowlevelsecurity
        )
        if not rls_config_on:
            self.logger.info(
                "constraints.rows.rowlevelsecurity is not set. "
                "Row filters are always applied for non-Global depths "
                "to maintain Dataverse access parity (this toggle is advisory only)."
            )
        else:
            self.logger.info(
                "Row level security enabled in config (always active for Dataverse)."
            )

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
            # Basic depth requires per-principal roles to prevent over-granting.
            # A shared role with ownerid in ('A','B') lets both see each
            # other's rows.  Splitting gives each user their own ownership filter.
            if self.__role_has_basic_effective_depth__(data["perms"]):
                per_principal = self.__build_per_principal_roles__(
                    data, catalog_name, schema_name, column_security
                )
                policies.extend(per_principal)
                continue

            # CLS divergence: if the effective users behind the principals
            # have different field security profile assignments, a shared
            # Fabric role would grant the union of all column permissions.
            # This includes single AAD-backed groups whose members have
            # divergent FSPs — OneLake applies one role to all group members.
            if column_security and self.__principals_have_divergent_cls__(
                data["principals"]
            ):
                per_principal = self.__build_per_principal_cls_roles__(
                    data, catalog_name, schema_name
                )
                policies.extend(per_principal)
                continue

            role_name = data["role_name"]
            permission_objects = []
            seen_entra_ids = set()
            for principal_id, principal_type in data["principals"]:
                resolved = self.__resolve_permission_object__(
                    principal_id, principal_type
                )
                for po in resolved:
                    entra_key = po.entra_object_id or po.id
                    if entra_key and entra_key not in seen_entra_ids:
                        seen_entra_ids.add(entra_key)
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
            column_constraints = (
                self.__get_column_constraints_for_principals__(
                    data["principals"], data["tables"], catalog_name, schema_name
                )
                if column_security
                else []
            )

            row_constraints = self.__get_row_constraints_for_role__(
                data["perms"], catalog_name, schema_name
            )

            role_name_with_context = role_name
            if data["role_business_unit_id"]:
                bu_label = self.__get_role_business_unit_label__(
                    data["role_business_unit_id"]
                )
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
            self.logger.warning(
                "No role-based policies generated from Dataverse permissions."
            )
            return None

        export = RolePolicyExport(
            source=self.config.source,
            type=PolicyWeaverConnectorType.DATAVERSE,
            policies=policies,
        )

        self.logger.info(
            f"Generated {len(policies)} role-based policies from Dataverse."
        )
        return export

    def __role_has_basic_effective_depth__(
        self, perms: List[DataverseTablePermission]
    ) -> bool:
        """Return True if any table in `perms` has Basic as its effective (highest-rank) depth."""
        table_to_perms: Dict[str, List[DataverseTablePermission]] = {}
        for perm in perms:
            table_to_perms.setdefault(perm.table_name, []).append(perm)
        for table_perms in table_to_perms.values():
            ranked = sorted(
                table_perms,
                key=lambda p: self.__get_depth_rank__(p.depth),
                reverse=True,
            )
            if (ranked[0].depth or "Unknown").title() == "Basic":
                return True
        return False

    def __build_per_principal_roles__(
        self,
        data: Dict,
        catalog_name: str,
        schema_name: str,
        column_security: bool,
    ) -> List[RolePolicy]:
        """
        Split a role into per-principal Fabric roles for Basic-depth owner isolation.

        Basic depth means "see rows you own".  Fabric Data Access Roles apply the
        same row filter to every member, so a shared role with
        ownerid in ('A','B') would let both A and B see each other's rows.
        This method creates one Fabric role per resolved identity so each user's
        filter contains only their own ownership scope (their Dataverse user ID
        plus the IDs of teams they belong to within this role).

        AAD-backed teams are expanded to individual members because the Fabric
        group-level filter cannot vary per member.
        """
        role_name = data["role_name"]
        bu_id = data["role_business_unit_id"]
        bu_label = self.__get_role_business_unit_label__(bu_id) if bu_id else ""

        team_principal_ids = {
            pid for pid, ptype in data["principals"] if ptype == IamType.GROUP
        }

        # (ownership_scope, PermissionObject, cls_principals)
        per_user_entries: List[Tuple[Set[str], PermissionObject, set]] = []
        seen_entra_ids: Set[str] = set()

        for principal_id, principal_type in data["principals"]:
            if principal_type == IamType.USER:
                user = self.environment.lookup_user_by_id(principal_id)
                if not user or not user.azure_ad_object_id:
                    continue
                if user.azure_ad_object_id in seen_entra_ids:
                    continue
                seen_entra_ids.add(user.azure_ad_object_id)

                po = PermissionObject(
                    id=user.azure_ad_object_id,
                    email=user.email,
                    type=IamType.USER,
                    entra_object_id=user.azure_ad_object_id,
                )
                ownership = {user.id}
                for team in self.environment.get_user_teams(user.id):
                    if team.id in team_principal_ids:
                        ownership.add(team.id)
                per_user_entries.append((ownership, po, {(principal_id, IamType.USER)}))

            elif principal_type == IamType.GROUP:
                team = self.environment.lookup_team_by_id(principal_id)
                if not team:
                    continue
                # Always expand to individual members for Basic-depth roles.
                for member_id in team.member_ids or []:
                    user = self.environment.lookup_user_by_id(member_id)
                    if not user or not user.azure_ad_object_id:
                        continue
                    if user.azure_ad_object_id in seen_entra_ids:
                        continue
                    seen_entra_ids.add(user.azure_ad_object_id)

                    po = PermissionObject(
                        id=user.azure_ad_object_id,
                        email=user.email,
                        type=IamType.USER,
                        entra_object_id=user.azure_ad_object_id,
                    )
                    ownership = {user.id}
                    for t in self.environment.get_user_teams(user.id):
                        if t.id in team_principal_ids:
                            ownership.add(t.id)
                    per_user_entries.append(
                        (ownership, po, {(member_id, IamType.USER)})
                    )

                if not team.member_ids:
                    self.logger.warning(
                        f"Team {team.name} ({principal_id}) has no members to expand "
                        f"for per-principal Basic-depth role splitting."
                    )

        if not per_user_entries:
            return []

        self.logger.info(
            f"Splitting role '{role_name}' into {len(per_user_entries)} per-principal "
            f"roles for Basic-depth owner isolation."
        )

        permission_scopes = [
            PermissionScope(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
            for table_name in data["tables"]
        ]

        policies: List[RolePolicy] = []
        for ownership_scope, po, cls_principals in per_user_entries:
            column_constraints = (
                self.__get_column_constraints_for_principals__(
                    cls_principals, data["tables"], catalog_name, schema_name
                )
                if column_security
                else []
            )

            row_constraints = self.__get_row_constraints_for_role__(
                data["perms"],
                catalog_name,
                schema_name,
                basic_ownership_override=ownership_scope,
            )

            principal_label = po.email or po.id[:12]
            if bu_label:
                name_ctx = f"{role_name}_{bu_label}_{principal_label}"
            else:
                name_ctx = f"{role_name}_{principal_label}"

            policies.append(
                RolePolicy(
                    name=name_ctx,
                    permissionobjects=[po],
                    permissionscopes=permission_scopes,
                    columnconstraints=column_constraints
                    if column_constraints
                    else None,
                    rowconstraints=row_constraints if row_constraints else None,
                )
            )

        return policies

    def __principals_have_divergent_cls__(self, principals: set) -> bool:
        """Return True if the effective users behind `principals` have different
        field security profile coverage.

        GROUP principals are expanded to their member user IDs so that:
        - AAD-backed team IDs (which never appear in profile coverage) are
          resolved to the actual users who will receive the Fabric role.
        - A single AAD-backed group whose members have divergent FSPs is
          correctly detected (OneLake applies one role policy to all group
          members, so per-member CLS differences require splitting).
        """
        # Expand all principals to effective user IDs
        effective_user_ids: List[str] = []
        for pid, ptype in principals:
            if ptype == IamType.USER:
                effective_user_ids.append(pid)
            elif ptype == IamType.GROUP:
                team = self.environment.lookup_team_by_id(pid)
                if team and team.member_ids:
                    effective_user_ids.extend(team.member_ids)

        if len(effective_user_ids) < 2:
            return False

        # Pre-compute expanded coverage for each profile
        profile_coverage: Dict[str, set] = {}
        for profile in self.environment.field_security_profiles:
            covered = set(profile.user_ids or [])
            for team_id in profile.team_ids or []:
                team = self.environment.lookup_team_by_id(team_id)
                if team:
                    covered.update(team.member_ids or [])
            profile_coverage[profile.id] = covered

        reference_profiles = None
        for uid in effective_user_ids:
            matching = frozenset(
                prof_id
                for prof_id, covered in profile_coverage.items()
                if uid in covered
            )
            if reference_profiles is None:
                reference_profiles = matching
            elif matching != reference_profiles:
                return True

        return False

    def __build_per_principal_cls_roles__(
        self,
        data: Dict,
        catalog_name: str,
        schema_name: str,
    ) -> List[RolePolicy]:
        """
        Split a non-Basic role into per-principal Fabric roles for CLS isolation.

        When principals in the same Dataverse role have different field security
        profile assignments, a shared Fabric role would grant the union of all
        column permissions to every member.  Splitting gives each user their
        own column constraints while preserving the shared BU-depth row filter.
        """
        role_name = data["role_name"]
        bu_id = data["role_business_unit_id"]
        bu_label = self.__get_role_business_unit_label__(bu_id) if bu_id else ""

        # Row constraints are BU-depth-based and identical for all principals
        row_constraints = self.__get_row_constraints_for_role__(
            data["perms"], catalog_name, schema_name
        )

        permission_scopes = [
            PermissionScope(
                catalog=catalog_name,
                catalog_schema=schema_name,
                table=table_name,
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
            )
            for table_name in data["tables"]
        ]

        policies: List[RolePolicy] = []
        seen_entra_ids: Set[str] = set()

        for principal_id, principal_type in data["principals"]:
            if principal_type == IamType.USER:
                user = self.environment.lookup_user_by_id(principal_id)
                if not user or not user.azure_ad_object_id:
                    continue
                if user.azure_ad_object_id in seen_entra_ids:
                    continue
                seen_entra_ids.add(user.azure_ad_object_id)

                po = PermissionObject(
                    id=user.azure_ad_object_id,
                    email=user.email,
                    type=IamType.USER,
                    entra_object_id=user.azure_ad_object_id,
                )
                cls_principals = {(principal_id, IamType.USER)}

            elif principal_type == IamType.GROUP:
                team = self.environment.lookup_team_by_id(principal_id)
                if not team:
                    continue

                # In the CLS-split path, ALL groups (AAD-backed or not) must
                # be expanded to individual members.  A single Fabric group
                # role cannot represent per-member CLS differences, and the
                # team ID itself doesn't match FSP profile coverage (which
                # is keyed on user IDs).
                for member_id in team.member_ids or []:
                    muser = self.environment.lookup_user_by_id(member_id)
                    if not muser or not muser.azure_ad_object_id:
                        continue
                    if muser.azure_ad_object_id in seen_entra_ids:
                        continue
                    seen_entra_ids.add(muser.azure_ad_object_id)

                    mpo = PermissionObject(
                        id=muser.azure_ad_object_id,
                        email=muser.email,
                        type=IamType.USER,
                        entra_object_id=muser.azure_ad_object_id,
                    )
                    mcls = {(member_id, IamType.USER)}
                    col_constraints = self.__get_column_constraints_for_principals__(
                        mcls, data["tables"], catalog_name, schema_name
                    )
                    label = muser.email or muser.azure_ad_object_id[:12]
                    name = (
                        f"{role_name}_{bu_label}_{label}"
                        if bu_label
                        else f"{role_name}_{label}"
                    )
                    policies.append(
                        RolePolicy(
                            name=name,
                            permissionobjects=[mpo],
                            permissionscopes=permission_scopes,
                            columnconstraints=col_constraints
                            if col_constraints
                            else None,
                            rowconstraints=row_constraints if row_constraints else None,
                        )
                    )
                continue  # members handled inline
            else:
                continue

            # Build per-principal role (USER path — GROUP always continues above)
            column_constraints = self.__get_column_constraints_for_principals__(
                cls_principals, data["tables"], catalog_name, schema_name
            )

            principal_label = po.email or po.id[:12]
            name = (
                f"{role_name}_{bu_label}_{principal_label}"
                if bu_label
                else f"{role_name}_{principal_label}"
            )

            policies.append(
                RolePolicy(
                    name=name,
                    permissionobjects=[po],
                    permissionscopes=permission_scopes,
                    columnconstraints=column_constraints
                    if column_constraints
                    else None,
                    rowconstraints=row_constraints if row_constraints else None,
                )
            )

        if policies:
            self.logger.info(
                f"Splitting role '{role_name}' into {len(policies)} per-principal "
                f"roles for column-level security isolation."
            )

        return policies

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
        return rank_map.get((depth or "Unknown").title(), 0)

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
        depth = (effective_depth or "Unknown").title()

        if depth == "Global":
            return None

        if depth == "Deep":
            descendants = self.__get_descendant_business_unit_ids__(
                role_business_unit_id
            )
            if not descendants:
                return "false"
            escaped = "','".join(descendants)
            return f"owningbusinessunit in ('{escaped}')"

        if depth == "Local":
            if not role_business_unit_id:
                return "false"
            return f"owningbusinessunit = '{role_business_unit_id}'"

        if depth == "Basic":
            if not principal_ids:
                return "false"
            escaped = "','".join(sorted(principal_ids))
            return f"ownerid in ('{escaped}')"

        # Unknown or unrecognized depth — fail closed (deny all rows)
        self.logger.warning(
            f"Unrecognized effective depth '{effective_depth}' for role BU '{role_business_unit_id}'. "
            f"Denying all rows (fail-closed)."
        )
        return "false"

    def __get_row_constraints_for_role__(
        self,
        perms: List[DataverseTablePermission],
        catalog_name: str,
        schema_name: str,
        basic_ownership_override: Set[str] = None,
    ) -> List[RowConstraint]:
        """
        Build BU-aware row constraints by mapping Dataverse read depth to Fabric row filters:
        - Global: no filter
        - Deep: owningbusinessunit in role BU and descendants
        - Local: owningbusinessunit equals role BU
        - Basic: ownerid equals one of the role principals

        When `basic_ownership_override` is provided, it replaces the aggregated
        principal ID set for Basic-depth tables.  This is used by the per-principal
        splitting path to ensure each user's filter contains only their own
        ownership scope instead of all principals in the role.
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
            effective_depth = (ranked[0].depth or "Unknown").title()
            role_business_unit_id = ranked[0].role_business_unit_id

            if basic_ownership_override is not None and effective_depth == "Basic":
                principal_ids = basic_ownership_override
            else:
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

    def __resolve_permission_object__(
        self, principal_id: str, principal_type: IamType
    ) -> List[PermissionObject]:
        """
        Resolve a Dataverse principal to PermissionObject(s) with Entra identity.
        Returns a list to support expanding owner/access teams to individual users.
        """
        if principal_type == IamType.USER:
            user = self.environment.lookup_user_by_id(principal_id)
            if not user:
                self.logger.warning(f"User {principal_id} not found in environment.")
                return []

            if not user.azure_ad_object_id:
                self.logger.warning(
                    f"Skipping Dataverse user {principal_id} because azure_ad_object_id is missing."
                )
                return []

            return [
                PermissionObject(
                    id=user.azure_ad_object_id,
                    email=user.email,
                    type=IamType.USER,
                    entra_object_id=user.azure_ad_object_id,
                )
            ]

        elif principal_type == IamType.GROUP:
            team = self.environment.lookup_team_by_id(principal_id)
            if not team:
                self.logger.warning(f"Team {principal_id} not found in environment.")
                return []

            # AAD-backed teams (type 2 or 3) have Entra group object IDs
            if team.azure_ad_object_id:
                return [
                    PermissionObject(
                        id=team.azure_ad_object_id,
                        type=IamType.GROUP,
                        entra_object_id=team.azure_ad_object_id,
                    )
                ]
            else:
                # Owner or Access teams - expand to individual users
                expanded = []
                for member_id in team.member_ids or []:
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
                if not expanded:
                    self.logger.warning(
                        f"Owner/Access team {team.name} ({principal_id}) produced no resolvable Entra identities "
                        f"(members without azure_ad_object_id or empty membership)."
                    )
                return expanded

        return []

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
        # Expand GROUP principals to their member user IDs so team-assigned
        # FSP profiles are correctly matched (profile coverage is built from
        # user_ids and team.member_ids, never raw team IDs).
        principal_ids: Set[str] = set()
        for pid, ptype in principals:
            if ptype == IamType.USER:
                principal_ids.add(pid)
            elif ptype == IamType.GROUP:
                team = self.environment.lookup_team_by_id(pid)
                if team and team.member_ids:
                    principal_ids.update(team.member_ids)
                else:
                    principal_ids.add(pid)  # fallback: raw ID

        for profile in self.environment.field_security_profiles:
            # Check if any of the principals are assigned to this profile
            profile_principals = set(profile.user_ids or [])
            for team_id in profile.team_ids or []:
                team = self.environment.lookup_team_by_id(team_id)
                if team:
                    profile_principals.update(team.member_ids or [])

            if not principal_ids.intersection(profile_principals):
                continue

            # Group permissions by table
            table_columns: Dict[str, List[str]] = {}
            for perm in profile.permissions or []:
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
