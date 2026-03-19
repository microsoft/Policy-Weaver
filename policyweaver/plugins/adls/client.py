import json
import logging
import os
from typing import List

from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.adls.model import (
    AdlsConnection,
    AdlsDatabaseMap,
    AdlsGrant,
    AdlsPrincipal,
    AdlsSourceMap,
)
from policyweaver.plugins.adls.api import AdlsAPIClient
from policyweaver.core.api.microsoftgraph import MicrosoftGraphClient

from policyweaver.models.export import (
    PermissionScope,
    PolicyExport,
    Policy,
    Permission,
    PermissionObject,
    RolePolicy,
    RolePolicyExport,
)

from policyweaver.core.enum import (
    IamType,
    PermissionType,
    PermissionState,
    PolicyWeaverConnectorType,
)

from policyweaver.core.utility import Utils


class AdlsPolicyWeaver(PolicyWeaverCore):
    """
    ADLS Gen2 Policy Weaver for Azure Data Lake Storage ACLs.
    This class extends PolicyWeaverCore to implement the mapping of POSIX ACL policies
    from ADLS Gen2 to the Policy Weaver framework.
    """

    def __init__(self, config: AdlsSourceMap) -> None:
        """
        Initializes the AdlsPolicyWeaver with the provided configuration.
        Args:
            config (AdlsSourceMap): The configuration object containing ADLS connection details.
        Raises:
            ValueError: If the configuration is invalid.
        """
        super().__init__(PolicyWeaverConnectorType.ADLS_GEN2, config)

        self.__config_validation(config)

        connection = AdlsConnection(
            account_url=config.adls.account_url,
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret,
        )

        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = AdlsAPIClient(connection)

    def __config_validation(self, config: AdlsSourceMap) -> None:
        """
        Validates the configuration for the AdlsPolicyWeaver.
        Args:
            config (AdlsSourceMap): The configuration object to validate.
        Raises:
            ValueError: If required fields are missing.
        """
        if not config.adls:
            raise ValueError("AdlsSourceMap configuration is required for AdlsPolicyWeaver.")

        if not config.adls.account_url:
            raise ValueError(
                "account_url is required in the ADLS configuration."
            )

        if not config.service_principal:
            raise ValueError(
                "service_principal configuration is required for ADLS authentication."
            )

        sp = config.service_principal
        if not sp.tenant_id or not sp.client_id or not sp.client_secret:
            raise ValueError(
                "service_principal must include tenant_id, client_id, and client_secret."
            )

    def __build_permission_object__(self, principal: AdlsPrincipal) -> PermissionObject:
        """
        Build a PermissionObject from an ADLS principal.
        Args:
            principal (AdlsPrincipal): The ADLS principal.
        Returns:
            PermissionObject: The corresponding permission object, or None.
        """
        if principal.principal_type == "user":
            return PermissionObject(
                id=principal.object_id,
                email=principal.email,
                type=IamType.USER,
                entra_object_id=principal.object_id,
            )
        elif principal.principal_type == "group":
            return PermissionObject(
                id=principal.object_id,
                type=IamType.GROUP,
                entra_object_id=principal.object_id,
            )
        return None

    def __get_all_permission_objects_for_principal__(
        self, principal_id: str
    ) -> List[PermissionObject]:
        """
        Get permission objects for a given principal ID.
        If the principal is a group, individual user members are not expanded here —
        the principal itself is returned as a GROUP permission object.
        Args:
            principal_id (str): The Azure AD Object ID.
        Returns:
            List[PermissionObject]: List of permission objects.
        """
        matching = [p for p in self.map.principals if p.object_id == principal_id]
        if not matching:
            return []

        principal = matching[0]
        po = self.__build_permission_object__(principal)
        return [po] if po else []

    @staticmethod
    def __deduplicate_permission_objects__(
        permission_objects: List[PermissionObject],
    ) -> List[PermissionObject]:
        seen = set()
        result = []
        for obj in permission_objects:
            key = obj.entra_object_id or obj.id
            if key not in seen:
                seen.add(key)
                result.append(obj)
        return result

    @staticmethod
    def __split_adls_path__(path: str) -> tuple:
        """
        Split an ADLS path into (schema, table) for Fabric mapping.
        '/' or ''         → ('', '')      → maps to wildcard (*)
        'sales'           → ('sales', '') → maps to Tables/sales
        'sales/reports'   → ('sales', 'reports') → maps to Tables/sales/reports
        """
        stripped = path.strip("/") if path else ""
        if not stripped:
            return ("", "")
        segments = stripped.split("/", 1)
        schema = segments[0]
        table = segments[1] if len(segments) > 1 else ""
        return (schema, table)

    def __compute_valid_grants__(self) -> List[AdlsGrant]:
        """
        Filter grants to only include access-scope grants with read permission.
        Returns:
            List[AdlsGrant]: Valid grants for policy mapping.
        """
        valid = [
            g
            for g in self.map.grants
            if g.read and g.acl_scope == "access"
        ]

        # Deduplicate
        seen = set()
        deduped = []
        for g in valid:
            key = (g.principal_id, g.container, g.path)
            if key not in seen:
                seen.add(key)
                deduped.append(g)
        return deduped

    def _build_table_based_policy__(
        self, container: str, path: str, grants: List[AdlsGrant]
    ) -> Policy:
        """
        Build a table-based policy for a single ADLS path.
        Maps container → catalog, parent directory → schema, path → table.
        Args:
            container (str): The ADLS container name.
            path (str): The ADLS path.
            grants (List[AdlsGrant]): Grants for this path.
        Returns:
            Policy: The mapped policy.
        """
        schema_name, table_name = self.__split_adls_path__(path)

        policy = Policy(
            catalog=container,
            catalog_schema=schema_name,
            table=table_name,
            permissions=[],
        )

        permission_objects = []
        for grant in grants:
            permission_objects.extend(
                self.__get_all_permission_objects_for_principal__(grant.principal_id)
            )

        permission_objects = self.__deduplicate_permission_objects__(permission_objects)

        if permission_objects:
            permission = Permission(
                name=PermissionType.SELECT,
                state=PermissionState.GRANT,
                objects=permission_objects,
            )
            policy.permissions.append(permission)

        return policy

    def __build_table_based_policy_export__(self) -> PolicyExport:
        """
        Build a table-based policy export from all valid grants.
        Returns:
            PolicyExport: The complete policy export.
        """
        policy_export = PolicyExport(
            source=self.config.source, type=self.config.type, policies=[]
        )

        grants_by_path = {}
        for grant in self.valid_grants:
            key = (grant.container, grant.path)
            if key not in grants_by_path:
                grants_by_path[key] = []
            grants_by_path[key].append(grant)

        for (container, path), grants in grants_by_path.items():
            policy = self._build_table_based_policy__(container, path, grants)
            if policy and policy.permissions:
                policy_export.policies.append(policy)

        return policy_export

    def _build_role_based_policy__(
        self, principal_id: str, grants: List[AdlsGrant]
    ) -> RolePolicy:
        """
        Build a role-based policy for a single principal.
        Expands each granted path to include all discovered sub-folders.
        Args:
            principal_id (str): The Azure AD Object ID of the principal.
            grants (List[AdlsGrant]): All grants for this principal.
        Returns:
            RolePolicy: The mapped role-based policy, or None.
        """
        # Collect all explicitly granted paths
        granted_paths = {(g.container, g.path) for g in grants}

        # Expand each granted path to include all scanned sub-directories
        expanded_paths = set()
        has_root_grant = False
        all_dirs = [
            (acl.container, acl.path)
            for acl in self.map.path_acls
            if acl.is_directory
        ]
        for container, path in granted_paths:
            expanded_paths.add((container, path))
            prefix = path.strip("/")
            if not prefix:
                has_root_grant = True
                continue
            for dir_container, dir_path in all_dirs:
                if dir_container != container:
                    continue
                dir_stripped = dir_path.strip("/")
                if dir_stripped.startswith(prefix + "/"):
                    expanded_paths.add((dir_container, dir_path))

        # If there is a root grant, the wildcard already covers everything
        if has_root_grant:
            expanded_paths = {(c, p) for c, p in granted_paths if not p.strip("/")}
        else:
            # Prune parent paths that have children in the set so only
            # leaf (table-level) paths remain.
            parents_to_remove = set()
            for container, path in expanded_paths:
                prefix = path.strip("/")
                if not prefix:
                    continue
                for other_container, other_path in expanded_paths:
                    if other_container != container:
                        continue
                    other_stripped = other_path.strip("/")
                    if other_stripped != prefix and other_stripped.startswith(prefix + "/"):
                        parents_to_remove.add((container, path))
                        break
            expanded_paths -= parents_to_remove

        # Build deduplicated permission scopes
        permission_scopes = []
        seen_keys = set()
        for container, path in expanded_paths:
            schema_name, table_name = self.__split_adls_path__(path)
            key = (container, schema_name, table_name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            permission_scopes.append(
                PermissionScope(
                    catalog=container,
                    catalog_schema=schema_name,
                    table=table_name,
                    name=PermissionType.SELECT,
                    state=PermissionState.GRANT,
                )
            )

        permission_objects = self.__get_all_permission_objects_for_principal__(principal_id)

        if not permission_objects:
            self.logger.warning(f"No valid permission objects for principal: {principal_id}")
            return None
        if not permission_scopes:
            self.logger.warning(f"No valid permission scopes for principal: {principal_id}")
            return None

        # Use the display name as the role name if available
        matching = [p for p in self.map.principals if p.object_id == principal_id]
        role_name = matching[0].display_name if matching and matching[0].display_name else principal_id

        policy = RolePolicy(
            name=role_name,
            permissionscopes=permission_scopes,
            permissionobjects=permission_objects,
        )
        return policy

    def __build_role_based_policy_export__(self) -> RolePolicyExport:
        """
        Build a role-based policy export from all valid grants.
        Returns:
            RolePolicyExport: The complete role-based policy export.
        """
        policy_export = RolePolicyExport(
            source=self.config.source, type=self.config.type, policies=[]
        )

        grants_by_principal = {}
        for grant in self.valid_grants:
            if grant.principal_id not in grants_by_principal:
                grants_by_principal[grant.principal_id] = []
            grants_by_principal[grant.principal_id].append(grant)

        for principal_id, grants in grants_by_principal.items():
            policy = self._build_role_based_policy__(principal_id, grants)
            if policy:
                policy_export.policies.append(policy)

        return policy_export

    async def __resolve_principal_names__(self) -> None:
        """
        Resolve display names for all principals via Microsoft Graph.
        """
        graph_client = MicrosoftGraphClient()
        for principal in self.map.principals:
            result = await graph_client.get_directory_object_by_id(principal.object_id)
            if result:
                principal.display_name = result.get('display_name')
                self.logger.info(
                    f"Resolved principal {principal.object_id} → {principal.display_name}"
                )

    async def map_policy(self, policy_mapping="role_based"):
        """
        Main entry point: scan ADLS ACLs and map them to PolicyWeaver export format.
        Args:
            policy_mapping (str): 'role_based' or 'table_based'.
        Returns:
            PolicyExport or RolePolicyExport: The mapped policy export.
        """
        adls_config = self.config.adls

        self.map = self.api_client.__get_database_map__(
            self.config.source,
            container=adls_config.container,
            path=adls_config.path or "",
            max_depth=adls_config.max_depth if adls_config.max_depth is not None else -1,
        )

        await self.__resolve_principal_names__()

        self.valid_grants = self.__compute_valid_grants__()
        self.logger.info(f"Computed {len(self.valid_grants)} valid grants for policy mapping.")

        if policy_mapping == "role_based":
            return self.__build_role_based_policy_export__()
        elif policy_mapping == "table_based":
            return self.__build_table_based_policy_export__()
