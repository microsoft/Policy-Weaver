import logging
import json
import os
import time
from typing import List, Dict, Any

import requests
from pydantic.json import pydantic_encoder

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.enum import IamType
from policyweaver.models.config import Source
from policyweaver.plugins.dataverse.model import (
    DataverseUser,
    DataverseTeam,
    DataverseSecurityRole,
    DataverseRolePrivilege,
    DataverseFieldSecurityProfile,
    DataverseFieldPermission,
    DataverseTablePermission,
    DataverseEnvironment,
)


class DataverseAPIClient:
    """
    Dataverse API Client for fetching security metadata from Dynamics 365 / Dataverse.
    Uses the Dataverse Web API (OData v4) to retrieve users, teams, security roles,
    role privileges, field-level security profiles, and their assignments.
    """

    DEFAULT_API_VERSION = "v9.2"
    READ_PRIVILEGE_PREFIX = "prvRead"
    READ_ACCESS_RIGHT = 1  # ReadAccess bit in Dataverse privilege access rights

    def __init__(self):
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.base_url = os.environ["DATAVERSE_ENVIRONMENT_URL"].rstrip("/")
        self.dataverse_scope = f"{self.base_url}/.default"
        self.api_version = os.getenv("DATAVERSE_API_VERSION", self.DEFAULT_API_VERSION)
        self.api_url = f"{self.base_url}/api/data/{self.api_version}"
        self.__token = None
        self.__token_expires_on = 0

    def _get_access_token(self, force_refresh: bool = False) -> str:
        """Get a cached access token and refresh before expiry when needed."""
        refresh_window_seconds = 120
        now = int(time.time())

        if (
            force_refresh
            or not self.__token
            or now >= (self.__token_expires_on - refresh_window_seconds)
        ):
            token = ServicePrincipal.Credential.get_token(self.dataverse_scope)
            self.__token = token.token
            self.__token_expires_on = token.expires_on

        return self.__token

    def _request_get(self, url: str) -> requests.Response:
        """Issue GET with a single token-refresh retry when Dataverse returns 401."""
        response = requests.get(url, headers=self._headers)
        if response.status_code == 401:
            self._get_access_token(force_refresh=True)
            response = requests.get(url, headers=self._headers)
        return response

    @property
    def _headers(self) -> dict:
        if not self.__token:
            self._get_access_token()
        return {
            "Authorization": f"Bearer {self.__token}",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
            "Prefer": "odata.include-annotations=*,odata.maxpagesize=5000",
        }

    def _get_paged(self, url: str) -> List[dict]:
        """Fetch all pages of an OData collection."""
        results = []
        while url:
            response = self._request_get(url)
            response.raise_for_status()
            data = response.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return results

    def get_environment_security_map(self, source: Source) -> DataverseEnvironment:
        """
        Fetches the complete security metadata for a Dataverse environment.
        Args:
            source (Source): The source configuration with table/schema filters.
        Returns:
            DataverseEnvironment: The collected security metadata.
        """
        env = DataverseEnvironment()

        self.logger.info("Fetching Dataverse users...")
        env.users = self.__get_users__()
        self.logger.info(f"Found {len(env.users)} active users.")

        self.logger.info("Fetching Dataverse teams...")
        env.teams = self.__get_teams__()
        self.logger.info(f"Found {len(env.teams)} teams.")

        self.logger.info("Fetching security roles...")
        env.security_roles = self.__get_security_roles__()
        self.logger.info(f"Found {len(env.security_roles)} security roles.")

        self.logger.info("Fetching role privileges...")
        env.role_privileges = self.__get_role_read_privileges__(env.security_roles)
        self.logger.info(f"Found {len(env.role_privileges)} read privileges.")

        self.logger.info("Fetching user-role assignments...")
        env.user_role_assignments = self.__get_user_role_assignments__()
        self.logger.info(f"Found user-role assignments for {len(env.user_role_assignments)} users.")

        self.logger.info("Fetching team-role assignments...")
        env.team_role_assignments = self.__get_team_role_assignments__()
        self.logger.info(f"Found team-role assignments for {len(env.team_role_assignments)} teams.")

        self.logger.info("Fetching team memberships...")
        self.__populate_team_members__(env.teams)

        self.logger.info("Fetching field-level security profiles...")
        env.field_security_profiles = self.__get_field_security_profiles__()
        self.logger.info(f"Found {len(env.field_security_profiles)} field security profiles.")

        # Resolve effective table-level read permissions
        table_filter = self.__get_table_filter__(source)
        env.table_permissions = self.__resolve_table_permissions__(
            env, table_filter
        )

        self.logger.debug(
            f"Dataverse Environment Security Map: {json.dumps(env, default=pydantic_encoder, indent=4)}"
        )
        return env

    def __get_table_filter__(self, source: Source) -> List[str]:
        """Build a list of table names from source config for filtering."""
        tables = []
        if source and source.schemas:
            for schema in source.schemas:
                if schema.tables:
                    tables.extend(schema.tables)
        return tables if tables else None

    def __get_users__(self) -> List[DataverseUser]:
        """Retrieve active (non-disabled) system users."""
        url = (
            f"{self.api_url}/systemusers"
            "?$select=systemuserid,fullname,internalemailaddress,azureactivedirectoryobjectid,isdisabled"
            "&$filter=isdisabled eq false and internalemailaddress ne null"
        )
        records = self._get_paged(url)
        users = []
        for r in records:
            email = r.get("internalemailaddress", "")
            if not email or email.strip() == "":
                continue
            users.append(
                DataverseUser(
                    id=r["systemuserid"],
                    name=r.get("fullname"),
                    email=email,
                    azure_ad_object_id=r.get("azureactivedirectoryobjectid"),
                    is_disabled=r.get("isdisabled", False),
                )
            )
        self.logger.debug(f"Dataverse Users: {json.dumps(users, default=pydantic_encoder, indent=4)}")
        return users

    def __get_teams__(self) -> List[DataverseTeam]:
        """Retrieve teams from Dataverse."""
        url = (
            f"{self.api_url}/teams"
            "?$select=teamid,name,teamtype,azureactivedirectoryobjectid"
        )
        records = self._get_paged(url)
        teams = [
            DataverseTeam(
                id=r["teamid"],
                name=r.get("name"),
                team_type=r.get("teamtype", 0),
                azure_ad_object_id=r.get("azureactivedirectoryobjectid"),
            )
            for r in records
        ]
        self.logger.debug(f"Dataverse Teams: {json.dumps(teams, default=pydantic_encoder, indent=4)}")
        return teams

    def __populate_team_members__(self, teams: List[DataverseTeam]) -> None:
        """Populate member_ids for each team via teammemberships."""
        for team in teams:
            url = f"{self.api_url}/teams({team.id})/teammembership_association/$ref"
            try:
                records = self._get_paged(url)
                member_ids = []
                for r in records:
                    ref = r.get("@odata.id", "")
                    if "systemusers(" in ref:
                        uid = ref.split("systemusers(")[1].rstrip(")")
                        member_ids.append(uid)
                team.member_ids = member_ids
            except Exception as e:
                self.logger.warning(f"Failed to fetch members for team {team.name}: {e}")
                team.member_ids = []

    def __get_security_roles__(self) -> List[DataverseSecurityRole]:
        """Retrieve all security roles."""
        url = f"{self.api_url}/roles?$select=roleid,name"
        records = self._get_paged(url)
        roles = [
            DataverseSecurityRole(id=r["roleid"], name=r.get("name"))
            for r in records
        ]
        self.logger.debug(f"Dataverse Security Roles: {json.dumps(roles, default=pydantic_encoder, indent=4)}")
        return roles

    def __get_role_read_privileges__(self, roles: List[DataverseSecurityRole]) -> List[DataverseRolePrivilege]:
        """
        Retrieve role privileges and filter to only read-related privileges.
        Uses the roleprivileges_association navigation property.
        """
        all_privileges = []

        for role in roles:
            url = (
                f"{self.api_url}/roles({role.id})/roleprivileges_association"
                "?$select=privilegeid,name,accessright"
            )
            try:
                records = self._get_paged(url)
            except Exception as e:
                self.logger.warning(f"Failed to fetch privileges for role {role.name}: {e}")
                continue

            for r in records:
                priv_name = r.get("name", "")
                access_right = r.get("accessright", 0)

                # Filter to read privileges: name starts with 'prvRead' or accessright includes ReadAccess bit
                is_read = priv_name.lower().startswith(self.READ_PRIVILEGE_PREFIX.lower())
                if not is_read and not (access_right & self.READ_ACCESS_RIGHT):
                    continue

                # Extract entity name from privilege name (e.g., 'prvReadaccount' -> 'account')
                entity_name = None
                if priv_name.lower().startswith("prvread"):
                    entity_name = priv_name[7:]  # len("prvRead") = 7

                depth = self.__get_privilege_depth__(role.id, r["privilegeid"])

                all_privileges.append(
                    DataverseRolePrivilege(
                        privilege_id=r["privilegeid"],
                        role_id=role.id,
                        name=priv_name,
                        access_right=access_right,
                        depth=depth,
                        entity_name=entity_name,
                        can_read=True,
                    )
                )

        return all_privileges

    def __get_privilege_depth__(self, role_id: str, privilege_id: str) -> str:
        """
        Retrieve the depth of a specific privilege for a role using
        the RetrieveRolePrivilegesRole function.
        Falls back to 'Global' if the depth cannot be determined.
        """
        url = (
            f"{self.api_url}/roles({role_id})/roleprivileges_association"
            f"?$filter=privilegeid eq {privilege_id}"
            "&$select=depth"
        )
        try:
            response = self._request_get(url)
            if response.status_code == 200:
                data = response.json()
                values = data.get("value", [])
                if values:
                    depth_val = values[0].get("depth", 0)
                    depth_map = {0: "Basic", 1: "Local", 2: "Deep", 3: "Global"}
                    return depth_map.get(depth_val, "Global")
        except Exception:
            pass
        return "Global"

    def __get_user_role_assignments__(self) -> Dict[str, List[str]]:
        """
        Get mapping of user IDs to their assigned security role IDs.
        Uses systemuserroles_association.
        """
        url = (
            f"{self.api_url}/systemuserroles"
            "?$select=systemuserid,roleid"
        )
        records = self._get_paged(url)
        assignments: Dict[str, List[str]] = {}
        for r in records:
            user_id = r.get("systemuserid")
            role_id = r.get("roleid")
            if user_id and role_id:
                assignments.setdefault(user_id, []).append(role_id)

        self.logger.debug(f"User-Role Assignments: {len(assignments)} users mapped")
        return assignments

    def __get_team_role_assignments__(self) -> Dict[str, List[str]]:
        """
        Get mapping of team IDs to their assigned security role IDs.
        Uses teamroles_association.
        """
        url = (
            f"{self.api_url}/teamroles"
            "?$select=teamid,roleid"
        )
        records = self._get_paged(url)
        assignments: Dict[str, List[str]] = {}
        for r in records:
            team_id = r.get("teamid")
            role_id = r.get("roleid")
            if team_id and role_id:
                assignments.setdefault(team_id, []).append(role_id)

        self.logger.debug(f"Team-Role Assignments: {len(assignments)} teams mapped")
        return assignments

    def __get_field_security_profiles__(self) -> List[DataverseFieldSecurityProfile]:
        """Retrieve field-level security profiles, their field permissions, and assignments."""
        url = (
            f"{self.api_url}/fieldsecurityprofiles"
            "?$select=fieldsecurityprofileid,name"
        )
        records = self._get_paged(url)
        profiles = []

        for r in records:
            profile_id = r["fieldsecurityprofileid"]
            profile = DataverseFieldSecurityProfile(
                id=profile_id,
                name=r.get("name"),
            )

            # Get field permissions for this profile
            perm_url = (
                f"{self.api_url}/fieldpermissions"
                f"?$select=fieldpermissionid,entityname,attributelogicalname,canread"
                f"&$filter=_fieldsecurityprofileid_value eq {profile_id}"
            )
            try:
                perm_records = self._get_paged(perm_url)
                profile.permissions = [
                    DataverseFieldPermission(
                        field_security_profile_id=profile_id,
                        field_security_profile_name=profile.name,
                        entity_name=p.get("entityname"),
                        attribute_logical_name=p.get("attributelogicalname"),
                        can_read=p.get("canread", 0),
                    )
                    for p in perm_records
                ]
            except Exception as e:
                self.logger.warning(f"Failed to fetch field permissions for profile {profile.name}: {e}")

            # Get users assigned to this profile
            user_url = f"{self.api_url}/fieldsecurityprofiles({profile_id})/systemuserprofiles_association/$ref"
            try:
                user_records = self._get_paged(user_url)
                profile.user_ids = [
                    ref.get("@odata.id", "").split("systemusers(")[1].rstrip(")")
                    for ref in user_records
                    if "systemusers(" in ref.get("@odata.id", "")
                ]
            except Exception as e:
                self.logger.warning(f"Failed to fetch user assignments for profile {profile.name}: {e}")

            # Get teams assigned to this profile
            team_url = f"{self.api_url}/fieldsecurityprofiles({profile_id})/teamprofiles_association/$ref"
            try:
                team_records = self._get_paged(team_url)
                profile.team_ids = [
                    ref.get("@odata.id", "").split("teams(")[1].rstrip(")")
                    for ref in team_records
                    if "teams(" in ref.get("@odata.id", "")
                ]
            except Exception as e:
                self.logger.warning(f"Failed to fetch team assignments for profile {profile.name}: {e}")

            profiles.append(profile)

        return profiles

    def __resolve_table_permissions__(
        self, env: DataverseEnvironment, table_filter: List[str]
    ) -> List[DataverseTablePermission]:
        """
        Resolve effective table-level read permissions for all principals.
        Combines user direct role assignments + team role assignments
        to determine which users/teams can read which tables.
        """
        permissions = []
        role_entity_map = self.__build_role_entity_map__(env.role_privileges, env.security_roles)

        # User direct role assignments
        for user_id, role_ids in env.user_role_assignments.items():
            user = env.lookup_user_by_id(user_id)
            if not user:
                continue
            for role_id in role_ids:
                if role_id not in role_entity_map:
                    continue
                role_name, entities = role_entity_map[role_id]
                for entity_name, depth in entities.items():
                    if table_filter and entity_name not in table_filter:
                        continue
                    permissions.append(
                        DataverseTablePermission(
                            table_name=entity_name,
                            principal_id=user_id,
                            principal_type=IamType.USER,
                            has_read=True,
                            depth=depth,
                            role_name=role_name,
                        )
                    )

        # Team role assignments
        for team_id, role_ids in env.team_role_assignments.items():
            team = env.lookup_team_by_id(team_id)
            if not team:
                continue
            for role_id in role_ids:
                if role_id not in role_entity_map:
                    continue
                role_name, entities = role_entity_map[role_id]
                for entity_name, depth in entities.items():
                    if table_filter and entity_name not in table_filter:
                        continue
                    permissions.append(
                        DataverseTablePermission(
                            table_name=entity_name,
                            principal_id=team_id,
                            principal_type=IamType.GROUP,
                            has_read=True,
                            depth=depth,
                            role_name=role_name,
                        )
                    )

        return permissions

    def __build_role_entity_map__(
        self,
        role_privileges: List[DataverseRolePrivilege],
        security_roles: List[DataverseSecurityRole],
    ) -> Dict[str, tuple]:
        """
        Build a map from role_id -> (role_name, {entity_name: depth}).
        Uses the role_id stored on each privilege to correctly associate
        privileges with their parent security role.
        """
        role_name_map = {r.id: r.name for r in security_roles}
        role_entity_map: Dict[str, tuple] = {}

        for priv in role_privileges:
            if not priv.role_id or not priv.entity_name or not priv.can_read:
                continue
            if priv.role_id not in role_entity_map:
                role_name = role_name_map.get(priv.role_id, "UnknownRole")
                role_entity_map[priv.role_id] = (role_name, {})
            role_entity_map[priv.role_id][1][priv.entity_name] = priv.depth or "Global"

        return role_entity_map
