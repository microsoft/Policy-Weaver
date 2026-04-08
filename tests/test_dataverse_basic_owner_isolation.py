"""
Tests for Basic-depth per-principal role splitting (owner isolation).

Basic depth in Dataverse means "see rows you own".  Fabric Data Access Roles
apply the same row filter to every member, so a shared role with
_ownerid_value in ('A','B') would let both A and B see each other's rows.

The fix splits Basic-depth roles into per-principal Fabric roles where each
user's filter contains only their own ownership scope (their Dataverse user ID
plus the IDs of teams they belong to within that role).
"""

import unittest
import logging

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap,
    DataverseSourceConfig,
    DataverseUser,
    DataverseTeam,
    DataverseTablePermission,
    DataverseEnvironment,
    DataverseBusinessUnit,
    DataverseSecurityRole,
)
from policyweaver.models.config import (
    Source,
    SourceSchema,
    ConstraintsConfig,
    RowConstraintsConfig,
    ColumnConstraintsConfig,
    FabricConfig,
)
from policyweaver.core.enum import IamType


def _make_config() -> DataverseSourceMap:
    return DataverseSourceMap(
        source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=False),
            rows=RowConstraintsConfig(rowlevelsecurity=True),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com"
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_client(environment: DataverseEnvironment) -> DataversePolicyWeaver:
    """Construct a DataversePolicyWeaver wired to a fake environment."""
    config = _make_config()
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.logger = logging.getLogger("test_basic_owner_isolation")
    client.environment = environment
    return client


def _build_export(environment: DataverseEnvironment):
    """Build a role-based export from the given environment."""
    client = _build_client(environment)
    return client.__build_role_based_export__()


# ---------------------------------------------------------------------------
# Two direct users sharing a role with Basic depth
# ---------------------------------------------------------------------------


class TestBasicDepthTwoDirectUsers(unittest.TestCase):
    """Two users with the same role at Basic depth must get separate Fabric roles."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
                DataverseUser(
                    id="user-B",
                    name="Bob",
                    email="bob@example.com",
                    azure_ad_object_id="entra-B",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="SalesRep", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-B",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_two_users_produce_two_separate_roles(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_each_role_has_exactly_one_member(self) -> None:
        export = _build_export(self.env)
        for policy in export.policies:
            self.assertEqual(len(policy.permissionobjects), 1)

    def test_alice_filter_contains_only_alice(self) -> None:
        export = _build_export(self.env)
        alice_policy = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice_policy), 1)
        filt = alice_policy[0].rowconstraints[0].filter_condition
        self.assertIn("user-A", filt)
        self.assertNotIn("user-B", filt)

    def test_bob_filter_contains_only_bob(self) -> None:
        export = _build_export(self.env)
        bob_policy = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob_policy), 1)
        filt = bob_policy[0].rowconstraints[0].filter_condition
        self.assertIn("user-B", filt)
        self.assertNotIn("user-A", filt)

    def test_role_names_include_principal_identity(self) -> None:
        export = _build_export(self.env)
        names = {p.name for p in export.policies}
        self.assertTrue(any("alice@example.com" in n for n in names))
        self.assertTrue(any("bob@example.com" in n for n in names))


# ---------------------------------------------------------------------------
# User + AAD-backed team sharing a role with Basic depth
# ---------------------------------------------------------------------------


class TestBasicDepthUserAndAadTeam(unittest.TestCase):
    """
    User A has role directly.  AAD-backed Team X (members A, B) also has the role.
    Both are Basic depth.  Team must be expanded to members; each user gets their
    own ownership scope.
    """

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
                DataverseUser(
                    id="user-B",
                    name="Bob",
                    email="bob@example.com",
                    azure_ad_object_id="entra-B",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-X",
                    name="Support Team",
                    team_type=2,
                    azure_ad_object_id="entra-team-X",
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="SalesRep", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={"team-X": ["role-1"]},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="team-X",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_aad_team_expanded_to_individual_roles(self) -> None:
        """AAD team must be expanded to per-member roles for Basic depth."""
        export = _build_export(self.env)
        # Alice (direct + via team) and Bob (via team) → 2 roles
        self.assertEqual(len(export.policies), 2)

    def test_alice_ownership_includes_own_id_and_team(self) -> None:
        """Alice (direct + team member) should see her records and team-owned records."""
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice), 1)
        filt = alice[0].rowconstraints[0].filter_condition
        self.assertIn("user-A", filt)
        self.assertIn("team-X", filt)
        self.assertNotIn("user-B", filt)

    def test_bob_ownership_includes_own_id_and_team(self) -> None:
        """Bob (team member only) should see his records and team-owned records."""
        export = _build_export(self.env)
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob), 1)
        filt = bob[0].rowconstraints[0].filter_condition
        self.assertIn("user-B", filt)
        self.assertIn("team-X", filt)
        self.assertNotIn("user-A", filt)


# ---------------------------------------------------------------------------
# Owner team (type 0) sharing a role with Basic depth
# ---------------------------------------------------------------------------


class TestBasicDepthOwnerTeam(unittest.TestCase):
    """Owner team members must be expanded and each gets their own ownership scope."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
                DataverseUser(
                    id="user-B",
                    name="Bob",
                    email="bob@example.com",
                    azure_ad_object_id="entra-B",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-O",
                    name="Owner Team",
                    team_type=0,
                    azure_ad_object_id=None,
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="CaseWorker", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={"team-O": ["role-1"]},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="team-O",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="CaseWorker",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_owner_team_produces_per_member_roles(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_alice_sees_own_and_team_records(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        filt = alice[0].rowconstraints[0].filter_condition
        self.assertIn("user-A", filt)
        self.assertIn("team-O", filt)
        self.assertNotIn("user-B", filt)


# ---------------------------------------------------------------------------
# Single user → no split needed, but still per-principal
# ---------------------------------------------------------------------------


class TestBasicDepthSingleUser(unittest.TestCase):
    """A single user with Basic depth produces one role with owner-only filter."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="SalesRep", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_single_user_produces_one_role(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 1)

    def test_filter_contains_only_owner(self) -> None:
        export = _build_export(self.env)
        filt = export.policies[0].rowconstraints[0].filter_condition
        self.assertEqual(filt, "_ownerid_value in ('user-A')")


# ---------------------------------------------------------------------------
# Non-Basic depth role is NOT split
# ---------------------------------------------------------------------------


class TestNonBasicDepthNotSplit(unittest.TestCase):
    """Global/Deep/Local roles must remain shared — no per-principal splitting."""

    def _make_env(self, depth: str) -> DataverseEnvironment:
        return DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
                DataverseUser(
                    id="user-B",
                    name="Bob",
                    email="bob@example.com",
                    azure_ad_object_id="entra-B",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="Reader", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth=depth,
                    role_id="role-1",
                    role_name="Reader",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-B",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth=depth,
                    role_id="role-1",
                    role_name="Reader",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_global_depth_produces_one_shared_role(self) -> None:
        export = _build_export(self._make_env("Global"))
        self.assertEqual(len(export.policies), 1)
        self.assertEqual(len(export.policies[0].permissionobjects), 2)

    def test_local_depth_produces_one_shared_role(self) -> None:
        export = _build_export(self._make_env("Local"))
        self.assertEqual(len(export.policies), 1)
        self.assertEqual(len(export.policies[0].permissionobjects), 2)

    def test_deep_depth_produces_one_shared_role(self) -> None:
        export = _build_export(self._make_env("Deep"))
        self.assertEqual(len(export.policies), 1)
        self.assertEqual(len(export.policies[0].permissionobjects), 2)


# ---------------------------------------------------------------------------
# Mixed depth: role with Basic on one table and Global on another
# ---------------------------------------------------------------------------


class TestMixedDepthRole(unittest.TestCase):
    """
    When a role has Basic depth on one table and Global on another,
    the entire role is split into per-principal roles.  Global tables get
    identical (no-filter) treatment in each per-principal role.
    """

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
                DataverseUser(
                    id="user-B",
                    name="Bob",
                    email="bob@example.com",
                    azure_ad_object_id="entra-B",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="MixedRole", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[],
            table_permissions=[
                # Basic on incident
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="MixedRole",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-B",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="MixedRole",
                    role_business_unit_id="bu-root",
                ),
                # Global on account
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="MixedRole",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-B",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="MixedRole",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_mixed_role_splits_into_per_principal(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_global_table_has_no_row_constraint(self) -> None:
        """Global-depth account table should produce no row filter in either per-principal role."""
        export = _build_export(self.env)
        for policy in export.policies:
            # Row constraints exist only for incident (Basic), not account (Global)
            if policy.rowconstraints:
                for rc in policy.rowconstraints:
                    self.assertEqual(rc.table_name, "incident")

    def test_basic_table_has_per_principal_filter(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]

        alice_filt = [
            rc for rc in alice[0].rowconstraints if rc.table_name == "incident"
        ][0]
        bob_filt = [rc for rc in bob[0].rowconstraints if rc.table_name == "incident"][
            0
        ]

        self.assertIn("user-A", alice_filt.filter_condition)
        self.assertNotIn("user-B", alice_filt.filter_condition)

        self.assertIn("user-B", bob_filt.filter_condition)
        self.assertNotIn("user-A", bob_filt.filter_condition)

    def test_both_roles_have_both_table_scopes(self) -> None:
        """Each per-principal role should still grant access to both tables."""
        export = _build_export(self.env)
        for policy in export.policies:
            table_names = {ps.table for ps in policy.permissionscopes}
            self.assertIn("incident", table_names)
            self.assertIn("account", table_names)


# ---------------------------------------------------------------------------
# Deduplication: user appears both directly and via team
# ---------------------------------------------------------------------------


class TestBasicDeduplication(unittest.TestCase):
    """A user present both directly and via team membership must not get duplicate roles."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="user-A",
                    name="Alice",
                    email="alice@example.com",
                    azure_ad_object_id="entra-A",
                    business_unit_id="bu-root",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-X",
                    name="Team X",
                    team_type=2,
                    azure_ad_object_id="entra-team-X",
                    business_unit_id="bu-root",
                    member_ids=["user-A"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
            ],
            security_roles=[
                DataverseSecurityRole(
                    id="role-1", name="SalesRep", business_unit_id="bu-root"
                ),
            ],
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={"team-X": ["role-1"]},
            field_security_profiles=[],
            table_permissions=[
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="incident",
                    principal_id="team-X",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Basic",
                    role_id="role-1",
                    role_name="SalesRep",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_user_in_both_direct_and_team_produces_one_role(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 1)
        self.assertEqual(
            export.policies[0].permissionobjects[0].entra_object_id, "entra-A"
        )

    def test_deduped_ownership_includes_team(self) -> None:
        export = _build_export(self.env)
        filt = export.policies[0].rowconstraints[0].filter_condition
        self.assertIn("user-A", filt)
        self.assertIn("team-X", filt)


if __name__ == "__main__":
    unittest.main()
