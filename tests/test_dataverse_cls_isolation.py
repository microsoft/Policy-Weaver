"""
Tests for CLS (column-level security) per-principal isolation.

When principals in the same Dataverse role have different field security
profile assignments, a shared Fabric role would grant the union of all
column permissions to every member.  The fix detects CLS divergence and
splits into per-principal Fabric roles so each user sees only their own
allowed columns.
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
    DataverseFieldSecurityProfile,
    DataverseFieldPermission,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(cls_enabled: bool = True) -> DataverseSourceMap:
    return DataverseSourceMap(
        source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=cls_enabled),
            rows=RowConstraintsConfig(rowlevelsecurity=True),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com"
        ),
    )


def _build_client(
    environment: DataverseEnvironment, cls_enabled: bool = True
) -> DataversePolicyWeaver:
    config = _make_config(cls_enabled)
    client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
    client.config = config
    client.logger = logging.getLogger("test_cls_isolation")
    client.environment = environment
    return client


def _build_export(environment: DataverseEnvironment, cls_enabled: bool = True):
    client = _build_client(environment, cls_enabled)
    return client.__build_role_based_export__()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_USERS = [
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
]

_BUS = [DataverseBusinessUnit(id="bu-root", name="Root", parent_business_unit_id=None)]

_ROLES = [
    DataverseSecurityRole(id="role-1", name="Analyst", business_unit_id="bu-root")
]

_TABLE_PERMS_GLOBAL = [
    DataverseTablePermission(
        table_name="account",
        principal_id="user-A",
        principal_type=IamType.USER,
        principal_business_unit_id="bu-root",
        has_read=True,
        depth="Global",
        role_id="role-1",
        role_name="Analyst",
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
        role_name="Analyst",
        role_business_unit_id="bu-root",
    ),
]


def _fsp(
    fsp_id: str,
    name: str,
    user_ids: list,
    team_ids: list,
    entity: str,
    columns: list,
) -> DataverseFieldSecurityProfile:
    """Build a DataverseFieldSecurityProfile with can_read=4 permissions."""
    return DataverseFieldSecurityProfile(
        id=fsp_id,
        name=name,
        user_ids=user_ids,
        team_ids=team_ids,
        permissions=[
            DataverseFieldPermission(
                field_security_profile_id=fsp_id,
                field_security_profile_name=name,
                entity_name=entity,
                attribute_logical_name=col,
                can_read=4,
            )
            for col in columns
        ],
    )


# ---------------------------------------------------------------------------
# Two users with DIFFERENT FSP assignments -> split
# ---------------------------------------------------------------------------


class TestDivergentFspSplitsRoles(unittest.TestCase):
    """Two users in the same Global role with different FSPs must get separate Fabric roles."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[
                _fsp(
                    "fsp-1",
                    "Profile Alpha",
                    ["user-A"],
                    [],
                    "account",
                    ["name", "email"],
                ),
                _fsp(
                    "fsp-2",
                    "Profile Beta",
                    ["user-B"],
                    [],
                    "account",
                    ["name", "phone"],
                ),
            ],
            table_permissions=list(_TABLE_PERMS_GLOBAL),
        )

    def test_two_roles_produced(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_each_role_has_one_member(self) -> None:
        export = _build_export(self.env)
        for policy in export.policies:
            self.assertEqual(len(policy.permissionobjects), 1)

    def test_alice_sees_only_fsp1_columns(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice), 1)
        cols = set()
        for cc in alice[0].columnconstraints:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "email"})
        self.assertNotIn("phone", cols)

    def test_bob_sees_only_fsp2_columns(self) -> None:
        export = _build_export(self.env)
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob), 1)
        cols = set()
        for cc in bob[0].columnconstraints:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "phone"})
        self.assertNotIn("email", cols)

    def test_role_names_include_principal_identity(self) -> None:
        export = _build_export(self.env)
        names = {p.name for p in export.policies}
        self.assertTrue(any("alice@example.com" in n for n in names))
        self.assertTrue(any("bob@example.com" in n for n in names))


# ---------------------------------------------------------------------------
# Two users with SAME FSP assignment -> shared role
# ---------------------------------------------------------------------------


class TestSameFspKeepsSharedRole(unittest.TestCase):
    """Two users sharing the same FSP should produce one shared Fabric role."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[
                _fsp(
                    "fsp-shared",
                    "Shared Profile",
                    ["user-A", "user-B"],
                    [],
                    "account",
                    ["name", "email"],
                ),
            ],
            table_permissions=list(_TABLE_PERMS_GLOBAL),
        )

    def test_one_shared_role_produced(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 1)

    def test_shared_role_has_two_members(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies[0].permissionobjects), 2)


# ---------------------------------------------------------------------------
# CLS divergence with non-Basic depth preserves row constraints
# ---------------------------------------------------------------------------


class TestClsSplitPreservesRowConstraints(unittest.TestCase):
    """CLS split for a Deep-depth role must preserve the BU-based row filter on every split role."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=[
                DataverseBusinessUnit(
                    id="bu-root", name="Root", parent_business_unit_id=None
                ),
                DataverseBusinessUnit(
                    id="bu-child", name="Child", parent_business_unit_id="bu-root"
                ),
            ],
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name"]),
                _fsp("fsp-2", "Beta", ["user-B"], [], "account", ["phone"]),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Deep",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-B",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Deep",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_two_roles_produced(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_each_role_has_row_constraint(self) -> None:
        export = _build_export(self.env)
        for policy in export.policies:
            self.assertIsNotNone(policy.rowconstraints)
            self.assertTrue(len(policy.rowconstraints) > 0)

    def test_row_filter_is_deep_bu_filter(self) -> None:
        export = _build_export(self.env)
        for policy in export.policies:
            filt = policy.rowconstraints[0].filter_condition
            self.assertIn("_owningbusinessunit_value", filt)
            self.assertIn("bu-root", filt)


# ---------------------------------------------------------------------------
# Single user - no divergence possible, keep shared role
# ---------------------------------------------------------------------------


class TestSingleUserNoDivergence(unittest.TestCase):
    """A role with one user and CLS enabled should not split."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=[_USERS[0]],
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name"]),
            ],
            table_permissions=[_TABLE_PERMS_GLOBAL[0]],
        )

    def test_one_role_produced(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 1)

    def test_has_column_constraints(self) -> None:
        export = _build_export(self.env)
        self.assertIsNotNone(export.policies[0].columnconstraints)


# ---------------------------------------------------------------------------
# CLS disabled skips divergence check
# ---------------------------------------------------------------------------


class TestClsDisabledNoDivergenceCheck(unittest.TestCase):
    """When CLS is disabled in config, divergent FSPs should not cause splitting."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"], "user-B": ["role-1"]},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name"]),
                _fsp("fsp-2", "Beta", ["user-B"], [], "account", ["phone"]),
            ],
            table_permissions=list(_TABLE_PERMS_GLOBAL),
        )

    def test_one_shared_role_when_cls_off(self) -> None:
        export = _build_export(self.env, cls_enabled=False)
        self.assertEqual(len(export.policies), 1)

    def test_no_column_constraints_when_cls_off(self) -> None:
        export = _build_export(self.env, cls_enabled=False)
        self.assertIsNone(export.policies[0].columnconstraints)


# ---------------------------------------------------------------------------
# Owner team expanded in CLS split
# ---------------------------------------------------------------------------


class TestOwnerTeamExpandedInClsSplit(unittest.TestCase):
    """An owner team with divergent FSP from a direct user must expand members."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-X",
                    name="SupportTeam",
                    team_type=0,
                    azure_ad_object_id=None,
                    business_unit_id="bu-root",
                    member_ids=["user-B"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={"team-X": ["role-1"]},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name", "email"]),
                _fsp("fsp-2", "Beta", ["user-B"], [], "account", ["name", "phone"]),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="account",
                    principal_id="team-X",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_two_roles_after_team_expansion(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_each_expanded_role_has_one_member(self) -> None:
        export = _build_export(self.env)
        for p in export.policies:
            self.assertEqual(len(p.permissionobjects), 1)

    def test_alice_gets_fsp1_columns(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice), 1)
        cols = set()
        for cc in alice[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "email"})

    def test_bob_gets_fsp2_columns(self) -> None:
        export = _build_export(self.env)
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob), 1)
        cols = set()
        for cc in bob[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "phone"})


# ---------------------------------------------------------------------------
# Divergence detection helper direct tests
# ---------------------------------------------------------------------------


class TestDivergenceDetectionDirect(unittest.TestCase):
    """Direct unit tests for __principals_have_divergent_cls__."""

    def test_divergent_returns_true(self) -> None:
        env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "P1", ["user-A"], [], "account", ["name"]),
                _fsp("fsp-2", "P2", ["user-B"], [], "account", ["phone"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("user-A", IamType.USER), ("user-B", IamType.USER)}
        # Dunder methods (double leading + double trailing underscores)
        # are NOT name-mangled by Python, so access directly.
        self.assertTrue(client.__principals_have_divergent_cls__(principals))

    def test_same_profiles_returns_false(self) -> None:
        env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-shared", "P1", ["user-A", "user-B"], [], "account", ["name"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("user-A", IamType.USER), ("user-B", IamType.USER)}
        self.assertFalse(client.__principals_have_divergent_cls__(principals))

    def test_single_principal_returns_false(self) -> None:
        env = DataverseEnvironment(
            users=[_USERS[0]],
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "P1", ["user-A"], [], "account", ["name"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("user-A", IamType.USER)}
        self.assertFalse(client.__principals_have_divergent_cls__(principals))

    def test_no_profiles_not_divergent(self) -> None:
        env = DataverseEnvironment(
            users=_USERS,
            teams=[],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("user-A", IamType.USER), ("user-B", IamType.USER)}
        self.assertFalse(client.__principals_have_divergent_cls__(principals))

    def test_team_fsp_coverage_via_member_expansion(self) -> None:
        """Profile assigned to team-X covers user-A (member).  User-B has fsp-2.  Divergent."""
        env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-X",
                    name="T",
                    team_type=0,
                    azure_ad_object_id=None,
                    business_unit_id="bu-root",
                    member_ids=["user-A"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "P1", [], ["team-X"], "account", ["name"]),
                _fsp("fsp-2", "P2", ["user-B"], [], "account", ["phone"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("user-A", IamType.USER), ("user-B", IamType.USER)}
        self.assertTrue(client.__principals_have_divergent_cls__(principals))

    def test_aad_group_principal_expanded_to_members(self) -> None:
        """An AAD-backed GROUP principal must be expanded to member user IDs for matching."""
        env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-AAD",
                    name="AAD Team",
                    team_type=2,
                    azure_ad_object_id="entra-team-AAD",
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-1", "P1", ["user-A"], [], "account", ["name"]),
                _fsp("fsp-2", "P2", ["user-B"], [], "account", ["phone"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        # The principal is the AAD group itself — divergence detection must
        # expand to member user IDs to find the profile mismatch.
        principals = {("team-AAD", IamType.GROUP)}
        self.assertTrue(client.__principals_have_divergent_cls__(principals))

    def test_aad_group_same_fsp_not_divergent(self) -> None:
        """AAD group whose members share the same FSP should not be divergent."""
        env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-AAD",
                    name="AAD Team",
                    team_type=2,
                    azure_ad_object_id="entra-team-AAD",
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={},
            field_security_profiles=[
                _fsp("fsp-shared", "P1", ["user-A", "user-B"], [], "account", ["name"]),
            ],
            table_permissions=[],
        )
        client = _build_client(env)
        principals = {("team-AAD", IamType.GROUP)}
        self.assertFalse(client.__principals_have_divergent_cls__(principals))


# ---------------------------------------------------------------------------
# Single AAD-backed group with divergent member FSPs -> must split
# ---------------------------------------------------------------------------


class TestSingleAadGroupDivergentMembers(unittest.TestCase):
    """A role with a single AAD-backed group whose members have different FSPs
    must split into per-member Fabric roles.  OneLake applies one role policy
    to all group members, so per-member CLS differences require splitting."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-AAD",
                    name="AAD Security Team",
                    team_type=2,
                    azure_ad_object_id="entra-team-AAD",
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={"team-AAD": ["role-1"]},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name", "email"]),
                _fsp("fsp-2", "Beta", ["user-B"], [], "account", ["name", "phone"]),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="team-AAD",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_single_group_splits_into_per_member_roles(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 2)

    def test_each_role_is_individual_user(self) -> None:
        export = _build_export(self.env)
        for p in export.policies:
            self.assertEqual(len(p.permissionobjects), 1)
            self.assertEqual(p.permissionobjects[0].type, IamType.USER)

    def test_alice_sees_only_fsp1_columns(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice), 1)
        cols = set()
        for cc in alice[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "email"})

    def test_bob_sees_only_fsp2_columns(self) -> None:
        export = _build_export(self.env)
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob), 1)
        cols = set()
        for cc in bob[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "phone"})


# ---------------------------------------------------------------------------
# AAD-backed group with uniform FSPs -> shared role, group kept
# ---------------------------------------------------------------------------


class TestAadGroupSameFspKeepsGroup(unittest.TestCase):
    """A single AAD-backed group whose members share the same FSP should
    produce one shared Fabric role with the group as a GROUP PermissionObject."""

    def setUp(self) -> None:
        self.env = DataverseEnvironment(
            users=_USERS,
            teams=[
                DataverseTeam(
                    id="team-AAD",
                    name="AAD Team",
                    team_type=2,
                    azure_ad_object_id="entra-team-AAD",
                    business_unit_id="bu-root",
                    member_ids=["user-A", "user-B"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={},
            team_role_assignments={"team-AAD": ["role-1"]},
            field_security_profiles=[
                _fsp(
                    "fsp-shared",
                    "Shared",
                    ["user-A", "user-B"],
                    [],
                    "account",
                    ["name"],
                ),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="team-AAD",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_one_shared_role_produced(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 1)

    def test_role_member_is_group(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(export.policies[0].permissionobjects[0].type, IamType.GROUP)
        self.assertEqual(
            export.policies[0].permissionobjects[0].entra_object_id, "entra-team-AAD"
        )


# ---------------------------------------------------------------------------
# AAD group + user with divergent CLS -> all expanded
# ---------------------------------------------------------------------------


class TestAadGroupPlusUserDivergent(unittest.TestCase):
    """An AAD group and a direct user with divergent FSPs must both expand
    to individual per-member roles."""

    def setUp(self) -> None:
        self.users = [
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
            DataverseUser(
                id="user-C",
                name="Carol",
                email="carol@example.com",
                azure_ad_object_id="entra-C",
                business_unit_id="bu-root",
            ),
        ]
        self.env = DataverseEnvironment(
            users=self.users,
            teams=[
                DataverseTeam(
                    id="team-AAD",
                    name="AAD Support",
                    team_type=2,
                    azure_ad_object_id="entra-team-AAD",
                    business_unit_id="bu-root",
                    member_ids=["user-B", "user-C"],
                ),
            ],
            business_units=_BUS,
            security_roles=_ROLES,
            role_privileges=[],
            user_role_assignments={"user-A": ["role-1"]},
            team_role_assignments={"team-AAD": ["role-1"]},
            field_security_profiles=[
                _fsp("fsp-1", "Alpha", ["user-A"], [], "account", ["name", "email"]),
                _fsp(
                    "fsp-2",
                    "Beta",
                    ["user-B", "user-C"],
                    [],
                    "account",
                    ["name", "phone"],
                ),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="user-A",
                    principal_type=IamType.USER,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
                DataverseTablePermission(
                    table_name="account",
                    principal_id="team-AAD",
                    principal_type=IamType.GROUP,
                    principal_business_unit_id="bu-root",
                    has_read=True,
                    depth="Global",
                    role_id="role-1",
                    role_name="Analyst",
                    role_business_unit_id="bu-root",
                ),
            ],
        )

    def test_three_per_user_roles(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies), 3)

    def test_all_roles_are_individual_users(self) -> None:
        export = _build_export(self.env)
        for p in export.policies:
            self.assertEqual(len(p.permissionobjects), 1)
            self.assertEqual(p.permissionobjects[0].type, IamType.USER)

    def test_alice_gets_fsp1_columns(self) -> None:
        export = _build_export(self.env)
        alice = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-A"
        ]
        self.assertEqual(len(alice), 1)
        cols = set()
        for cc in alice[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "email"})

    def test_bob_gets_fsp2_columns(self) -> None:
        export = _build_export(self.env)
        bob = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-B"
        ]
        self.assertEqual(len(bob), 1)
        cols = set()
        for cc in bob[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "phone"})

    def test_carol_gets_fsp2_columns(self) -> None:
        export = _build_export(self.env)
        carol = [
            p
            for p in export.policies
            if p.permissionobjects[0].entra_object_id == "entra-C"
        ]
        self.assertEqual(len(carol), 1)
        cols = set()
        for cc in carol[0].columnconstraints or []:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"name", "phone"})


# ---------------------------------------------------------------------------
# Shared-path CLS: AAD-backed team-only principals
# ---------------------------------------------------------------------------


class TestSharedPathAadTeamOnlyCls(unittest.TestCase):
    """When a non-divergent role's only principal is an AAD-backed team,
    __get_column_constraints_for_principals__ must expand the team to
    member IDs so profile coverage is found.  Before the fix the team
    GUID didn't match any profile_principals and CLS was silently dropped."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="u1",
                    name="Alice",
                    email="alice@test.com",
                    azure_ad_object_id="entra-A",
                ),
                DataverseUser(
                    id="u2",
                    name="Bob",
                    email="bob@test.com",
                    azure_ad_object_id="entra-B",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-aad",
                    name="AAD Team",
                    team_type=2,
                    azure_ad_object_id="entra-group-1",
                    member_ids=["u1", "u2"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu1", name="Root BU", parent_business_unit_id=None
                ),
            ],
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="fsp1",
                    name="SharedFSP",
                    user_ids=["u1", "u2"],
                    team_ids=[],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="account",
                            attribute_logical_name="revenue",
                            can_read=4,
                        ),
                    ],
                ),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="account",
                    principal_id="team-aad",
                    principal_type=IamType.GROUP,
                    role_id="role1",
                    role_name="SalesRole",
                    role_business_unit_id="bu1",
                    depth="Deep",
                    privilege_depth_mask=4,
                ),
            ],
        )

    def test_shared_role_has_column_constraints(self) -> None:
        """The shared role must have CLS — not silently dropped."""
        export = _build_export(self.env)
        self.assertIsNotNone(export)
        self.assertEqual(len(export.policies), 1)
        self.assertIsNotNone(export.policies[0].columnconstraints)
        self.assertTrue(len(export.policies[0].columnconstraints) > 0)

    def test_shared_role_grants_correct_column(self) -> None:
        export = _build_export(self.env)
        cols = set()
        for cc in export.policies[0].columnconstraints:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"revenue"})

    def test_shared_role_member_is_group(self) -> None:
        """Non-divergent AAD team stays as GROUP in the shared role."""
        export = _build_export(self.env)
        po = export.policies[0].permissionobjects[0]
        self.assertEqual(po.type, IamType.GROUP)
        self.assertEqual(po.id, "entra-group-1")


class TestSharedPathAadTeamFspViaTeamId(unittest.TestCase):
    """FSP assigned via team_ids (not user_ids).
    The team GUID appears in profile.team_ids; the method must still
    expand the role's GROUP principal to match through member_ids."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="u1",
                    name="Alice",
                    email="alice@test.com",
                    azure_ad_object_id="entra-A",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-aad",
                    name="AAD Team",
                    team_type=3,
                    azure_ad_object_id="entra-group-1",
                    member_ids=["u1"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu1", name="Root BU", parent_business_unit_id=None
                ),
            ],
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="fsp1",
                    name="TeamFSP",
                    user_ids=[],
                    team_ids=["team-aad"],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="contact",
                            attribute_logical_name="email",
                            can_read=4,
                        ),
                    ],
                ),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="contact",
                    principal_id="team-aad",
                    principal_type=IamType.GROUP,
                    role_id="role1",
                    role_name="ServiceRole",
                    role_business_unit_id="bu1",
                    depth="Local",
                    privilege_depth_mask=2,
                ),
            ],
        )

    def test_team_assigned_fsp_produces_column_constraints(self) -> None:
        export = _build_export(self.env)
        self.assertIsNotNone(export)
        self.assertEqual(len(export.policies), 1)
        self.assertIsNotNone(export.policies[0].columnconstraints)

    def test_team_assigned_fsp_grants_correct_column(self) -> None:
        export = _build_export(self.env)
        cols = set()
        for cc in export.policies[0].columnconstraints:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"email"})


class TestSharedPathMixedUserAndAadTeamCls(unittest.TestCase):
    """Shared role with both a direct user and an AAD-backed team,
    same FSP coverage. Both principals' member IDs must be expanded
    to find their common profile."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = DataverseEnvironment(
            users=[
                DataverseUser(
                    id="u1",
                    name="Alice",
                    email="alice@test.com",
                    azure_ad_object_id="entra-A",
                ),
                DataverseUser(
                    id="u2",
                    name="Bob",
                    email="bob@test.com",
                    azure_ad_object_id="entra-B",
                ),
            ],
            teams=[
                DataverseTeam(
                    id="team-aad",
                    name="AAD Team",
                    team_type=2,
                    azure_ad_object_id="entra-group-1",
                    member_ids=["u2"],
                ),
            ],
            business_units=[
                DataverseBusinessUnit(
                    id="bu1", name="Root BU", parent_business_unit_id=None
                ),
            ],
            field_security_profiles=[
                DataverseFieldSecurityProfile(
                    id="fsp1",
                    name="CommonFSP",
                    user_ids=["u1", "u2"],
                    team_ids=[],
                    permissions=[
                        DataverseFieldPermission(
                            entity_name="lead",
                            attribute_logical_name="score",
                            can_read=4,
                        ),
                    ],
                ),
            ],
            table_permissions=[
                DataverseTablePermission(
                    table_name="lead",
                    principal_id="u1",
                    principal_type=IamType.USER,
                    role_id="role1",
                    role_name="LeadRole",
                    role_business_unit_id="bu1",
                    depth="Global",
                    privilege_depth_mask=8,
                ),
                DataverseTablePermission(
                    table_name="lead",
                    principal_id="team-aad",
                    principal_type=IamType.GROUP,
                    role_id="role1",
                    role_name="LeadRole",
                    role_business_unit_id="bu1",
                    depth="Global",
                    privilege_depth_mask=8,
                ),
            ],
        )

    def test_shared_role_has_cls(self) -> None:
        export = _build_export(self.env)
        self.assertIsNotNone(export)
        self.assertEqual(len(export.policies), 1)
        self.assertIsNotNone(export.policies[0].columnconstraints)

    def test_shared_role_grants_score_column(self) -> None:
        export = _build_export(self.env)
        cols = set()
        for cc in export.policies[0].columnconstraints:
            cols.update(cc.column_names)
        self.assertEqual(cols, {"score"})

    def test_shared_role_has_two_members(self) -> None:
        export = _build_export(self.env)
        self.assertEqual(len(export.policies[0].permissionobjects), 2)


if __name__ == "__main__":
    unittest.main()
