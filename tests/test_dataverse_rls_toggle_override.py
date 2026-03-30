"""
Tests that row constraints are always emitted for non-Global depths,
regardless of the rowlevelsecurity config toggle.

Dataverse requires row filters for Basic/Local/Deep depths to maintain
access parity. Skipping them would over-grant (expose rows the principal
cannot see in Dataverse). The toggle is effectively a no-op for the
Dataverse connector: Global depths never produce filters, and non-Global
depths always produce filters.
"""

import unittest
import logging

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap,
    DataverseSourceConfig,
    DataverseUser,
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


def _make_config(rls_enabled: bool) -> DataverseSourceMap:
    """Build a minimal DataverseSourceMap with explicit RLS toggle."""
    return DataverseSourceMap(
        source=Source(
            name="TestCatalog",
            schemas=[SourceSchema(name="dbo")],
        ),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        constraints=ConstraintsConfig(
            columns=ColumnConstraintsConfig(columnlevelsecurity=False),
            rows=RowConstraintsConfig(rowlevelsecurity=rls_enabled),
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com"
        ),
    )


def _make_environment(
    depth: str,
    role_bu_id: str = "bu-root",
    principal_bu_id: str = "bu-root",
) -> DataverseEnvironment:
    """Build a minimal environment with one user, one role, one table permission."""
    return DataverseEnvironment(
        users=[
            DataverseUser(
                id="user-1",
                name="Test User",
                email="test@example.com",
                azure_ad_object_id="entra-user-1",
                business_unit_id=principal_bu_id,
            ),
        ],
        teams=[],
        business_units=[
            DataverseBusinessUnit(
                id="bu-root", name="Root BU", parent_business_unit_id=None
            ),
            DataverseBusinessUnit(
                id="bu-child", name="Child BU", parent_business_unit_id="bu-root"
            ),
        ],
        security_roles=[
            DataverseSecurityRole(
                id="role-1", name="TestRole", business_unit_id=role_bu_id
            ),
        ],
        role_privileges=[],
        user_role_assignments={"user-1": ["role-1"]},
        team_role_assignments={},
        field_security_profiles=[],
        table_permissions=[
            DataverseTablePermission(
                table_name="account",
                principal_id="user-1",
                principal_type=IamType.USER,
                principal_business_unit_id=principal_bu_id,
                has_read=True,
                depth=depth,
                role_id="role-1",
                role_name="TestRole",
                role_business_unit_id=role_bu_id,
            ),
        ],
    )


class TestRlsToggleOverride(unittest.TestCase):
    """Row constraints must be emitted for non-Global depths even when the toggle is off."""

    def _build_export(self, rls_enabled: bool, depth: str):
        config = _make_config(rls_enabled=rls_enabled)
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.config = config
        client.logger = logging.getLogger("test_rls_toggle")
        client.environment = _make_environment(depth=depth)
        return client.__build_role_based_export__()

    # --- RLS OFF + non-Global: row constraints MUST still be present ---

    def test_rls_off_local_depth_emits_row_constraint(self):
        export = self._build_export(rls_enabled=False, depth="Local")
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)
        self.assertIn(
            "_owningbusinessunit_value", policy.rowconstraints[0].filter_condition
        )

    def test_rls_off_deep_depth_emits_row_constraint(self):
        export = self._build_export(rls_enabled=False, depth="Deep")
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)
        self.assertIn(
            "_owningbusinessunit_value", policy.rowconstraints[0].filter_condition
        )

    def test_rls_off_basic_depth_emits_row_constraint(self):
        export = self._build_export(rls_enabled=False, depth="Basic")
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)
        self.assertIn("_ownerid_value", policy.rowconstraints[0].filter_condition)

    def test_rls_off_unknown_depth_emits_deny_all_row_constraint(self):
        export = self._build_export(rls_enabled=False, depth="Unknown")
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)
        self.assertEqual("false", policy.rowconstraints[0].filter_condition)

    # --- RLS OFF + Global: no row constraint needed (Global sees all rows) ---

    def test_rls_off_global_depth_no_row_constraint(self):
        export = self._build_export(rls_enabled=False, depth="Global")
        policy = export.policies[0]

        self.assertIsNone(policy.rowconstraints)

    # --- RLS ON: same behavior (row constraints for non-Global, none for Global) ---

    def test_rls_on_local_depth_emits_row_constraint(self):
        export = self._build_export(rls_enabled=True, depth="Local")
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)

    def test_rls_on_global_depth_no_row_constraint(self):
        export = self._build_export(rls_enabled=True, depth="Global")
        policy = export.policies[0]

        self.assertIsNone(policy.rowconstraints)

    # --- No constraints config at all: still produces row constraints ---

    def test_no_constraints_config_local_depth_emits_row_constraint(self):
        config = DataverseSourceMap(
            source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
            fabric=FabricConfig(policy_mapping="role_based"),
            constraints=None,
            dataverse=DataverseSourceConfig(
                environment_url="https://test.crm.dynamics.com"
            ),
        )
        client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        client.config = config
        client.logger = logging.getLogger("test_rls_toggle")
        client.environment = _make_environment(depth="Local")

        export = client.__build_role_based_export__()
        policy = export.policies[0]

        self.assertIsNotNone(policy.rowconstraints)
        self.assertEqual(len(policy.rowconstraints), 1)
        self.assertIn(
            "_owningbusinessunit_value", policy.rowconstraints[0].filter_condition
        )


if __name__ == "__main__":
    unittest.main()
