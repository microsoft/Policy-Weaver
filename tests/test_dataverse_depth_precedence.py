import unittest

from policyweaver.plugins.dataverse.api import DataverseAPIClient
from policyweaver.plugins.dataverse.model import DataverseRolePrivilege, DataverseSecurityRole


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class TestDataverseRoleEntityDepthPrecedence(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ to avoid env and HTTP session requirements.
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)
        self.client.logger = _FakeLogger()

    def _build_role_entity_map(self, privileges, roles):
        return self.client.__build_role_entity_map__(
            role_privileges=privileges,
            security_roles=roles,
        )

    def test_keeps_strongest_depth_when_basic_then_global(self):
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Basic",
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Global",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertIn("role-1", result)
        role_name, role_bu_id, entity_depth_map = result["role-1"]
        self.assertEqual("Sales Reader", role_name)
        self.assertEqual("bu-1", role_bu_id)
        self.assertEqual("Global", entity_depth_map["account"])

    def test_keeps_strongest_depth_when_global_then_basic(self):
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Global",
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Basic",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Global", result["role-1"][2]["account"])

    def test_unknown_depth_normalizes_to_unknown_not_global(self):
        """Missing/null depth should produce 'Unknown' to trigger fail-closed downstream."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Sales Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth=None,
                can_read=True,
            )
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Unknown", result["role-1"][2]["account"])

    def test_unrecognized_depth_string_normalizes_to_unknown(self):
        """Depth values not in Basic/Local/Deep/Global should be treated as Unknown
        after normalization. __build_role_entity_map__ receives already-normalized
        depth values, so we pass 'Unknown' (the output of __normalize_depth__ for
        unrecognized inputs like 'Organization')."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadcontact",
                entity_name="contact",
                depth="Unknown",
                can_read=True,
            )
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        self.assertEqual("Unknown", result["role-1"][2]["contact"])

    def test_known_depth_wins_over_unknown_depth(self):
        """When a role has both Unknown and a valid depth for the same entity, valid depth wins."""
        role = DataverseSecurityRole(
            id="role-1",
            name="Reader",
            business_unit_id="bu-1",
        )
        privileges = [
            DataverseRolePrivilege(
                privilege_id="p1",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth=None,
                can_read=True,
            ),
            DataverseRolePrivilege(
                privilege_id="p2",
                role_id="role-1",
                name="prvReadaccount",
                entity_name="account",
                depth="Local",
                can_read=True,
            ),
        ]

        result = self._build_role_entity_map(privileges=privileges, roles=[role])

        # Local (rank 2) beats Unknown (rank 0)
        self.assertEqual("Local", result["role-1"][2]["account"])

    def test_normalize_depth_converts_unrecognized_string_to_unknown(self):
        """Verify __normalize_depth__ itself returns 'Unknown' for unrecognized values."""
        self.assertEqual("Unknown", self.client.__normalize_depth__("Organization"))
        self.assertEqual("Unknown", self.client.__normalize_depth__("SomeRandomValue"))
        self.assertEqual("Unknown", self.client.__normalize_depth__(99))
        self.assertEqual("Unknown", self.client.__normalize_depth__(None))

    def test_normalize_depth_passes_valid_values_through(self):
        """Known depth values should pass through unchanged."""
        self.assertEqual("Basic", self.client.__normalize_depth__("Basic"))
        self.assertEqual("Local", self.client.__normalize_depth__("local"))
        self.assertEqual("Deep", self.client.__normalize_depth__("DEEP"))
        self.assertEqual("Global", self.client.__normalize_depth__("Global"))
        self.assertEqual("Basic", self.client.__normalize_depth__(0))
        self.assertEqual("Local", self.client.__normalize_depth__(1))
        self.assertEqual("Deep", self.client.__normalize_depth__(2))
        self.assertEqual("Global", self.client.__normalize_depth__(3))


if __name__ == "__main__":
    unittest.main()
