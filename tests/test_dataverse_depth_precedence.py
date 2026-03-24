import unittest

from policyweaver.plugins.dataverse.api import DataverseAPIClient
from policyweaver.plugins.dataverse.model import DataverseRolePrivilege, DataverseSecurityRole


class TestDataverseRoleEntityDepthPrecedence(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ to avoid env and HTTP session requirements.
        self.client = DataverseAPIClient.__new__(DataverseAPIClient)

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

    def test_defaults_unknown_or_missing_depth_to_global(self):
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

        self.assertEqual("Global", result["role-1"][2]["account"])


if __name__ == "__main__":
    unittest.main()
