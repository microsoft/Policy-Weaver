import unittest

from policyweaver.core.enum import IamType
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import DataverseUser


class _FakeEnvironment:
    def __init__(self, users=None):
        self._users = {u.id: u for u in (users or [])}

    def lookup_user_by_id(self, user_id):
        return self._users.get(user_id)

    def lookup_team_by_id(self, team_id):
        return None


class _FakeLogger:
    def warning(self, message):
        return None


class TestDataversePermissionObjectResolution(unittest.TestCase):
    def setUp(self):
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        self.client.logger = _FakeLogger()

    def test_user_without_entra_object_id_is_skipped(self):
        user = DataverseUser(
            id="system-user-1",
            name="System User",
            email="sys@example.com",
            azure_ad_object_id=None,
        )
        self.client.environment = _FakeEnvironment(users=[user])

        resolved = self.client.__resolve_permission_object__("system-user-1", IamType.USER)

        self.assertIsNone(resolved)

    def test_user_with_entra_object_id_is_resolved(self):
        user = DataverseUser(
            id="system-user-2",
            name="Entra User",
            email="entra@example.com",
            azure_ad_object_id="entra-obj-2",
        )
        self.client.environment = _FakeEnvironment(users=[user])

        resolved = self.client.__resolve_permission_object__("system-user-2", IamType.USER)

        self.assertIsNotNone(resolved)
        self.assertEqual("entra-obj-2", resolved.id)
        self.assertEqual("entra-obj-2", resolved.entra_object_id)
        self.assertEqual(IamType.USER, resolved.type)


if __name__ == "__main__":
    unittest.main()
