import unittest

from policyweaver.core.enum import IamType
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import DataverseUser, DataverseTeam


class _FakeEnvironment:
    def __init__(self, users=None, teams=None):
        self._users = {u.id: u for u in (users or [])}
        self._teams = {t.id: t for t in (teams or [])}

    def lookup_user_by_id(self, user_id):
        return self._users.get(user_id)

    def lookup_team_by_id(self, team_id):
        return self._teams.get(team_id)


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class TestDataversePermissionObjectResolution(unittest.TestCase):
    def setUp(self):
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        self.client.logger = _FakeLogger()

    def test_user_without_entra_object_id_returns_empty_list(self):
        user = DataverseUser(
            id="system-user-1",
            name="System User",
            email="sys@example.com",
            azure_ad_object_id=None,
        )
        self.client.environment = _FakeEnvironment(users=[user])

        resolved = self.client.__resolve_permission_object__(
            "system-user-1", IamType.USER
        )

        self.assertEqual(resolved, [])

    def test_user_with_entra_object_id_returns_single_item_list(self):
        user = DataverseUser(
            id="system-user-2",
            name="Entra User",
            email="entra@example.com",
            azure_ad_object_id="entra-obj-2",
        )
        self.client.environment = _FakeEnvironment(users=[user])

        resolved = self.client.__resolve_permission_object__(
            "system-user-2", IamType.USER
        )

        self.assertEqual(len(resolved), 1)
        self.assertEqual("entra-obj-2", resolved[0].id)
        self.assertEqual("entra-obj-2", resolved[0].entra_object_id)
        self.assertEqual(IamType.USER, resolved[0].type)

    def test_aad_backed_team_returns_group_object(self):
        team = DataverseTeam(
            id="team-aad-1",
            name="AAD Team",
            team_type=2,
            azure_ad_object_id="entra-group-1",
        )
        self.client.environment = _FakeEnvironment(teams=[team])

        resolved = self.client.__resolve_permission_object__(
            "team-aad-1", IamType.GROUP
        )

        self.assertEqual(len(resolved), 1)
        self.assertEqual("entra-group-1", resolved[0].id)
        self.assertEqual(IamType.GROUP, resolved[0].type)
        self.assertEqual("entra-group-1", resolved[0].entra_object_id)

    def test_owner_team_single_member_expands_to_user(self):
        user = DataverseUser(
            id="user-in-team",
            name="Team Member",
            email="member@example.com",
            azure_ad_object_id="entra-member-1",
        )
        team = DataverseTeam(
            id="team-owner-1",
            name="Owner Team",
            team_type=0,
            azure_ad_object_id=None,
            member_ids=["user-in-team"],
        )
        self.client.environment = _FakeEnvironment(users=[user], teams=[team])

        resolved = self.client.__resolve_permission_object__(
            "team-owner-1", IamType.GROUP
        )

        self.assertEqual(len(resolved), 1)
        self.assertEqual("entra-member-1", resolved[0].id)
        self.assertEqual(IamType.USER, resolved[0].type)

    def test_owner_team_multiple_members_expands_to_all_users(self):
        user1 = DataverseUser(
            id="user-a",
            name="A",
            email="a@test.com",
            azure_ad_object_id="entra-a",
        )
        user2 = DataverseUser(
            id="user-b",
            name="B",
            email="b@test.com",
            azure_ad_object_id="entra-b",
        )
        team = DataverseTeam(
            id="team-owner-2",
            name="Multi Owner Team",
            team_type=0,
            azure_ad_object_id=None,
            member_ids=["user-a", "user-b"],
        )
        self.client.environment = _FakeEnvironment(users=[user1, user2], teams=[team])

        resolved = self.client.__resolve_permission_object__(
            "team-owner-2", IamType.GROUP
        )

        self.assertEqual(len(resolved), 2)
        entra_ids = {po.id for po in resolved}
        self.assertEqual(entra_ids, {"entra-a", "entra-b"})
        self.assertTrue(all(po.type == IamType.USER for po in resolved))

    def test_owner_team_no_resolvable_members_returns_empty_with_warning(self):
        user_no_entra = DataverseUser(
            id="user-no-entra",
            name="No Entra",
            email="none@test.com",
            azure_ad_object_id=None,
        )
        team = DataverseTeam(
            id="team-empty-1",
            name="Empty Team",
            team_type=0,
            azure_ad_object_id=None,
            member_ids=["user-no-entra"],
        )
        self.client.environment = _FakeEnvironment(users=[user_no_entra], teams=[team])

        resolved = self.client.__resolve_permission_object__(
            "team-empty-1", IamType.GROUP
        )

        self.assertEqual(resolved, [])
        self.assertTrue(
            any(
                "Empty Team" in w and "no resolvable Entra identities" in w
                for w in self.client.logger.warnings
            )
        )

    def test_unknown_principal_type_returns_empty_list(self):
        self.client.environment = _FakeEnvironment()

        resolved = self.client.__resolve_permission_object__(
            "unknown-id", IamType.SERVICE_PRINCIPAL
        )

        self.assertEqual(resolved, [])


if __name__ == "__main__":
    unittest.main()
