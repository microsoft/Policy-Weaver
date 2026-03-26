import unittest
from unittest.mock import MagicMock

from policyweaver.core.enum import IamType
from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseEnvironment,
    DataverseTablePermission,
    DataverseTeam,
    DataverseUser,
)


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class TestDataverseDedupeScenarios(unittest.TestCase):
    """
    Test dedupe behavior in permission object building.
    Dedupe by Entra ID occurs when the same principal (or multiple teams with same member)
    resolve to the same Entra object ID.
    """

    def setUp(self):
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        self.client.logger = _FakeLogger()

    def test_user_in_two_teams_dedupes_by_entra_id_in_table_export(self):
        """
        Scenario: User is member of two separate owner teams.
        Both teams have permissions on the same table.
        Expected: User appears once in permission objects (dedupe by Entra ID).
        """
        # Setup: User with Entra ID
        user = DataverseUser(
            id="user-alice",
            name="Alice",
            email="alice@example.com",
            azure_ad_object_id="entra-alice",
        )

        # Setup: Two owner teams, both with same user as member
        team1 = DataverseTeam(
            id="team-sales",
            name="Sales Team",
            team_type=0,  # Owner team
            azure_ad_object_id=None,
            member_ids=["user-alice"],
        )
        team2 = DataverseTeam(
            id="team-support",
            name="Support Team",
            team_type=0,  # Owner team
            azure_ad_object_id=None,
            member_ids=["user-alice"],
        )

        # Setup: Permissions from both teams on same table
        perms = [
            DataverseTablePermission(
                table_name="incident",
                principal_id="team-sales",
                principal_type=IamType.GROUP,
            ),
            DataverseTablePermission(
                table_name="incident",
                principal_id="team-support",
                principal_type=IamType.GROUP,
            ),
        ]

        self.client.environment = DataverseEnvironment(
            users=[user],
            teams=[team1, team2],
        )

        # Execute: Build permission objects from table permissions
        permission_objects = self.client.__build_permission_objects__(perms)

        # Assert: Only one Alice despite being in two teams (dedupe by Entra ID)
        self.assertEqual(len(permission_objects), 1)
        self.assertEqual(permission_objects[0].id, "entra-alice")
        self.assertEqual(permission_objects[0].type, IamType.USER)

    def test_user_direct_and_via_team_dedupes_by_entra_id(self):
        """
        Scenario: User is assigned directly via permission AND is member of team also with permission.
        Expected: User appears once (dedupe by Entra ID).
        """
        # Setup: User with Entra ID
        user = DataverseUser(
            id="user-bob",
            name="Bob",
            email="bob@example.com",
            azure_ad_object_id="entra-bob",
        )

        # Setup: Team with Bob as member
        team = DataverseTeam(
            id="team-leads",
            name="Leadership Team",
            team_type=0,  # Owner team
            azure_ad_object_id=None,
            member_ids=["user-bob"],
        )

        # Setup: Permissions with both direct user and team assignment
        perms = [
            DataverseTablePermission(
                table_name="opportunity",
                principal_id="user-bob",
                principal_type=IamType.USER,
            ),
            DataverseTablePermission(
                table_name="opportunity",
                principal_id="team-leads",
                principal_type=IamType.GROUP,
            ),
        ]

        self.client.environment = DataverseEnvironment(
            users=[user],
            teams=[team],
        )

        # Execute: Build permission objects
        permission_objects = self.client.__build_permission_objects__(perms)

        # Assert: Only one Bob despite appearing as direct + via team
        self.assertEqual(len(permission_objects), 1)
        self.assertEqual(permission_objects[0].id, "entra-bob")
        self.assertEqual(permission_objects[0].type, IamType.USER)

    def test_multiple_teams_overlapping_membership_dedupes_all_users(self):
        """
        Scenario: Three teams with overlapping membership.
        Team1: [Alice, Bob]
        Team2: [Bob, Carol]
        Team3: [Carol, Dave]
        Expected: All four users appear exactly once (dedupe by Entra ID).
        """
        # Setup: Four users
        users = [
            DataverseUser(
                id="user-alice",
                name="Alice",
                email="alice@example.com",
                azure_ad_object_id="entra-alice",
            ),
            DataverseUser(
                id="user-bob",
                name="Bob",
                email="bob@example.com",
                azure_ad_object_id="entra-bob",
            ),
            DataverseUser(
                id="user-carol",
                name="Carol",
                email="carol@example.com",
                azure_ad_object_id="entra-carol",
            ),
            DataverseUser(
                id="user-dave",
                name="Dave",
                email="dave@example.com",
                azure_ad_object_id="entra-dave",
            ),
        ]

        # Setup: Three teams with overlapping membership
        teams = [
            DataverseTeam(
                id="team-1",
                name="Team 1",
                team_type=0,
                member_ids=["user-alice", "user-bob"],
            ),
            DataverseTeam(
                id="team-2",
                name="Team 2",
                team_type=0,
                member_ids=["user-bob", "user-carol"],
            ),
            DataverseTeam(
                id="team-3",
                name="Team 3",
                team_type=0,
                member_ids=["user-carol", "user-dave"],
            ),
        ]

        # Setup: Permissions from all teams on same table
        perms = [
            DataverseTablePermission(
                table_name="account",
                principal_id="team-1",
                principal_type=IamType.GROUP,
            ),
            DataverseTablePermission(
                table_name="account",
                principal_id="team-2",
                principal_type=IamType.GROUP,
            ),
            DataverseTablePermission(
                table_name="account",
                principal_id="team-3",
                principal_type=IamType.GROUP,
            ),
        ]

        self.client.environment = DataverseEnvironment(users=users, teams=teams)

        # Execute: Build permission objects
        permission_objects = self.client.__build_permission_objects__(perms)

        # Assert: Exactly four distinct users despite team overlaps
        entra_ids = {po.id for po in permission_objects}
        self.assertEqual(
            len(entra_ids),
            4,
            f"Expected 4 deduped users, got {len(entra_ids)}: {entra_ids}",
        )
        self.assertEqual(
            entra_ids, {"entra-alice", "entra-bob", "entra-carol", "entra-dave"}
        )


if __name__ == "__main__":
    unittest.main()
