import unittest

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver


class TestDataverseRowFilterColumns(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ so we can unit test pure filter generation logic.
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        self.client.environment = type("Env", (), {})()
        self.client.environment.business_units = []

    def test_deep_uses_owningbusinessunit_lookup_value_column(self):
        self.client.environment.business_units = [
            type("BU", (), {"id": "bu-root", "parent_business_unit_id": None})(),
            type("BU", (), {"id": "bu-child", "parent_business_unit_id": "bu-root"})(),
        ]

        condition = self.client.__build_row_filter_condition__(
            effective_depth="Deep",
            role_business_unit_id="bu-root",
            principal_ids=set(),
        )

        self.assertIn("_owningbusinessunit_value", condition)
        self.assertNotIn(" owningbusinessunit ", f" {condition} ")

    def test_local_uses_owningbusinessunit_lookup_value_column(self):
        condition = self.client.__build_row_filter_condition__(
            effective_depth="Local",
            role_business_unit_id="bu-root",
            principal_ids=set(),
        )

        self.assertEqual("_owningbusinessunit_value = 'bu-root'", condition)

    def test_basic_uses_owner_lookup_value_column(self):
        condition = self.client.__build_row_filter_condition__(
            effective_depth="Basic",
            role_business_unit_id=None,
            principal_ids={"user-a", "user-b"},
        )

        self.assertIn("_ownerid_value in (", condition)
        self.assertNotIn(" ownerid ", f" {condition} ")

    def test_local_without_business_unit_returns_false_filter(self):
        condition = self.client.__build_row_filter_condition__(
            effective_depth="Local",
            role_business_unit_id=None,
            principal_ids=set(),
        )

        self.assertEqual("false", condition)

    def test_basic_without_principals_returns_false_filter(self):
        condition = self.client.__build_row_filter_condition__(
            effective_depth="Basic",
            role_business_unit_id=None,
            principal_ids=set(),
        )

        self.assertEqual("false", condition)


if __name__ == "__main__":
    unittest.main()
