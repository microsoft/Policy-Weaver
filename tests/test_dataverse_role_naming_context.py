import unittest

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver


class _FakeBusinessUnit:
    def __init__(self, name=None):
        self.name = name


class _FakeEnvironment:
    def __init__(self, bu_map=None):
        self._bu_map = bu_map or {}

    def lookup_business_unit_by_id(self, business_unit_id):
        return self._bu_map.get(business_unit_id)


class TestDataverseRoleNamingContext(unittest.TestCase):
    def setUp(self):
        self.client = DataversePolicyWeaver.__new__(DataversePolicyWeaver)

    def test_uses_business_unit_name_when_available(self):
        bu_id = "9f3ab4f1-9b1f-4f8a-b88a-99df6fb8b8a1"
        self.client.environment = _FakeEnvironment(
            bu_map={bu_id: _FakeBusinessUnit(name="Operations")}
        )

        label = self.client.__get_role_business_unit_label__(bu_id)

        self.assertEqual("Operations", label)

    def test_falls_back_to_short_business_unit_id_when_name_missing(self):
        bu_id = "9f3ab4f1-9b1f-4f8a-b88a-99df6fb8b8a1"
        self.client.environment = _FakeEnvironment(bu_map={})

        label = self.client.__get_role_business_unit_label__(bu_id)

        self.assertEqual("9f3ab4f1", label)


if __name__ == "__main__":
    unittest.main()
