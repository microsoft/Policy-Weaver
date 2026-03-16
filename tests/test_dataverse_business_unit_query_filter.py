import unittest

from policyweaver.plugins.dataverse.api import DataverseAPIClient


class TestDataverseBusinessUnitQueryFilter(unittest.TestCase):
    def test_business_unit_query_filters_disabled_units(self):
        client = DataverseAPIClient.__new__(DataverseAPIClient)
        client.api_url = "https://example.crm.dynamics.com/api/data/v9.2"

        captured = {"url": None}

        def fake_get_paged(url):
            captured["url"] = url
            return [
                {
                    "businessunitid": "bu-1",
                    "name": "Active BU",
                    "_parentbusinessunitid_value": None,
                }
            ]

        client._get_paged = fake_get_paged

        result = client.__get_business_units__()

        self.assertIn("$filter=isdisabled eq false", captured["url"])
        self.assertEqual(1, len(result))
        self.assertEqual("bu-1", result[0].id)


if __name__ == "__main__":
    unittest.main()
