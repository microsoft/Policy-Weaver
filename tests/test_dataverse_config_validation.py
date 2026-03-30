"""
Tests for DataversePolicyWeaver.__config_validation.

Covers invalid/missing Dataverse configuration scenarios that must
raise ValueError with clear messages before any API calls are made.
"""

import unittest

from policyweaver.plugins.dataverse.client import DataversePolicyWeaver
from policyweaver.plugins.dataverse.model import (
    DataverseSourceMap,
    DataverseSourceConfig,
)
from policyweaver.models.config import (
    Source,
    SourceSchema,
    FabricConfig,
)


def _base_config(**overrides) -> dict:
    """Return kwargs for a valid DataverseSourceMap, with overrides applied."""
    defaults = dict(
        source=Source(name="TestCatalog", schemas=[SourceSchema(name="dbo")]),
        fabric=FabricConfig(
            tenant_id="t",
            workspace_id="w",
            mirror_id="m",
            policy_mapping="role_based",
        ),
        dataverse=DataverseSourceConfig(
            environment_url="https://test.crm.dynamics.com"
        ),
    )
    defaults.update(overrides)
    return defaults


class TestDataverseConfigValidation(unittest.TestCase):
    """Validation must reject missing or malformed Dataverse config early."""

    def test_missing_dataverse_section_raises_valueerror(self) -> None:
        """dataverse=None must raise with a clear message."""
        cfg = DataverseSourceMap(**_base_config(dataverse=None))
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn(
            "DataverseSourceMap configuration is required", str(ctx.exception)
        )

    def test_missing_environment_url_raises_valueerror(self) -> None:
        """environment_url=None must raise."""
        cfg = DataverseSourceMap(
            **_base_config(dataverse=DataverseSourceConfig(environment_url=None))
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("environment_url is required", str(ctx.exception))

    def test_empty_environment_url_raises_valueerror(self) -> None:
        """environment_url='' must raise."""
        cfg = DataverseSourceMap(
            **_base_config(dataverse=DataverseSourceConfig(environment_url=""))
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("environment_url is required", str(ctx.exception))

    def test_http_environment_url_raises_valueerror(self) -> None:
        """Plain http:// URLs must be rejected (requires https)."""
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(
                    environment_url="http://org.crm.dynamics.com"
                )
            )
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("must start with 'https://'", str(ctx.exception))

    def test_non_url_environment_url_raises_valueerror(self) -> None:
        """Arbitrary strings without https:// prefix must be rejected."""
        cfg = DataverseSourceMap(
            **_base_config(
                dataverse=DataverseSourceConfig(environment_url="org.crm.dynamics.com")
            )
        )
        with self.assertRaises(ValueError) as ctx:
            DataversePolicyWeaver(cfg)
        self.assertIn("must start with 'https://'", str(ctx.exception))

    def test_valid_config_does_not_raise(self) -> None:
        """A well-formed config must pass validation without error."""
        cfg = DataverseSourceMap(**_base_config())
        # Should not raise — instantiation succeeds.
        weaver = DataversePolicyWeaver(cfg)
        self.assertIsNotNone(weaver)

    def test_table_based_policy_mapping_raises_valueerror(self) -> None:
        """table_based mode is structurally incompatible with Dataverse depth/CLS."""
        cfg = DataverseSourceMap(**_base_config())
        weaver = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        weaver.config = cfg
        weaver.logger = __import__("logging").getLogger("test")
        with self.assertRaises(ValueError) as ctx:
            weaver.map_policy("table_based")
        self.assertIn("role_based", str(ctx.exception))

    def test_default_policy_mapping_does_not_raise(self) -> None:
        """Default parameter is role_based and should not raise ValueError."""
        cfg = DataverseSourceMap(**_base_config())
        weaver = DataversePolicyWeaver.__new__(DataversePolicyWeaver)
        weaver.config = cfg
        weaver.logger = __import__("logging").getLogger("test")
        weaver.api_client = type(
            "Stub",
            (),
            {
                "get_environment_security_map": staticmethod(
                    lambda _: __import__(
                        "policyweaver.plugins.dataverse.model",
                        fromlist=["DataverseEnvironment"],
                    ).DataverseEnvironment()
                )
            },
        )()
        # Should not raise — returns None because there are no table_permissions
        result = weaver.map_policy()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
