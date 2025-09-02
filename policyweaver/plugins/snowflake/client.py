import json
import os
from pydantic.json import pydantic_encoder

from typing import List, Tuple

from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.snowflake.model import SnowflakeSourceMap

from policyweaver.models.export import (
    PolicyExport, Policy, Permission, PermissionObject
)

from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType
)

from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.snowflake.api import SnowflakeAPIClient

class SnowflakePolicyWeaver(PolicyWeaverCore):
    """
        Snowflake Policy Weaver for Snowflake Databases.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from Snowflake Database to the Policy Weaver framework.
    """
    sf_read_permissions = ["SELECT", "OWNERSHIP"]
    sf_database_read_prereqs = ["USAGE", "OWNERSHIP"]
    sf_schema_read_prereqs = ["USAGE", "OWNERSHIP"]

    def __init__(self, config:SnowflakeSourceMap) -> None:
        """
        Initializes the SnowflakePolicyWeaver with the provided configuration.
        Args:
            config (SnowflakeSourceMap): The configuration object containing the workspace URL, account ID, and API token.
        Raises:
            ValueError: If the configuration is not of type SnowflakeSourceMap.
        """
        super().__init__(PolicyWeaverConnectorType.SNOWFLAKE, config)

        self.__config_validation(config)
        self.__init_environment(config)
        
        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = SnowflakeAPIClient()

    def __init_environment(self, config:SnowflakeSourceMap) -> None:
        os.environ["SNOWFLAKE_ACCOUNT"] = config.snowflake.account_name
        os.environ["SNOWFLAKE_USER"] = config.snowflake.user_name
        os.environ["SNOWFLAKE_PASSWORD"] = config.snowflake.password
        os.environ["SNOWFLAKE_WAREHOUSE"] = config.snowflake.warehouse

    def __config_validation(self, config:SnowflakeSourceMap) -> None:
        """
        Validates the configuration for the SnowflakePolicyWeaver.
        This method checks if the configuration is of type SnowflakeSourceMap and if all required fields are present.
        Args:
            config (SnowflakeSourceMap): The configuration object to validate.
        Raises:
            ValueError: If the configuration is not of type SnowflakeSourceMap or if any required fields are missing.
        """
        if not config.snowflake:
            raise ValueError("SnowflakeSourceMap configuration is required for SnowflakePolicyWeaver.")

        if not config.snowflake.account_name:
            raise ValueError("Snowflake account name is required in the configuration.")

        if not config.snowflake.user_name:
            raise ValueError("Snowflake user name is required in the configuration.")

        if not config.snowflake.password:
            raise ValueError("Snowflake password is required in the configuration.")

        if not config.snowflake.warehouse:
            raise ValueError("Snowflake warehouse is required in the configuration.")
        

    def map_policy(self):
        self.map = self.api_client.__get_database_map__()
        pass