from policyweaver.models.common import (
    PolicyWeaverConnectorType,
    SourceMap,
    PolicyExport,
)

from datetime import datetime
from typing import Dict
import os
import json
import logging


class PolicyWeaverCore:
    """
    Core class for Policy Weaver, responsible for mapping policies
    from various sources to a unified format.
    This class initializes with a connector type and configuration,
    and provides a method to map policies.
    Example usage:
        core = PolicyWeaverCore(PolicyWeaverConnectorType.AZURE, config)
        policy_export = core.map_policy()
    """
    def __init__(self, type: PolicyWeaverConnectorType, config:SourceMap):
        """
        Initialize the PolicyWeaverCore with a connector type and configuration.
        Args:
            type (PolicyWeaverConnectorType): The type of connector to use (e.g., Azure, AWS).
            config (SourceMap): Configuration settings for the policy mapping.
        """
        self.connector_type = type
        self.config = config
        self.logger = logging.getLogger("POLICY_WEAVER")

    def map_policy(self) -> PolicyExport:
        """
        Map policies from the configured source to a unified format.
        This method retrieves policies from the source, processes them,
        and returns a PolicyExport object containing the mapped policies.
        Returns:
            PolicyExport: An object containing the mapped policies.
        """
        pass

    def __write_to_log__(self, type: str, data: Dict):
        """
        Write the provided data to a log file in a specific directory based on the type.
        The log file is named with the current timestamp and stored in a directory
        named after the type (e.g., "azure_snapshot", "aws_snapshot").
        Args:
            type (str): The type of connector (e.g., "Azure", "AWS").
            data (Dict): The data to log, typically a dictionary containing policy information.
        """
        directory = "."
        log_directory = f"{directory}/{type.lower()}_snapshot"

        os.makedirs(log_directory, exist_ok=True)

        log_file = f"{log_directory}/log_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"

        with open(log_file, "w") as file:
            json.dump(data, file, indent=4)
