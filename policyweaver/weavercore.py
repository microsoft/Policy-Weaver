from policyweaver.models.common import (
    PolicyWeaverConnectorType,
    SourceMap,
    PolicyExport,
)
from policyweaver.auth import ServicePrincipal

from datetime import datetime
from typing import Dict
import os
import json
import logging


class PolicyWeaverCore:
    def __init__(self, type: PolicyWeaverConnectorType, config:SourceMap, service_principal:ServicePrincipal):
        self.connector_type = type
        self.config = config
        self.service_principal = service_principal
        self.logger = logging.getLogger(config.application_name)

    def map_policy(self) -> PolicyExport:
        pass

    def __write_to_log__(self, type: str, data: Dict):
        directory = "."
        log_directory = f"{directory}/{type.lower()}_snapshot"

        os.makedirs(log_directory, exist_ok=True)

        log_file = f"{log_directory}/log_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"

        with open(log_file, "w") as file:
            json.dump(data, file, indent=4)
