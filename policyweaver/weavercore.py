from policyweaver.models.common import (
    PolicyWeaverConnectorType,
    Source,
    PolicyExport,
)
from datetime import datetime
from typing import Dict
import os
import json


class PolicyWeaverCore:
    def __init__(self, type: PolicyWeaverConnectorType):
        self.connector_type = type

    def map_policy(self, source: Source) -> PolicyExport:
        pass

    def __write_to_log__(self, type: str, data: Dict):
        directory = "/lakehouse/default/Files/audit"
        log_directory = f"{directory}/{type.lower()}_snapshot"

        os.makedirs(log_directory, exist_ok=True)

        log_file = f"{log_directory}/log_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"

        with open(log_file, "w") as file:
            json.dump(data, file)
