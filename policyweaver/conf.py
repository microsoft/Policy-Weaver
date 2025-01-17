import os
from uuid import uuid4

from policyweaver.models.common import (
    SourceMap
)

class Configuration:
    @staticmethod
    def configure_environment(config:SourceMap):
        if not config.correlation_id:
            config.correlation_id = str(uuid4())

        os.environ['CORRELATION_ID'] = config.correlation_id