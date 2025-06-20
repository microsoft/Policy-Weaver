import os
from uuid import uuid4

from policyweaver.models.config import SourceMap

class Configuration:
    """
    Configuration class for managing application settings and environment variables.
    This class provides methods to set and retrieve configuration values,
    including correlation IDs and service principal credentials.
    Example usage:
        config = Configuration()
        config.configure_environment(SourceMap(correlation_id="12345"))
        print(os.environ['CORRELATION_ID'])  # Outputs: 12345
    """
    @staticmethod
    def configure_environment(config:SourceMap):
        """
        Configure the environment with the provided SourceMap configuration.
        This method sets the correlation ID in the environment variables
        and ensures that a unique correlation ID is generated if not provided.
        Args:
            config (SourceMap): The SourceMap instance containing configuration values.
        """
        if not config.correlation_id:
            config.correlation_id = str(uuid4())

        os.environ['CORRELATION_ID'] = config.correlation_id