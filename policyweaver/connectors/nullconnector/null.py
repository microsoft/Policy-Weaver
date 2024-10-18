from policyweaver.connectors.source import *

class NullConnector(PolicySource):
    """
    NullConnector is a placeholder implementation of the PolicySource interface.
    Methods:
        __init__(): Initializes the NullConnector instance.
        open(): Opens the connector (no-op).
        close(): Closes the connector (no-op).
        validate(): Validates the connector (always returns True).
        get_policies() -> list: Retrieves policies (always returns an empty list).
    """

    def __init__(self):
        """
        Initializes the NullConnector.
        This constructor does not perform any operations.
        """

        return
    
    def open(self):
        """
        Opens the null connector.
        This method is a placeholder and does not perform any operations.
        """

        return
    
    def close(self):
        """
        Closes the connection.
        This method is a placeholder and does not perform any actions.
        """

        return
    
    def validate(self):
        """
        A placeholder method for validation.
        This method currently does nothing and always returns True.
        """

        return True
    
    def get_policies(self) -> list:
        """
        Retrieve a list of policies.
        Returns:
            list: An empty list representing no policies.
        """

        return []