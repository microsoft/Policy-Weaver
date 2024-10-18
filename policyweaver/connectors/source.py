from abc import ABC, abstractmethod

class PolicySource(ABC):
    """
    Abstract base class for policy sources.
    This class defines the interface for policy sources, which are responsible for
    opening, closing, validating, and retrieving policies.
    Methods
    -------
    open()
        Abstract method to open the policy source.
    close()
        Abstract method to close the policy source.
    validate() -> bool
        Abstract method to validate the policy source.
    get_policies() -> list
        Abstract method to retrieve a list of policies from the source.
    """

    @abstractmethod
    def open(self):
        """
        Opens a connection or resource.
        This method is intended to be overridden by subclasses to implement
        the logic for opening a specific type of connection or resource.
        """

        pass

    @abstractmethod
    def close(self):
        """
        Closes the connection or resource associated with this instance.
        This method should be overridden by subclasses to implement the specific
        logic required to properly close and clean up any resources or connections
        that were opened or used by the instance.
        """

        pass

    @abstractmethod
    def validate(self) -> bool:
        """
        Validates the current state or configuration.
        Returns:
            bool: True if the validation is successful, False otherwise.
        """

        pass

    @abstractmethod
    def get_policies() -> list:
        """
        Retrieves a list of policies.
        Returns:
            list: A list containing policy data.
        """

        pass

class PolicyService:
    """
    A service class to interact with a policy source and retrieve access policies.
    Attributes:
        source (PolicySource): The source from which policies are retrieved.
    Methods:
        __init__(source: PolicySource) -> None:
            Initializes the PolicyService with a given policy source.
        get_access_policies() -> list:
            Retrieves access policies from the source if the source is valid.
            Returns a list of policies.
    """

    def __init__(self, source: PolicySource) -> None:
        """
        Initializes the source connector with the given PolicySource.
        Args:
            source (PolicySource): The policy source to be used by the connector.
        """

        self.source = PolicySource
    
    def get_access_policies(self) -> list:
        """
        Retrieves access policies from the source.
        This method validates the source, opens it, retrieves the policies, 
        and then closes the source. If the source is not valid, it returns 
        an empty list.
        Returns:
            list: A list of access policies retrieved from the source.
        """

        policies = []

        if self.source.validate():
            self.source.open()
            policies = self.source.get_policies()
            self.source.close()

        return policies
