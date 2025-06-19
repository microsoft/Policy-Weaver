import os
import certifi

import logging
from msgraph.graph_service_client import GraphServiceClient
from kiota_abstractions.api_error import APIError

from policyweaver.auth import ServicePrincipal
from policyweaver.models.common import Utils

class MicrosoftGraphClient:
    """
    A class to interact with the Microsoft Graph API for user management.
    This class provides methods to look up user IDs by email addresses.
    Attributes:
        logger (logging.Logger): Logger instance for logging API interactions.
        graph_client (GraphServiceClient): Client for making requests to the Microsoft Graph API.
    """
    def __init__(self):
        """
        Initializes the MicrosoftGraphClient with a logger and a GraphServiceClient.
        Sets the SSL certificate file to ensure secure connections.
        
        Raises:
            ValueError: If the ServicePrincipal credentials are not set.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        os.environ["SSL_CERT_FILE"] = certifi.where()

        self.graph_client = GraphServiceClient(
            credentials=ServicePrincipal.Credential,
            scopes=["https://graph.microsoft.com/.default"],
        )

    async def __get_user_by_email(self, email: str) -> str:
        """
        Retrieves a user by their email address from the Microsoft Graph API.
        Args:
            email (str): The email address of the user to look up.
        Returns:
            User object if found, None otherwise.
        """
        try:
            u = await self.graph_client.users.by_user_id(email).get()
            return u
        except APIError:
            return None

    async def lookup_user_id_by_email(self, email: str) -> str:
        """
        Looks up a user ID by their email address.
        Args:
            email (str): The email address of the user to look up. 
        Returns:
            str: The user ID if found, None otherwise.
        """
        if Utils.is_uuid(email):
            return email  
        
        if Utils.is_email(email):
            user = await self.__get_user_by_email(email)

            if user: 
                self.logger.debug(f"MSFT GRAPH CLIENT {email} - {user.id}")
                return user.id 
            
        self.logger.debug(f"MSFT GRAPH CLIENT {email} - USER NOT FOUND")
        return None
       