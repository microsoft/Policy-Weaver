import os
import certifi

import logging
from msgraph.graph_service_client import GraphServiceClient
from kiota_abstractions.api_error import APIError

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.utility import Utils

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

    async def get_service_principal_by_id(self, id:str) -> str:
        """
        Looks up a service principal by its ID.
        Args:
            id (str): The ID of the service principal to look up.
        Returns:
            str: The service principal ID if found, None otherwise.
        """
        try:
            sp = await self.graph_client.service_principals_with_app_id(id).get()
            if sp:
                self.logger.debug(f"MSFT GRAPH CLIENT {id} - {sp.id}")
                return sp.id
        except APIError:
            self.logger.debug(f"MSFT GRAPH CLIENT {id} - SERVICE PRINCIPAL NOT FOUND IN GRAPH API")
            return None
        

    async def get_user_by_email(self, email: str) -> str:
        """
        Looks up a user ID by their email address.
        Args:
            email (str): The email address of the user to look up. 
        Returns:
            str: The user ID if found, None otherwise.
        """
        try:
            u = await self.graph_client.users.by_user_id(email.lower()).get()

            if u: 
                self.logger.debug(f"MSFT GRAPH CLIENT {email} - {u.id}")
                return u.id 
        except APIError:
            self.logger.debug(f"MSFT GRAPH CLIENT {email} - USER NOT FOUND IN GRAPH API")
            return None
       