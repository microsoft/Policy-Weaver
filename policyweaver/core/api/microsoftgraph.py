import asyncio
import os
from urllib.parse import quote

import certifi
import logging
import requests

from policyweaver.core.auth import ServicePrincipal
from policyweaver.core.utility import Utils

class MicrosoftGraphClient:
    """
    A class to interact with the Microsoft Graph REST API.
    This class provides methods to look up user IDs by email address and
    service principal object IDs by application ID.
    Attributes:
        logger (logging.Logger): Logger instance for logging API interactions.
    """
    def __init__(self):
        """
        Initializes the MicrosoftGraphClient with a logger.
        Sets the SSL certificate file to ensure secure connections.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        os.environ["SSL_CERT_FILE"] = certifi.where()

    async def get_service_principal_by_id(self, id: str) -> str | None:
        """
        Looks up a service principal object ID by its application (client) ID
        using the Microsoft Graph REST API.

        This direct REST request works around insufficient_claims responses from
        the Graph SDK when the same service-principal token is accepted by Graph.

        Args:
            id (str): The application (client) ID of the service principal.

        Returns:
            str | None: The service principal object ID if found, otherwise None.
        """
        app_id = id.strip()
        graph_url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"(appId='{quote(app_id, safe='-')}')"
        )

        try:
            response = await self._graph_rest_get(graph_url)
        except requests.RequestException:
            self.logger.exception(
                f"MSFT GRAPH REST CLIENT {id} - SERVICE PRINCIPAL REQUEST FAILED"
            )
            return None

        if response.status_code == 200:
            sp_id = response.json().get("id")
            if not sp_id:
                self.logger.error(
                    f"MSFT GRAPH REST CLIENT {id} - RESPONSE MISSING SERVICE PRINCIPAL ID"
                )
                return None

            self.logger.debug(f"MSFT GRAPH REST CLIENT {id} - FOUND - {sp_id}")
            return sp_id

        if response.status_code == 404:
            self.logger.debug(
                f"MSFT GRAPH REST CLIENT {id} - SERVICE PRINCIPAL NOT FOUND"
            )
            return None

        self.logger.error(
            f"MSFT GRAPH REST CLIENT {id} - HTTP {response.status_code} - "
            f"{response.text}"
        )
        return None

    async def _graph_rest_get(self, url: str) -> requests.Response:
        """
        Sends an authenticated GET request to Microsoft Graph without blocking the event loop.
        Args:
            url (str): The full Microsoft Graph URL.
        Returns:
            requests.Response: The HTTP response.
        Raises:
            requests.RequestException: If the request cannot be completed.
        """
        access_token = ServicePrincipal.get_token(
            scope="https://graph.microsoft.com/.default"
        )
        return await asyncio.to_thread(
            requests.get,
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=30,
        )


    async def get_user_by_email(self, email: str) -> str | None:
        """
        Looks up a user ID by email using the Microsoft Graph REST API.

        This direct REST request works around insufficient_claims responses from
        the Graph SDK when the same service-principal token is accepted by Graph.

        Args:
            email (str): The email address of the user to look up.

        Returns:
            str | None: The user ID if found, otherwise None.
        """
        normalized_email = email.strip().lower()
        encoded_user = quote(normalized_email, safe="@.")
        graph_url = f"https://graph.microsoft.com/v1.0/users/{encoded_user}"

        try:
            response = await self._graph_rest_get(graph_url)
        except requests.RequestException:
            self.logger.exception(f"MSFT GRAPH REST CLIENT {email} - REQUEST FAILED")
            return None

        if response.status_code == 200:
            user_id = response.json().get("id")
            if not user_id:
                self.logger.error(
                    f"MSFT GRAPH REST CLIENT {email} - RESPONSE MISSING USER ID"
                )
                return None

            self.logger.info(
                f"MSFT GRAPH REST CLIENT {email} - FOUND - {user_id}"
            )
            return user_id

        if response.status_code == 404:
            self.logger.warning(
                f"MSFT GRAPH REST CLIENT {email} - USER NOT FOUND"
            )
            return None

        self.logger.error(
            f"MSFT GRAPH REST CLIENT {email} - HTTP {response.status_code} - "
            f"{response.text}"
        )
        return None