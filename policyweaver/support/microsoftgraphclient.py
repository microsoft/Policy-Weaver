import os
import certifi

import logging
from msgraph.graph_service_client import GraphServiceClient
from kiota_abstractions.api_error import APIError

from policyweaver.auth import ServicePrincipal
from policyweaver.models.common import Utils

class MicrosoftGraphClient:
    def __init__(self, service_principal: ServicePrincipal):
        self.logger = logging.getLogger("POLICY_WEAVER")
        os.environ["SSL_CERT_FILE"] = certifi.where()

        self.graph_client = GraphServiceClient(
            credentials=service_principal.credential,
            scopes=["https://graph.microsoft.com/.default"],
        )

    async def __get_user_by_email(self, email: str) -> str:
        try:
            u = await self.graph_client.users.by_user_id(email).get()
            return u
        except APIError:
            return None

    async def lookup_user_id_by_email(self, email: str) -> str:
        lookup_id = None
        
        if Utils.is_email(email):
            user = await self.__get_user_by_email(email)

            if user: 
                lookup_id = user.id            
        elif Utils.is_uuid(email):
            lookup_id = email     

        if lookup_id:
            self.logger.debug(f"MSFT GRAPH CLIENT {email} - {lookup_id}")
        else:
            self.logger.debug(f"MSFT GRAPH CLIENT {email} - USER NOT FOUND")

        return lookup_id
       