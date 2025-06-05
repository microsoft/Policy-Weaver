import os
import certifi
from azure.identity import ClientSecretCredential
from msgraph.graph_service_client import GraphServiceClient
from kiota_abstractions.api_error import APIError

from policyweaver.auth import ServicePrincipal

class MicrosoftGraphClient:
    def __init__(self, service_principal: ServicePrincipal):
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
        user = await self.__get_user_by_email(email)
    
        if not user:
            return None
    
        return user.id