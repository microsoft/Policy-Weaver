import os
import certifi
from azure.identity import ClientSecretCredential
from msgraph.graph_service_client import GraphServiceClient
from kiota_abstractions.api_error import APIError


class MicrosoftGraphClient:
    def __init__(self, tenant: str, id: str, secret: str):
        os.environ["SSL_CERT_FILE"] = certifi.where()

        self.graph_client = GraphServiceClient(
            credentials=ClientSecretCredential(
                tenant_id=tenant, client_id=id, client_secret=secret
            ),
            scopes=["https://graph.microsoft.com/.default"],
        )

    async def get_user_by_email(self, email: str) -> str:
        try:
            return await self.graph_client.users.by_user_id(email).get()
        except APIError:
            return None

    async def lookup_user_id_by_email(self, email: str) -> str:
        user = await self.get_user_by_email(email)

        if not user:
            return None

        return user.id
