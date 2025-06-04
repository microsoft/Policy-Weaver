from azure.identity import ClientSecretCredential

class ServicePrincipal:
    def __init__(self, tenant_id:str, client_id:str, client_secret: str):
        self.__token__ = None

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)

    def get_token(self) -> str:
        if self.__token__ is None:
            self.__token__ = self.credential.get_token("https://api.fabric.microsoft.com/.default")
        
        return self.__token__.token

    def get_token_header(self):
        return {
            "Authorization": f"Bearer {self.get_token()}",
        }
