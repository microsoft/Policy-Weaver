from policyweaver.support.restapiclient import RestAPIProxy


class FabricAPI:
    def __init__(self, workspace_id: str, api_token: str):
        self.workspace_id = workspace_id
        self.token = api_token

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        self.rest_api_proxy = RestAPIProxy(
            base_url="https://api.fabric.microsoft.com/v1/", headers=headers
        )

    def __get_workspace_uri__(self, uri) -> str:
        return f"workspaces/{self.workspace_id}/{uri}"

    def put_data_access_policy(self, item_id, access_policy):
        uri = f"items/{item_id}/dataAccessRoles"
        return self.rest_api_proxy.put(
            endpoint=self.__get_workspace_uri__(uri), data=access_policy
        )

    def list_data_access_policy(self, item_id):
        uri = f"items/{item_id}/dataAccessRoles"
        return self.rest_api_proxy.get(endpoint=self.__get_workspace_uri__(uri)).json()

    def get_workspace_name(self) -> str:
        response = self.rest_api_proxy.get(
            endpoint=self.__get_workspace_uri__("")
        ).json()
        return response["displayName"]

    def get_lakehouse_id(self, lakehouse_name: str) -> str:
        uri = "lakehouses"
        response = self.rest_api_proxy.get(
            endpoint=self.__get_workspace_uri__(uri)
        ).json()
        o = [
            x["id"]
            for x in response["value"]
            if x["displayName"].lower() == lakehouse_name.lower()
        ]

        if o:
            return o[0]

        return None
