import logging

from policyweaver.core.api.rest import RestAPIProxy
from policyweaver.core.auth import ServicePrincipal

class FabricAPI:
    """
    A class to interact with the Fabric API for managing data access policies.
    This class provides methods to put and list data access policies, and to retrieve workspace information.
    Attributes:
        workspace_id (str): The unique identifier of the Fabric workspace.
        logger (logging.Logger): Logger instance for logging API interactions.
        token (str): Authentication token for accessing the Fabric API.
        rest_api_proxy (RestAPIProxy): Proxy for making REST API calls to the Fabric API.
    """
    def __init__(self, workspace_id: str, weaver_type: str = None):
        """
        Initializes the FabricAPI instance with the given workspace ID.
        Args:
            workspace_id (str): The unique identifier of the Fabric workspace.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.workspace_id = workspace_id
        self.weaver_type = weaver_type

        self.token = ServicePrincipal.get_token()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

        self.rest_api_proxy = RestAPIProxy(
            base_url="https://api.fabric.microsoft.com/v1", headers=headers, weaver_type=self.weaver_type
        )

    def __get_workspace_uri__(self, uri) -> str:
        """
        Constructs the full URI for the Fabric API workspace.
        Args:
            uri (str): The specific endpoint URI to append to the workspace base URI.
        Returns:
            str: The full URI for the Fabric API workspace.
        """
        uri = f"workspaces/{self.workspace_id}/{uri}"
        self.logger.debug(f"FABRIC API - WORKSPACE URI: {uri}")
        return uri

    def put_data_access_policy(self, item_id, access_policy):
        """
        Updates the data access policy for a specific item in the Fabric workspace.
        Args:
            item_id (str): The unique identifier of the item for which the access policy is being updated.
            access_policy (dict): The access policy to be applied to the item.
        Returns:
            Response: The response from the Fabric API after attempting to update the access policy.
        """
        uri = f"items/{item_id}/dataAccessRoles"
        return self.rest_api_proxy.put(
            endpoint=self.__get_workspace_uri__(uri), data=access_policy
        )

    def list_data_access_policy(self, item_id):
        """
        Retrieves the data access policy for a specific item in the Fabric workspace.
        Args:
            item_id (str): The unique identifier of the item for which the access policy is being retrieved.
        Returns:
            dict: The data access policy for the specified item.
        """
        uri = f"items/{item_id}/dataAccessRoles"
        return self.rest_api_proxy.get(endpoint=self.__get_workspace_uri__(uri)).json()

    def get_workspace_name(self) -> str:
        """
        Retrieves the display name of the Fabric workspace.
        Returns:
            str: The display name of the Fabric workspace.
        """
        response = self.rest_api_proxy.get(
            endpoint=self.__get_workspace_uri__("")
        ).json()
        return response["displayName"]
