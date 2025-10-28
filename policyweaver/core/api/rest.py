import requests
import logging

class RestAPIProxy:
    """
    A class to interact with a REST API.
    This class provides methods to perform GET, POST, PUT, and DELETE requests.
    Attributes:
        logger (logging.Logger): Logger instance for logging API interactions.
        base_url (str): The base URL of the REST API.
        headers (dict): Default headers to be used in API requests.
    """
    def __init__(self, base_url, headers=None, weaver_type=None):
        """
        Initializes the RestAPIProxy with a base URL and optional headers.
        Args:
            base_url (str): The base URL of the REST API.
            headers (dict, optional): Default headers to be used in API requests. Defaults to None.
        
        Raises:
            ValueError: If the base URL is not provided.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.base_url = base_url
        self.headers = headers
        self.weaver_type = weaver_type if weaver_type else "UNKNOWN"

    def get(self, endpoint, params=None, headers=None):
        """
        Performs a GET request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the GET request is made.
            params (dict, optional): Query parameters to be included in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the GET request.
        """
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - GET - {self.base_url}/{endpoint} - HEADERS {headers} - PARAMS - {params}")

        response = requests.get(
            f"{self.base_url}/{endpoint}", params=params, headers=headers
        )
        return self._handle_response(response)

    def post(self, endpoint, data=None, json=None, files=None, headers=None):
        """
        Performs a POST request to the specified endpoint of the REST API.  
        Args:
            endpoint (str): The endpoint to which the POST request is made.
            data (dict, optional): Form data to be included in the request. Defaults to None
            json (dict, optional): JSON data to be included in the request. Defaults to None.
            files (dict, optional): Files to be uploaded in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the POST request.
        """
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - POST - {self.base_url}/{endpoint} - HEADERS {headers} - DATA - {data} - JSON - {json}")

        response = requests.post(
            f"{self.base_url}/{endpoint}",
            data=data,
            json=json,
            files=files,
            headers=headers,
        )
        return self._handle_response(response)

    def put(self, endpoint, data=None, json=None, headers=None):
        """
        Performs a PUT request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the PUT request is made.
            data (dict, optional): Form data to be included in the request. Defaults to None
            json (dict, optional): JSON data to be included in the request. Defaults to None.
            headers (dict, optional): Headers to be included in the request. Defaults to None.
        Returns:
            Response object: The response from the PUT request."""
        if not headers:
            headers = self.headers

        headers["policyweaver"] = self.weaver_type

        self.logger.debug(f"REST API PROXY - PUT - {self.base_url}/{endpoint} - HEADERS {headers} - DATA - {data} - JSON - {json}") 
        response = requests.put(
            f"{self.base_url}/{endpoint}", data=data, json=json, headers=headers
        )
        return self._handle_response(response)

    def delete(self, endpoint, headers=None):
        """
        Performs a DELETE request to the specified endpoint of the REST API.
        Args:
            endpoint (str): The endpoint to which the DELETE request is made.
            headers (dict, optional): Headers to be included in the request. Defaults to None.  
        Returns:
            Response object: The response from the DELETE request.
        """
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - DELETE - {self.base_url}/{endpoint} - HEADERS {headers}")
        response = requests.delete(f"{self.base_url}/{endpoint}", headers=headers)
        return self._handle_response(response)

    def _handle_response(self, response):
        """
        Handles the response from the REST API. 
        Args:
            response (Response): The response object from the requests library.
        Returns:
            Response object: The response if the status code is 200, 201, or 202.
        Raises:
            HTTPError: If the response status code is not 200, 201, or 202.
        """
        self.logger.debug(f"REST API PROXY - RESPONSE - {response.status_code}")
        if response.status_code in (200, 201, 202):
            return response
        else:
            self.logger.error(f"REST API PROXY - ERROR - {response.status_code} - {response.text}")
            response.raise_for_status()
