import requests
import logging

class RestAPIProxy:
    def __init__(self, base_url, headers=None):
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.base_url = base_url
        self.headers = headers

    def get(self, endpoint, params=None, headers=None):
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - GET - {self.base_url}/{endpoint} - HEADERS {headers} - PARAMS - {params}")

        response = requests.get(
            f"{self.base_url}/{endpoint}", params=params, headers=headers
        )
        return self._handle_response(response)

    def post(self, endpoint, data=None, json=None, files=None, headers=None):
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
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - PUT - {self.base_url}/{endpoint} - HEADERS {headers} - DATA - {data} - JSON - {json}") 
        response = requests.put(
            f"{self.base_url}/{endpoint}", data=data, json=json, headers=headers
        )
        return self._handle_response(response)

    def delete(self, endpoint, headers=None):
        if not headers:
            headers = self.headers

        self.logger.debug(f"REST API PROXY - DELETE - {self.base_url}/{endpoint} - HEADERS {headers}")
        response = requests.delete(f"{self.base_url}/{endpoint}", headers=headers)
        return self._handle_response(response)

    def _handle_response(self, response):
        self.logger.debug(f"REST API PROXY - RESPONSE - {response.status_code}")
        if response.status_code in (200, 201, 202):
            return response
        else:
            response.raise_for_status()
