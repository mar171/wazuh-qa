"""Custom request module wrapping the requests module.

Classes:
  - Request(object)
  - GetRequest(Request)
  - PostRequest(Request)
  - PutRequest(Request)
  - DeleteRequest(Request)
"""

import requests


class Request(object):
    """Class to make requests.

    Args:
        url (str): Url to send the request.
        method (str): Request type.
        payload (dict): Request parameters.
        headers (dict): Request headers.

    Attributes:
        url (str): Url to send the request.
        method (str): Request type.
        payload (dict): Request parameters.
        headers (dict): Request headers.
    """
    def __init__(self, url, method, payload=None, headers=None):
        self.url = url
        self.method = method.upper()
        self.payload = payload
        self.headers = headers

    def send(self):
        """Send the request.

        Returns:
            Response <Response>: Response object.
        """
        args = {
            'method': self.method,
            'url': self.url,
            'headers': self.headers
        }

        if self.payload is not None:
            args['json'] = self.payload

        return requests.request(**args)


class GetRequest(Request):
    """Class to build GET requests.

    Args:
        url (str): Url to send the request.
        payload (dict): Request parameters.
        headers (dict): Request headers.
    """
    def __init__(self, url, payload=None, headers=None):
        super().__init__(url=url, method='GET', payload=payload, headers=headers)


class PostRequest(Request):
    """Class to build POST requests.

    Args:
        url (str): Url to send the request.
        payload (dict): Request parameters.
        headers (dict): Request headers.
    """
    def __init__(self, url, payload=None, headers=None):
        super().__init__(url=url, method='POST', payload=payload, headers=headers)


class PutRequest(Request):
    """Class to build PUT requests.

    Args:
        url (str): Url to send the request.
        payload (dict): Request parameters.
        headers (dict): Request headers.
    """
    def __init__(self, url, payload=None, headers=None):
        super().__init__(url=url, method='PUT', payload=payload, headers=headers)


class DeleteRequest(Request):
    """Class to build DELETE requests.

    Args:
        url (str): Url to send the request.
        payload (dict): Request parameters.
        headers (dict): Request headers.
    """
    def __init__(self, url, payload=None, headers=None):
        super().__init__(url=url, method='DELETE', payload=payload, headers=headers)
