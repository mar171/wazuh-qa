from base64 import b64encode
from requests.exceptions import ConnectionError
from json import JSONDecodeError
from urllib3 import disable_warnings, exceptions
from http import HTTPStatus

from wazuh_testing.models.request import Request, GetRequest


disable_warnings(exceptions.InsecureRequestWarning)

DEFAULT_USER = 'wazuh'
DEFAULT_PASSOWRD = 'wazuh'
DEFAULT_PORT = 55000
DEFAULT_ADDRESS = 'localhost'
DEFAULT_PROTOCOL = 'https'
DEFAULT_TOKEN_EXPIRATION = 900


class WazuhAPIResponse(object):

    def __init__(self, request_response):
        self.request_response = request_response
        self.status_code = request_response.status_code
        self.error = 0
        self.data = self.__get_data()

    def __get_data(self):
        if self.status_code == HTTPStatus.METHOD_NOT_ALLOWED or self.status_code == HTTPStatus.UNAUTHORIZED:
            self.error = 1
            return self.request_response.json()['title']

        if self.status_code == HTTPStatus.OK:
            try:
                data_container = self.request_response.json()

                if 'data' in data_container:
                    self.error = data_container['error'] if 'error' in data_container else 0
                    return data_container['data']
                else:
                    self.error = 0
                    return data_container

            except JSONDecodeError:
                return self.request_response.text

    def __str__(self):
        return '{' + f"'status_code': {self.status_code}, 'data': '{self.data}', error: {self.error}" + '}'


class WazuhAPIRequest(object):

    def __init__(self, endpoint, method, payload=None, headers=None, verify=False):
        self.endpoint = endpoint
        self.method = method.upper()
        self.payload = payload
        self.headers = headers
        self.verify = verify

    def __get_request_parameters(self, wazuh_api_object):
        if wazuh_api_object.token is None:
            wazuh_api_object.token = wazuh_api_object.get_token()

        self.headers = {} if self.headers is None else self.headers
        self.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {wazuh_api_object.token}'
        })

        request_args = {
            'method': self.method,
            'url': f"{wazuh_api_object.url}{self.endpoint}",
            'headers': self.headers,
            'verify': self.verify
        }

        if self.payload is not None:
            request_args['payload'] = self.payload

        return request_args

    def __call__(self, func):
        def wrapper(obj, *args, **kwargs):
            kwargs['response'] = self.send(obj)

            return func(obj, *args, **kwargs)

        return wrapper

    def send(self, wazuh_api_object):
        request_parameters = self.__get_request_parameters(wazuh_api_object)

        try:
            return WazuhAPIResponse(Request(**request_parameters).send())
        except ConnectionError:
            raise RuntimeError(f"Cannot establish connection with {wazuh_api_object.url}") from ConnectionError


class WazuhAPI():
    def __init__(self, user=DEFAULT_USER, password=DEFAULT_PASSOWRD, port=DEFAULT_PORT, address=DEFAULT_ADDRESS,
                 protocol=DEFAULT_PROTOCOL, auto_auth=True, token_expiration=DEFAULT_TOKEN_EXPIRATION):
        self.user = user
        self.password = password
        self.port = port
        self.address = address
        self.protocol = protocol
        self.url = f"{protocol}://{address}:{port}"
        self.token_expiration = token_expiration
        self.token = self.get_token() if auto_auth else None

        if token_expiration != DEFAULT_TOKEN_EXPIRATION:
            self.set_token_expiration(token_expiration)
            self.token = self.get_token()

    def get_token(self):
        basic_auth = f"{self.user}:{self.password}".encode()
        auth_header = {'Content-Type': 'application/json', 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

        try:
            response = GetRequest(f"{self.url}/security/user/authenticate?raw=true", headers=auth_header).send()

            if response.status_code == HTTPStatus.OK:
                return response.text
            else:
                raise RuntimeError(f"Error obtaining login token: {response.json()}")

        except ConnectionError:
            raise RuntimeError(f"Cannot establish connection with {self.url}") from ConnectionError

    def set_token_expiration(self, num_seconds):
        response = WazuhAPIRequest(method='PUT', endpoint='/security/config',
                                   payload={'auth_token_exp_timeout': num_seconds}).send(self)
        return response

    @WazuhAPIRequest(method='GET', endpoint='/')
    def get_api_info(self, response):
        return response.data
