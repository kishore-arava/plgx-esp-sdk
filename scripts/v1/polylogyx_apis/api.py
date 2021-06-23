#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple class to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
The APIs are documented at:
https://github.com/polylogyx/polylogyx-api/
EXAMPLE USAGE:::
from api import PolylogyxApi
polylogyxApi = PolylogyxApi(domain=<IP/DOMAIN>, username=<USERNAME>,
                                         password=<PASSWORD>)
response = polylogyxApi.get_nodes()
print json.dumps(response, sort_keys=False, indent=4)
"""
import requests
from websocket import create_connection
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT_SECS = 30


class PolylogyxApi:

    def __init__(self, domain=None, username=None, password=None):
        self.username = username
        self.password = password
        self.version = 0
        self.max_retries = 5
        self.domain = domain
        self.base = "https://" + domain + "/esp-ui/services/api/v1"

        if username is None or password is None:
            raise ApiError("You must supply a username and password.")
        self.fetch_token()

    def fetch_token(self):
        """
        Logs into PolyLogyx ESP platform and fetches auth token
        :return: JSON Response of Auth token
        """
        url = self.base + '/login'
        payload = {'username': self.username, 'password': self.password}
        try:
            response = _return_response_and_status_code(requests.post(
                url, json=payload, headers={},
                verify=False, timeout=TIMEOUT_SECS))
            if response['response_code'] == 200:
                if 'status' in response['results'] and response['results']['status'] == "failure":
                    raise ApiError("Invalid username and or password.")
                self.AUTH_TOKEN = response['results']['token']
        except requests.RequestException as e:
            return dict(error=str(e))

    def get_nodes(self, platform=None, status=None, start=None, limit=None):
        """ This API allows you to get all the nodes registered.
            :return: JSON response that contains list of nodes.
        """

        url = self.base + "/hosts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        body = {}
        if platform:
            body['platform'] = platform
        if status:
            body['status'] = status
        if start is not None:
            body['start'] = start
        if limit:
            body['limit'] = limit
        try:
            response = requests.post(
                url, headers=headers, json=body,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_nodes_distribution(self):
        """ This API allows you to get distributed count on platform, status pair.
            :return: JSON response that contains list of node's platform distribution.
        """
        url = self.base + "/hosts/count"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_all_packs(self):
        """ This API allows you to get all packs
            :return: JSON response that contains an array of all packs.
        """

        url = self.base + "/packs"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, data={},
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_node(self, node_id=None, host_identifier=None):
        """ This API allows you to get a host details for the given id
            :return: JSON response that contains host details.
        """
        if node_id:
            url = self.base + "/hosts/{}".format(node_id)
        elif host_identifier:
            url = self.base + "/hosts/{}".format(host_identifier)
        else:
            url = self.base + "/hosts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_nodes_distribution_count(self):
        """ This API allows you to get count of nodes registered for platform, status pair.
            :return: JSON response that contains list of platform, status and count combination.
        """

        url = self.base + "/hosts/count"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_alerts(self, data):
        """ This API allows you to get the alerts for the filters requested.
            :return: JSON response that contains list of Alerts.
        """

        url = self.base + "/alerts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def send_distributed_query(self, sql=None, tags=[], host_identifiers=[]):
        """ Send a query to nodes.
               This API allows you to execute an on-demand query on the nodes.
               :param sql: The sql query to be executed
               :param tags: Specify the array of tags.
               :param host_identifiers: Specify the host_identifier array.
               :return: JSON response that contains query_id.
               """
        payload = {
            "query": sql,
            "nodes": ','.join(host_identifiers),
            "tags": ','.join(tags)
        }

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/distributed/add"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_distributed_query_results(self, query_id):

        """ Retrieve the query results based on the query_id query.
               This API uses web socket connection for getting data.
               :param query_id: Query id for which the results to be fetched
               :return: Stream data of a query executed on nodes.
        """
        conn = create_connection("wss://" + self.domain + ":5000" + "/distributed/result",
                                 sslopt={"cert_reqs": ssl.CERT_NONE})

        conn.send(str(query_id))
        result = conn.recv()
        return conn

    def get_query_count(self, host_identifier=None):
        """
        Returns query results count of a host
        :param host_identifier: Host identifier of the host to fetch query counts
        :return: JSON array of query names and counts
        """
        payload = {'host_identifier': host_identifier}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + '/hosts/recent_activity/count'
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_query_data(self, query_name=None, host_identifier=None, start=1, limit=100):
        """
        Fetches the query results i.e recent activity of a node and query name pair with filters applied.
        :param query_name: query_name to filter recent_activity
        :param host_identifier: host identifier of the node to filter recent_activity
        :param start: Pagination's start
        :param limit: Pagination's end
        :return: Returns list of query results for a node and query name pair.
        """
        payload = {'host_identifier': host_identifier, 'query_name': query_name, 'start': start, 'limit': limit}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + '/hosts/recent_activity'
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def search_query_data(self, search_conditions):
        """
        A conditions based search on recent activity.
        :param search_conditions: JSON array of conditions to filter recent activity.
        :return: JSON array of filtered recent_activity.
        """
        payload = search_conditions
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/search"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carves(self, host_identifier=None):
        """ Retrieve file carving  list.
               This API allows you to execute an on-demand query on the nodes.
               :param host_identifier: Node host_identifier for which the carves to fetched.
               :return: JSON response that contains list of file carving done.
        """
        payload = {'host_identifier': host_identifier}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/carves"

        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carve_by_query_id(self, query_id=None, host_identifier=None):
        """ Download the carved file using the sesion_id.
               This API allows you to execute an on-demand query on the nodes.
               :param session_id: session id of a carve to be downloaded.
               :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        payload = {'host_identifier': host_identifier, 'query_id': query_id}
        try:
            response = requests.post(
                self.base + "/carves/query", headers=headers, json=payload, verify=False, timeout=TIMEOUT_SECS)

        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def download_carve(self, session_id=None):
        """ Download the carved file using the sesion_id.
               This API allows you to execute an on-demand query on the nodes.
               :param session_id: session id of a carve to be downloaded.
               :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                self.base + "/carves/download/" + session_id, headers=headers, verify=False)
            return response.content
        except requests.RequestException as e:
            return dict(error=str(e))

    def take_action(self, data):
        """ This API allows you to take an action against a node through response action path.
            :return: JSON response of status and message about action took.
        """

        url = self.base + "/response/add"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_action_status(self, command_id):
        """ This API allows you to get status of an endpoint for response action path.
            :return: JSON response that contains status of the endpoint.
        """

        url = self.base + "/response/" + command_id
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)


class ApiError(Exception):
    pass


def _return_response_and_status_code(response, json_results=True):
    """ Output the requests response content or content as json and status code

    :rtype : dict
    :param response: requests response object
    :param json_results: Should return JSON or raw content
    :return: dict containing the response content and/or the status code with error string.
    """
    if response.status_code == requests.codes.ok:
        return dict(results=response.json() if json_results else response.content, response_code=response.status_code)
    elif response.status_code == 400:
        return dict(
            error='package sent is malformed.',
            response_code=response.status_code)
    elif response.status_code == 404:
        return dict(error='Requested URL not found.', response_code=response.status_code)

    else:
        return dict(response_code=response.status_code)
