#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Script for scaning the CVE vulnerabilities from all installed applications .
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import os
import sys
import json
from scripts.v1.polylogyx_apis.api import PolylogyxApi

sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))


class Main:
    def __init__(self, domain=None, username=None, password=None, nvd_feed=None):
        self.api = PolylogyxApi(domain=domain, username=username, password=password)
        self.nvd_feed = nvd_feed
        self.sql_windows = """SELECT 'a' AS part, publisher AS vendor, name AS product, version \
        AS version FROM programs WHERE name IS NOT NULL AND name <> '';"""
        self.sql = self.sql_windows
        self.command = """echo '{0}' | csv2cpe -x -lower -cpe_part=1 -cpe_vendor=2 -cpe_product=3 \
        -cpe_version=4 | cpe2cve -cpe 1 -e 1 -cve 1 {1}"""

    def run(self):
        all_windows_hosts = self.get_active_windows_hosts()
        if all_windows_hosts:
            for host in all_windows_hosts:
                csv_array = self.get_installed_programs_csv(host)
                for csv in csv_array:
                    command = self.command.format(csv.decode('utf-8'), self.nvd_feed)
                    print os.system(command)

    def get_active_windows_hosts(self):
        nodes_count = self.api.get_nodes_distribution_count()['results']['data']['windows']['online']
        response = self.api.get_nodes(platform='windows', status=True, start=0, limit=nodes_count)
        if 'data' in response['results'] and 'results' in response['results']['data']:
            return response['results']['data']['results']
        return

    def get_installed_programs_csv(self, node):
        request = self.api.send_distributed_query(sql=self.sql, tags=[],
                                                  host_identifiers=[node['host_identifier']])
        if request['response_code'] and 'results' in request:
            if request['results']['status'] == 'success':
                try:
                    query_data = self.api.get_distributed_query_results(
                        request['results']['data']['query_id'])
                    data = json.loads(query_data.recv())
                    if 'data' in data:
                        return [','.join([result['part'], result['vendor'], result['product'], result['version']]) \
                                for result in data['data']]
                except Exception as e:
                    print(e)
            else:
                print (request['results']['message'])
        else:
            print("Error sending the query : ".format(self.sql))
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')
    parser.add_argument('--username', help='Admin username', required=True)
    parser.add_argument('--domain', help='Domain/Ip of the server', required=True)
    parser.add_argument('--password', help='Admin password', required=True)
    parser.add_argument('--nvd_feed', help='Path of the json.gz formatted nvd feed file', required=True)

    args = parser.parse_args()
    main = Main(args.domain, args.username, args.password, args.nvd_feed)
    main.run()
