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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from v1.polylogyx_apis.api import PolylogyxApi
import subprocess


class Main:
    splitter = ','

    def __init__(self, domain=None, username=None, password=None, nvd_feed=None):
        self.api = PolylogyxApi(domain=domain, username=username, password=password)
        self.nvd_feed = nvd_feed
        self.sql_windows = """SELECT 'a' AS part, publisher AS vendor, name AS product, version \
        AS version FROM programs WHERE name IS NOT NULL AND name <> '';"""
        self.sql_darwin = """SELECT 'a' AS part, '' AS vendor, bundle_name AS product, bundle_version AS version FROM apps WHERE bundle_name IS NOT NULL AND bundle_name <> '';"""
        self.sql_ubuntu = """SELECT 'a' AS part, '' AS vendor, name AS product, version AS version FROM deb_packages WHERE name IS NOT NULL AND name <> '';"""
        self.sql_rhel = """SELECT 'a' AS part, '' AS vendor, name AS product, version AS version FROM rpm_packages WHERE name IS NOT NULL AND name <> '';"""
        self.command = """echo '{0}' | csv2cpe -x -lower -cpe_part=1 -cpe_vendor=2 -cpe_product=3 \
        -cpe_version=4 | cpe2cve -cpe 1 -e 1 -cve 1 {1}"""

    def run(self):
        hosts = self.get_active_hosts()
        if hosts:
            for host in hosts:
                vulnerable_found = False
                print("Scanning for vulnerabilities on installed applications in the host: {}".format(
                    host['host_identifier']))
                csv_array = self.get_installed_programs_csv(host)
                for csv in csv_array:
                    command = self.command.format(csv, self.nvd_feed)
                    output = subprocess.getoutput(command)
                    if output:
                        vulnerable_found = True
                        part, vendor, product, version = csv.split(self.splitter)
                        print(
                            "Vulnerable found for the application '{0}' with version '{1}' in the host '{2}' with the CVE: {3}" \
                                .format(product, version, host['host_identifier'], output))
                if not vulnerable_found:
                    print("No vulnerable found in the host: {}".format(host['host_identifier']))

    def run_command(self, command):
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        return iter(p.stdout.readline, b'')

    def get_active_hosts(self):
        api_response_data = self.api.get_nodes_distribution_count()['results']['data']
        nodes_count = api_response_data['windows']['online'] + api_response_data['linux']['online'] + api_response_data['darwin']['online']
        response = self.api.get_nodes(status=True, start=0, limit=nodes_count)
        if 'data' in response['results'] and 'results' in response['results']['data']:
            return response['results']['data']['results']
        return

    def get_installed_programs_csv(self, node):
        platform_sql_mappings = {"windows": self.sql_windows, "ubuntu": self.sql_ubuntu, "rhel": self.sql_rhel, "darwin": self.sql_darwin}
        request = self.api.send_distributed_query(sql=platform_sql_mappings.get(node['os_info']['platform']), tags=[],
                                                  host_identifiers=[node['host_identifier']])
        if request['response_code'] and 'results' in request:
            if request['results']['status'] == 'success':
                try:
                    query_data = self.api.get_distributed_query_results(
                        request['results']['data']['query_id'])
                    data = json.loads(query_data.recv())
                    filtered_list = []

                    if 'data' in data:
                        for result in data['data']:
                            vendor_word_list = result['vendor'].split(" ")
                            product = result['product']
                            vendor = result['vendor']
                            for item in vendor_word_list:
                                if item == "The":
                                    continue
                                else:
                                    vendor = item.lower()
                                    break
                            product_word_list = result['product'].split(" ")
                            for item in product_word_list:
                                if item == "The":
                                    continue
                                else:
                                    product = item.lower()
                                    break
                            filtered_list.append(
                                self.splitter.join([result['part'], vendor, product, result['version']]))
                    return filtered_list
                except Exception as e:
                    print(e)
            else:
                print(request['results']['message'])
        else:
            print("Error sending the query : ".format(platform_sql_mappings.get(node['os_info']['platform'])))
        return []


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')
    parser.add_argument('--username', help='Admin username', required=True)
    parser.add_argument('--domain', help='Domain/Ip of the server', required=True)
    parser.add_argument('--password', help='Admin password', required=True)
    parser.add_argument('--nvd_feed', help='Path of the json.gz formatted nvd feed file', required=True)
    args = parser.parse_args()
    main = Main(args.domain, args.username, args.password, args.nvd_feed)
    main.run()
