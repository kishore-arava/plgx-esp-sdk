#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Script for scaning the CVE vulnerabilities from all installed applications .
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import time
import os
import sys
import json
import xlsxwriter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from v1.polylogyx_apis.api import PolylogyxApi


class Main:
    """
    Class to scan the additional apps or removed apps from a base host
    """
    count_per_iter = 5
    DEVIATED = 'DEVIATED'
    MATCHED = 'MATCHED'
    ADDED = 'ADDED'
    REMOVED = 'REMOVED'

    def __init__(self, domain=None, username=None, password=None, pack_name=None, host_identifier=None):
        self.api = PolylogyxApi(domain=domain, username=username, password=password)
        self.pack_name = pack_name
        self.host_identifier = host_identifier

        dir_name = os.getcwd() + '/installed_apps/'
        file_name = dir_name + 'installed_apps_{0}.xlsx'.format(int(time.time()))
        try:
            os.mkdir(dir_name)
        except:
            pass

        self.work_book = xlsxwriter.Workbook(file_name)
        self.merge_format = self.work_book.add_format({'bold': 1, 'border': 1, 'align': 'center',
                                                       'valign': 'vcenter', 'fg_color': 'yellow'})
        self.work_sheet = None
        self.host_query_matched_results = {}

    def run(self):
        """
        Main method
        :return: Returns nothing
        """
        base_results_dict = {}

        # fetches all hosts with the platform of the base host
        total_hosts = self.get_list_of_hosts_with_same_platform(host_identifier=self.host_identifier)

        # fetches all query names of the pack
        query_names_of_pack = self.get_all_query_names_of_pack(pack_name=self.pack_name)

        # Fetching all query results of base host for the packed queries to compare with all other hosts
        for query in query_names_of_pack:
            packed_query = "pack/{0}/{1}".format(self.pack_name, query)
            base_results_dict[query] = self.get_query_results(host_identifier=self.host_identifier,
                                                              query_name=packed_query)
        # writes base host's installed applications list to excel sheet
        self.write_apps_installed_in_base_host(base_results_dict)
        for host in total_hosts:
            if not host['host_identifier'] == self.host_identifier:
                self.host_query_matched_results = {}
                # adds new sheet to the excel file with host name as sheet name
                self.work_sheet = self.work_book.add_worksheet(host['display_name'])
                print("Started scanning host {} for additional programs installed...".format(host['host_identifier']))

                # Fetching all query results of host
                for query in query_names_of_pack:
                    packed_query = "pack/{0}/{1}".format(self.pack_name, query)
                    results = self.get_query_results(host_identifier=host['host_identifier'], query_name=packed_query)

                    # compares the results with base host results to find the deviation
                    self.analyze_results(base_results_dict[query], results, query)

                # writes the matched results to excel sheet
                self.write_matched_results_to_excel()
                print("Completed scanning host {} for additional programs installed...".format(host['host_identifier']))
        self.work_book.close()

    def get_list_of_hosts_with_same_platform(self, host_identifier):
        """
        Fetches hosts with the same platform as the base host for the host identifier given
        :param host_identifier: Base host's host identifier
        :return: Array of hosts
        """
        host = self.api.get_node(host_identifier=host_identifier)
        if host:
            platform = host['results']['data']['platform']
            if platform not in ["windows", "darwin", "freebsd"]:
                platform = "linux"
            hosts_count = self.api.get_nodes_distribution()
            total_hosts_count = hosts_count['results']['data'][platform]['online'] + hosts_count['results']['data'][platform]['offline']
            total_hosts = self.api.get_nodes(platform=platform, start=0, limit=total_hosts_count)
            return total_hosts['results']['data']['results']
        print("No host found with the given host identifier '{}', Quitting...".format(self.host_identifier))
        exit(0)

    def get_all_query_names_of_pack(self, pack_name):
        """
        Fetches all the query names of the queries associated with pack for the name given
        :param pack_name: Pack name with queries to find all installed apps and extended chrome apps
        :return: Array of query names
        """
        pack_response = self.api.get_all_packs()
        packs = pack_response['results']['data']['results']
        for pack in packs:
            if pack['name'] == pack_name:
                return [query['name'] for query in pack['queries']]
        print("No pack found with the given name '{}', Quitting...".format(pack_name))
        exit(0)

    def get_query_results(self, host_identifier, query_name):
        """
        Fetches recent activity
        :param host_identifier: Host identifier of the host
        :param query_name: Name of the query
        :param query_count: Total results count of the query of the host
        :return:
        """
        api_response = self.api.get_query_data(
                host_identifier=host_identifier,
                query_name=query_name, start=0, limit=self.count_per_iter)
        results = [result_log['columns'] for result_log in api_response['results']['data']['results']]
        iterations_count = api_response['results']['data']['total_count'] // self.count_per_iter
        for iter_num in range(1, iterations_count+1):
            start = iter_num * self.count_per_iter
            limit = (iter_num + 1) * self.count_per_iter
            results.extend([result_log['columns'] for result_log in self.api.get_query_data(
                host_identifier=host_identifier,
                query_name=query_name, start=start, limit=limit)['results']['data']['results']])
        return results

    def analyze_results(self, base_results, results, query):
        """
        :param base_results: Recent activity of the base_host
        :param results: Recent activity of the host to scan
        :param query: Name of the query
        :return: None
        """
        for result_json in base_results:
            for result in results:
                if result_json == result:
                    print("Entry {} matched..".format(result['name']))
                else:
                    if result_json['name'] == result['name']:
                        deviated = False
                        for key, value in result_json.items():
                            if not value == result[key]:
                                deviated = True
                                print("Entry {} deviated..".format(result['name']))
                                break
                        if deviated:
                            self.push_to_host_matched_results_array(query, result['name'], self.DEVIATED, result, result_json)
        if results:
            missing_apps_array = [i for i in base_results if i not in results]
            added_apps_array = [i for i in results if i not in base_results]
        else:
            missing_apps_array = []
            added_apps_array = []

        for result in missing_apps_array:
            print("App {} missing..".format(result['name']))
            self.push_to_host_matched_results_array(query, result['name'], self.REMOVED, '', result)
        for result in added_apps_array:
            print("App {} installed additionally..".format(result['name']))
            self.push_to_host_matched_results_array(query, result['name'], self.ADDED, result, '')

    def push_to_host_matched_results_array(self, query, name, status, actual_result, expected_result):
        """
        Pushes the results to the main dict per host with query name as key and array of results as value
        :param query: Name of query
        :param status: One of DEVIATED, ADDED, REMOVED
        :param actual_result: Result log columns of host
        :param expected_result: Result log columns of base host
        :return: None
        """
        if query in self.host_query_matched_results:
            self.host_query_matched_results[query].append({
                'name': name,
                'status': status,
                'actual_result': json.dumps(actual_result),
                'expected_result': json.dumps(expected_result)})
        else:
            self.host_query_matched_results[query] = [{
                'name': name,
                'status': status,
                'actual_result': json.dumps(actual_result),
                'expected_result': json.dumps(expected_result)}]

    def write_apps_installed_in_base_host(self, result_dict):
        """
        Writes all the applications installed in a host
        :param result_dict: Dict of query_name as key and array of results as value
        :return: None
        """
        work_sheet = self.work_book.add_worksheet('BaseHost')
        work_sheet.write(0, 0, "NAME")
        work_sheet.write(0, 1, "COLUMNS")
        row_count = 2
        for query, results_array in result_dict.items():
            if results_array:
                work_sheet.merge_range('A{}:B{}'.format(row_count, row_count), query, self.merge_format)
                for result in results_array:
                    work_sheet.write(row_count, 0, result['name'])
                    work_sheet.write(row_count, 1, json.dumps(result))
                    row_count += 1
                work_sheet.write(row_count, 0, '')
                work_sheet.write(row_count, 0, '')
                row_count += 2

    def write_matched_results_to_excel(self):
        """
        Writes matched results to excel sheet
        :return: None
        """
        self.work_sheet.write(0, 0, "NAME")
        self.work_sheet.write(0, 1, "STATUS")
        self.work_sheet.write(0, 2, "ACTUAL COLUMNS")
        self.work_sheet.write(0, 3, "EXPECTED COLUMNS")
        row_count = 2
        for query, results_array in self.host_query_matched_results.items():
            self.work_sheet.merge_range('A{}:C{}'.format(row_count, row_count), query, self.merge_format)
            for result in results_array:
                self.work_sheet.write(row_count, 0, result['name'])
                self.work_sheet.write(row_count, 1, result['status'])
                self.work_sheet.write(row_count, 2, result['actual_result'])
                self.work_sheet.write(row_count, 3, result['expected_result'])
                row_count += 1
            self.work_sheet.write(row_count, 0, '')
            self.work_sheet.write(row_count, 0, '')
            row_count += 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')
    parser.add_argument('--username', help='Admin username', required=True)
    parser.add_argument('--domain', help='Domain/Ip of the server', required=True)
    parser.add_argument('--password', help='Admin password', required=True)
    parser.add_argument('--pack_name', help='Name of the pack to get all installed programs', required=True)
    parser.add_argument('--host_identifier', help='Host identifier of the host with base image', required=True)
    args = parser.parse_args()
    main = Main(args.domain, args.username, args.password, args.pack_name, args.host_identifier)
    main.run()
