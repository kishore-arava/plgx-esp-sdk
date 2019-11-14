#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Script for getting the reputation of all indicators collected in last 24 hrs from virustotal .
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import json
import math
import time
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from example_scripts.helper_scripts import fetch_vt_reputation
from polylogyx_apis.api import PolylogyxApi


def main(domain=None, username=None, password=None):
    polylogyx_api = PolylogyxApi(domain=domain, username=username, password=password)

    current_time = int(time.time())
    start_time = current_time - 24 * 60 * 60
    indicators = ['md5', 'sha1', 'sha256']

    indicator_not_empty_rules = []
    hash_list = {}
    for indicator in indicators:
        hash_list[indicator] = {}
        indicator_not_empty_rules.append(
            {"id": indicator, "field": indicator, "type": "string", "input": "text", "operator": "is_not_empty",
             "value": ''})
    per_page_count = 10
    if args.pid:
        search_json = {"condition": "AND",
                       "rules": [{"condition": "OR", "rules": indicator_not_empty_rules},
                                 {"condition": "AND", "rules": [
                                     {"id": "time", "field": "time", "type": "string", "input": "text",
                                      "operator": "less_or_equal",
                                      "value": current_time},
                                     {"id": 'pid', "field": 'pid', "type": "string", "input": "text",
                                      "operator": "equal",
                                      "value": args.pid},
                                     {"id": "time", "field": "time", "type": "string", "input": "text",
                                      "operator": "greater_or_equal",
                                      "value": start_time}]}], "valid": True}
    else:
        search_json = {"condition": "AND",
                       "rules": [{"condition": "OR", "rules": indicator_not_empty_rules},
                                 {"condition": "AND", "rules": [
                                     {"id": "time", "field": "time", "type": "string", "input": "text",
                                      "operator": "less_or_equal",
                                      "value": current_time},
                                     {"id": "time", "field": "time", "type": "string", "input": "text",
                                      "operator": "greater_or_equal",
                                      "value": start_time}]}], "valid": True}
    response = polylogyx_api.search_query_data({"conditions": search_json})
    acquired_results = 0
    if response['response_code'] == 200 and 'results' in response and 'data' in response['results']:

        for key, value in response['results']['data'].items():
            if args.limit and acquired_results >= args.limit:
                break
            for query_result in value:
                total_results = query_result['count']
                if args.limit and acquired_results >= args.limit:
                    break
                for x in range(0, int(math.ceil(float( total_results) / float(per_page_count)))):
                    response_query_result = polylogyx_api.search_query_data(
                        {"conditions": search_json, "host_identifier": key,
                         "query_name": query_result['query_name'],
                         "start": x * per_page_count,

                         "limit": per_page_count})

                    if response_query_result[
                        'response_code'] == 200 and 'results' in response_query_result and 'data' in \
                            response_query_result['results']:
                        for entry in response_query_result['results']['data']:
                            for indicator in indicators:
                                if indicator in entry and entry[indicator]:
                                    if entry[indicator] in hash_list[indicator]:
                                        hash_list[indicator][entry[indicator]] = hash_list[indicator][
                                                                                     entry[indicator]] + " " + key
                                    else:
                                        hash_list[indicator][entry[indicator]] = key
                        acquired_results = acquired_results+per_page_count

                    if args.limit and acquired_results >=args.limit:
                        break

    return json.dumps(hash_list)


def write_to_csv(result):
    headers = ['hash', 'hosts']
    file_name = os.getcwd() + '/suspicious_ioc/suspicious_ioc_hash.csv'
    try:
        os.mkdir(os.getcwd() + '/suspicious_ioc/')
    except Exception:
        pass
    with open(file_name, 'w') as writeFile:
        writer = csv.writer(writeFile, delimiter=',')
        writer.writerows([headers])
        result = json.loads(result)
        for data in result:
            for hash in result[data]:
                if hash:
                    writer.writerow([hash, result[data][hash]])
    return file_name


def anaylyse_vt_score_file(file_path):
    with open(file_path, 'rb') as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            try:
                vt_score_num_denom = row['vt_score'].split("/")
                if len(vt_score_num_denom) > 1:
                    if float(float(vt_score_num_denom[0]) / float(vt_score_num_denom[1])):
                        rows.append(row)
            except Exception as e:
                pass
    if len(rows) > 0:
        print ("Bad indicators are:")
        for row in rows:
            print (row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')

    parser.add_argument('--username',

                        help='Admin username', required=True)

    parser.add_argument('--domain',

                        help='Domain/Ip of the server', required=True)
    parser.add_argument('--password',

                        help='Admin password', required=True)
    parser.add_argument('--vt_api_key',

                        help='Vt Api Key', required=True)

    parser.add_argument('--limit', help='Limit', type=int)
    parser.add_argument('--pid', help='Process ID')

    args = parser.parse_args()
    print('PolyLogyx')
    print('Acquiring indicators collected in the last 24 hours and match with VirusTotal to lookup for the reputation')
    res = main(args.domain, args.username, args.password)
    if res:
        print('Generating the csv of the acquired hashes..')
        filename = write_to_csv(res)
        print('Successfully generated the files at {0}'.format(filename))
        print('file {0} is created successfully'.format(filename))
        print('Fetching virustotal reputation of the acquired indicators')
        vt_score_path = fetch_vt_reputation.main(args.vt_api_key, filename)
        anaylyse_vt_score_file(vt_score_path)
    else:
        print('No indicators present')