#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import ast
import binascii
import csv
import os
import sys
import time

if sys.version_info[0] >= 3 or sys.version_info[0] < 2  :
    raise Exception("Must be using Python 2.* to run this script")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from example_scripts.helper_scripts import ShimCacheParser

from example_scripts.helper_scripts import fetch_hash_from_path, fetch_vt_reputation
from polylogyx_apis.api import PolylogyxApi

APPCOMPAT_SHIM_QUERY = "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache%%' and name='AppCompatCache';"

polylogyx_api = None


def get_distributed_query_data_over_websocket(sql, host_identifier):
    response = polylogyx_api.send_distributed_query(sql=sql, tags=[],
                                                    host_identifiers=[host_identifier])
    if response['response_code'] == 200 and 'results' in response:
        if response['results']['status'] == 'success':

            query_id_conn = polylogyx_api.get_distributed_query_results(
                response['results']['query_id'])
            result = query_id_conn.recv()
            result = result.decode('utf8')

            query_results = ast.literal_eval(result)
            query_results = query_results['data']
            return query_results
        else:
            print(response['results']['message'])
    return []


def analyse_binary_file(source_file_path, output_path, host_identifier, creds):

    ShimCacheParser.main(["ShimCacheParser.py", "-b", source_file_path, "-o", output_path])

    print ("Acquiring hashes for the obtained file paths...")

    with open(output_path, 'rb') as inp, open(output_path.replace("appcompat.csv", "appcompat_limit.csv"), 'wb') as out:
        writer = csv.writer(out)
        current_index = 0
        for row in csv.reader(inp):
            current_index = current_index + 1
            if current_index >= args.limit:
                break
            writer.writerow(row)
    output_path = output_path.replace("appcompat.csv", "appcompat_limit.csv")

    output_hash_path = fetch_hash_from_path.main(creds['domain'], creds['username'], creds['password'], host_identifier,
                                                 output_path, args.limit)

    print ("Fetching virustotal for the collected hashes...")
    file_score_path = fetch_vt_reputation.main(args.vt_api_key, output_hash_path)

    return file_score_path


def main(domain, username, password, host_identifier, vt_api_key):
    global polylogyx_api
    creds = {'username': username, 'password': password, 'domain': domain, 'vt_api_key': vt_api_key}
    polylogyx_api = PolylogyxApi(domain=domain, username=username,
                                 password=password)
    host_identifiers = host_identifier.split(',')

    for host_identifier in host_identifiers:
        print("Acquiring binary file from host : {0}".format(host_identifier))
        response = get_distributed_query_data_over_websocket(APPCOMPAT_SHIM_QUERY, host_identifier)
        if response and len(response) > 0 and 'data' in response[0]:
            base_folder_path = os.getcwd() + '/appcompat/' + host_identifier + '/' + str(
                int(time.time()))
            try:
                os.makedirs(base_folder_path)
            except OSError as e:
                pass
            file_path = base_folder_path + '/' + 'appcompat.bin'
            with open(file_path, 'wb') as f:
                hb = binascii.a2b_hex(response[0]['data'])
                f.write(hb)
                f.close()
                print('Generated appcompat bin file for host  : {0} at {1}'.format(host_identifier,
                                                                                   file_path))
            vt_score_path = analyse_binary_file(file_path, base_folder_path + '/' + "appcompat.csv", host_identifier,
                                                creds)

            anaylyse_vt_score_file(vt_score_path, host_identifier)

        else:
            print("Nothing to acquire from the host : {0}".format(host_identifier))


def anaylyse_vt_score_file(file_path, host_identifier):
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

    for row in rows:
        print(row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')

    parser.add_argument('--username',

                        help='Admin username', required=True)

    parser.add_argument('--domain',

                        help='Domain/Ip of the server', required=True)
    parser.add_argument('--password',

                        help='Admin password', required=True)
    parser.add_argument('--host_identifier',

                        help='host_identifer of agent', required=True)

    parser.add_argument('--vt_api_key',

                        help='Vt Api Key', required=True)
    parser.add_argument('--limit', help='Limit', type=int)

    args = parser.parse_args()

    print('PolyLogyx')
    print('Checking for app compatibility across the hosts... ')

    main(args.domain, args.username, args.password, args.host_identifier, args.vt_api_key)


