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

directory = "C:\\Users\\%\\Downloads\\%"
sql = "select file.path,hash.md5 from file join  hash on hash.path=file.path where file.path like '" + directory + "';"


def main(domain=None, username=None, password=None):
    polylogyx_api = PolylogyxApi(domain=domain, username=username, password=password)

    request = polylogyx_api.send_distributed_query(sql=sql, tags=[],
                                                   host_identifiers=[args.host_identifier])
    if request['response_code'] and 'results' in request:
        if request['results']['status'] == 'success':

            try:
                query_data = polylogyx_api.get_distributed_query_results(
                    request['results']['query_id'])
                data = query_data.recv()
                return data

            except Exception as e:
                print(e)
        else:
            print (request['results']['message'])
    else:
        print("Error sending the query : ".format(sql))

    return

    # return json.dumps(hash_list)


def write_to_csv(result, host_identifier):
    headers = ['path', 'md5']
    base_folder_path = os.getcwd() + "/file_hashes/{0}/".format(host_identifier)
    file_name = base_folder_path + "{0}_file_hash.csv".format(time.time())
    try:
        os.makedirs(base_folder_path)
    except Exception as e:
        pass
    with open(file_name, 'w') as writeFile:
        writer = csv.writer(writeFile, delimiter=',')
        writer.writerows([headers])
        result = json.loads(result)
        result = result['data']
        for hash in result:
            writer.writerow([hash['path'], hash['md5']])
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
            print row


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


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

    parser.add_argument("--scan", type=str2bool, nargs='?',
                        const=True, default=False,
                        help="Scan acquired file hashes flag")

    parser.add_argument('--vt_api_key',

                        help='Vt Api Key')

    parser.add_argument('--limit', help='Limit', type=int)

    args = parser.parse_args()
    print('PolyLogyx')
    print('Acquiring list of files in the directory : {0}'.format(directory))
    res = main(args.domain, args.username, args.password)
    if res:
        print('Generating the csv of the acquired hashes..')
        filename = write_to_csv(res, args.host_identifier)
        print('Successfully generated the files at {0}'.format(filename))
        print('file {0} is created successfully'.format(filename))
        if args.scan:
            try:
                if args.vt_api_key:
                    print('Fetching virustotal reputation of the acquired indicators')
                    vt_score_path = fetch_vt_reputation.main(args.vt_api_key, filename)
                    anaylyse_vt_score_file(vt_score_path)
            except:
                print ("Please provide a virustotal key for getting reputations of the acquired hashes")
