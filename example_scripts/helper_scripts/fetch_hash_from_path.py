#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import ast
import json
from functools import reduce

from polylogyx_apis.api import PolylogyxApi

path_column_name = 'path'
polylogyx_api = None
max_hash_per_request = 100

polylogyx_api=None

def main(domain, username, password, host_identifier, file_path, limit):
    global polylogyx_api
    polylogyx_api = PolylogyxApi(domain=domain, username=username,
                                 password=password)

    return read_csv(file_path, host_identifier, limit)


def read_csv(file_path, host_identifier, limit):
    import csv
    with open(file_path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        indicator_index = -1
        existing_paths = []
        for row in csv_reader:
            if line_count == 0:
                if path_column_name in row:
                    indicator_index = row.index(path_column_name)
                else:
                    raise Exception("No valid path provided")

                line_count += 1
            else:
                existing_paths.append(row[indicator_index])
                line_count += 1
        unique_paths = reduce(lambda l, x: l if x in l else l + [x], existing_paths, [])

        if limit and len(unique_paths) >= limit:
            unique_paths = unique_paths[0:limit]

        path_groups = list(divide_chunks(unique_paths, max_hash_per_request))

        if len(unique_paths) > 0:
            import os
            file_name = os.path.basename(file_path)
            location = os.path.dirname(file_path)
            file_hash_output_path = location + "/" + file_name.split(".")[0] + "_hash" + "." + file_name.split(".")[1]
            columns = ['path', 'md5']
            with open(file_hash_output_path, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(columns)

                for path_list in path_groups:
                    if len(path_list) > 1:
                        t = tuple(path_list)
                        query = 'SELECT path,md5 FROM win_hash WHERE path IN {}'.format(t)
                    elif len(path_list) == 1:
                        query = "SELECT path,md5 FROM win_hash WHERE path  ='" + path_list[0] + "'"

                    query_id = polylogyx_api.send_distributed_query(sql=query, tags=[],
                                                                    host_identifiers=[host_identifier])
                    try:
                        conn = polylogyx_api.get_distributed_query_results(
                            query_id['results']['query_id'])
                        result = conn.recv()
                        result = result.decode('utf8')
                        results = ast.literal_eval(result)
                        if 'data' in results and len(results['data']) > 0:
                            for elem in results['data']:
                                writer.writerow([elem['path'], elem['md5']])
                    except Exception as e:
                        print ("Error getting hashes for file paths")
                print("Created a file with the hashes at : " + file_hash_output_path)
                return file_hash_output_path


def divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')

    parser.add_argument('--username',

                        help='Admin username', required=True)

    parser.add_argument('--domain',

                        help='Domain/Ip of the server', required=True)
    parser.add_argument('--password',

                        help='Admin password', required=True)

    parser.add_argument('--file_path',

                        help='CSV File Path', required=True)
    parser.add_argument('--host_identifier',

                        help='host_identifer of agent', required=True)

    args = parser.parse_args()

    main(args.domain, args.username, args.password, args.host_identifier, args.file_path, args.limit)
