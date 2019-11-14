#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse

import os
import tarfile
import time
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from example_scripts.helper_scripts import prefetch
from polylogyx_apis.api import PolylogyxApi

PREFETCH_QUERY = "select carve(path) from file where path like 'C:\WINDOWS\Prefetch\%.pf' ;"
carve_wait_time = 30

polylogyx_api=None
def main(domain, username, password, host_identifier):
    global polylogyx_api

    polylogyx_api = PolylogyxApi(domain=domain, username=username,
                                 password=password)

    sql = PREFETCH_QUERY
    print ("PolyLogyx")
    print ("Acquiring prefetch files for the node : {0}".format(host_identifier))

    request = polylogyx_api.send_distributed_query(sql=sql, tags=[],
                                                   host_identifiers=[args.host_identifier])
    if request['response_code'] and 'results' in request:
        if request['results']['status'] == 'success':

            try:
                query_data = polylogyx_api.get_distributed_query_results(
                    request['results']['query_id'])

                data = query_data.recv()
                sleep_and_download_file(host_identifier, request['results']['query_id'])

            except Exception as e:
                print(e)
        else:
            print (request['results']['message'])
    else:
        print("Error sending the query : ".format(sql))


def untar_file(file_path, dir):
    tar = tarfile.open(file_path)
    tar.extractall(path=dir)  # untar file into same directory
    tar.close()
    anylase_using_prefetch(file_path, dir)


def anylase_using_prefetch(file_path, dir):
    prefetch.main(["prefetch.py", "--directory", dir + "/"])


def sleep_and_download_file(host_identifier, query_id):
    time.sleep(carve_wait_time)
    carve_response = polylogyx_api.get_carve_by_query_id(host_identifier=host_identifier, query_id=query_id)
    if 'results' in carve_response and 'data' in carve_response['results']:
        carve = carve_response['results']['data']
        if carve['archive']:
            download_carve(host_identifier, carve['session_id'])
        else:
            sleep_and_download_file(host_identifier, query_id)
    else:
        sleep_and_download_file(host_identifier, query_id)


def download_carve(host_identifier, session_id):
    base_folder_path = os.getcwd() + '/prefetch/' + host_identifier + '/' + str(int(time.time()))
    file = polylogyx_api.download_carve(session_id=session_id)
    file_path = base_folder_path + '/' + session_id + ".tar"
    try:
        os.makedirs(base_folder_path)
    except OSError as e:
        print(e)
        pass
    with open(file_path, 'wb') as s:
        s.write(file)
    untar_file(file_path, base_folder_path + '/' + session_id)


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

    args = parser.parse_args()

    main(args.domain, args.username, args.password, args.host_identifier)
