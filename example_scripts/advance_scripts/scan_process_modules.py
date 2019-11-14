#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import ast
import os
import tarfile
import time
import glob
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from polylogyx_apis.api import PolylogyxApi

polylogyx_api = None
carve_wait_time = 30
SUSPICIOUS_QUERY = "select * from win_suspicious_process_scan where modules_suspicious >0 and (modules_replaced>0 or modules_detached>0 or modules_hooked>0 or modules_implanted);"


def download_carve(host_identifier, session_id, suspiciousProcess):
    base_folder_path = os.getcwd() + '/suspicious_process/' + host_identifier + '/' + str(int(time.time()))
    file = polylogyx_api.download_carve(session_id=session_id)
    file_path = base_folder_path + '/' + session_id + ".tar"
    try:
        os.makedirs(base_folder_path)
    except OSError as e:
        print(e)
        pass
    with open(file_path, 'wb') as s:
        s.write(file)
    untar_file(file_path, base_folder_path + '/' + session_id, suspiciousProcess)


def untar_file(file_path, dir, suspiciousProcess):
    tar = tarfile.open(file_path)
    tar.extractall(path=dir)  # untar file into same directory
    tar.close()
    read_tag_file(dir, suspiciousProcess)


def read_tag_file(folder_path, suspiciousProcess):
    os.chdir(folder_path)
    suspicious_module_count = 0
    for file in glob.glob("*.dll.tag"):
        f = open(folder_path + "/" + file, "r")
        lines = f.readlines()
        for line in lines:
            if "[" in line and "]" in line:
                substring = line[line.index("[") + len("["):line.index("]")]
                module_array = substring.split(":")
                if len(module_array) == 3:
                    module_name = module_array[1]
                    if module_array[2] == '1':
                        print(file + " is having a suspicious module with name : " + module_name)
                        suspicious_module_count += 1
                    else:
                        print(file + " is having a non suspicious module with name : " + module_name)
                else:
                    print("Invalid format for a module in " + file)
        if suspicious_module_count:
            print('{0} modules are suspicious in the process : {1}'.format(str(suspicious_module_count),
                                                                           suspiciousProcess['process_name']))
        else:
            print('There is no suspicious module in the process : {0}'.format(suspiciousProcess['process_name']))


def main(domain, username, password, host_identifier):
    global polylogyx_api
    polylogyx_api = PolylogyxApi(domain=domain, username=username,
                                 password=password)
    fetch_suspicous_process_data(host_identifier)


def fetch_suspicous_process_data(host_identifier):
    suspicous_process_query_results = get_distributed_query_data_over_websocket(SUSPICIOUS_QUERY, host_identifier)
    if len(suspicous_process_query_results)>0:
        for i in range(len(suspicous_process_query_results)):
            suspiciousProcess = suspicous_process_query_results[i]
            suspicious_dump_sql = 'select * from win_suspicious_process_dump where pid=' + suspiciousProcess[
                'pid'] + ';'
            suspicous_process_dumps_location = get_distributed_query_data_over_websocket(suspicious_dump_sql,
                                                                                         host_identifier)
            print('Acquiring process dump {0}/{1} from the host : {2}'.format(str(i + 1),
                                                                              str(len(suspicous_process_query_results)),
                                                                              host_identifier))
            suspicious_dump_carve_query = "select * from carves where path like '" + \
                                          suspicous_process_dumps_location[0][
                                              'process_dumps_location'] + "\\%' and carve=1;"
            request = polylogyx_api.send_distributed_query(sql=suspicious_dump_carve_query, tags=[],
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
                print("Error sending the query : ".format(suspicious_dump_carve_query))
    else:
        print("No suspicious processes found for the host : {0}".format(host_identifier))


def sleep_and_download_file(host_identifier, suspiciousProcess,query_id):
    time.sleep(carve_wait_time)
    carve_response = polylogyx_api.get_carve_by_query_id(host_identifier=host_identifier, query_id=query_id)
    if 'results' in carve_response and 'data' in carve_response['results']:
        carve = carve_response['results']['data']
        if carve['archive']:
            download_carve(host_identifier, carve['session_id'])
        else:
            sleep_and_download_file(host_identifier,suspiciousProcess, query_id)
    else:
        sleep_and_download_file(host_identifier,suspiciousProcess, query_id)


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
    print('PolyLogyx')
    print('Scanning for suspicious process modules across all the hosts.')

    main(args.domain, args.username, args.password, args.host_identifier)
