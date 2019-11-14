#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import ast
import csv
import json
import os
import re
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))

from example_scripts.helper_scripts import fetch_hash_from_path, fetch_vt_reputation
from polylogyx_apis.api import PolylogyxApi

AUTORUN_QUERIES = {
    'BootExecute': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager%%' and name='BootExecute';",
    ],
    'office addon': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Office\Outlook\Addins%%' and name='FileName';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Office\Excel\Addins%%';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Office\Excel\Addins%%';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Office\PowerPoint\Addins%%';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Office\PowerPoint\Addins%%';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Office\Word\Addins%%';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Office\Word\Addins%%';"
    ],
    'Hijacks': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Htmlfile\Shell\Open\Command%%';",
    ],
    'Drivers & services': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services%%' and name='ImagePath';",
    ],
    'Font Drivers': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers%%';",
    ],
    'winlogon': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GpExtensions%%' and name='DllName';",
    ],
    'Print Monitors': [
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors%%' and name='Driver';",
    ],
    'WinSock': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries%%' and name='ProtocolName';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\\System\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries%%' and name='LibraryPath';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64%%' and name='ProtocolName';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64%%' and name='LibraryPath';",
    ],
    'LSA Providers': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders%' and name='SecurityProviders';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa%' and name = 'Authentication Packages';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa%' and name = 'Notification Packages';",
    ],
    'Network Providers': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order%';",
    ],
    'Logon': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd%' and name='StartupPrograms';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon%' and name='Userinit';",
        "select name, data from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon%' and name='VMApplet';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon%' and name='Shell';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot%' and name='AlternateShell';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run%';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components%%' and name='StubPath';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components%%' and name='StubPath';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows%' and name='IconServiceLib';",
    ],
    'KnownDlls': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDlls%';",
    ],
    'Internet Explorer': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Extensions%%' and name='HotIcon';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions%%' and name='HotIcon';",
    ],
    'codecs': [
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Drivers32%';",
        "select name, data, type from registry where key like 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32%';",
    ],
    'clsid': [
        "select name, data, key from registry where key like 'HKEY_CLASSES_ROOT\CLSID\%\InProcServer32%%' and name like '%Default%';",
    ]
    ,
    'Queries in current users': [
        "select name, data, type from registry where key like 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%';",
        "select name, data, type from registry where key like 'HKEY_CURRENT_USER\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run%';"
    ]
}

polylogyx_api = None

result_dict = {}


def main(domain, username, password, host_identifier):
    global polylogyx_api
    polylogyx_api = PolylogyxApi(domain=domain, username=username,
                                 password=password)
    host_identifiers = host_identifier.split(',')
    path_parser = PathParser()
    finished=False
    for host_identifier in host_identifiers:
        print('Scanning for autoruns from the host : {0}'.format(host_identifier))

        hashes = []
        for name, queries in AUTORUN_QUERIES.items():
            print ("Getting data for the {0}".format(name))
            if finished:
                break
            for i in range(len(queries)):
                query = queries[i]
                print ("Getting data for the query {0}".format(str(i + 1) + "/" + str(len(queries)) + " " + name))

                query_results = get_distributed_query_data_over_websocket(query, host_identifier)
                response = path_parser.parse_resgistry_paths(query_results, name)
                hashes.extend(response)

                if args.limit and len(hashes) >= args.limit:
                    hashes = hashes[0:args.limit]
                    finished=True
                    break
        file_path=write_to_csv(hashes, host_identifier)
        print ("Fetching hashes for the path obtained")
        filepath = fetch_hashes(args.domain, args.username, args.password, host_identifier,file_path)
        print ("Fetching virustotal reputation for the hashes obtained")
        vt_score_path = fetch_vt_reputation.main(args.vt_api_key, filepath)
        anaylyse_vt_score_file(vt_score_path, host_identifier)


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


def write_to_csv(hashes, host_identifier):
    base_folder_path = os.getcwd() + '/autoruns/' + host_identifier + '/' + str(int(time.time()))
    try:
        os.makedirs(base_folder_path)
    except OSError as e:
        print(e)
        pass
    file_path = base_folder_path + '/' + 'autorun.csv'
    columns = hashes[0].keys()

    with open(file_path, 'w') as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=columns)
        writer.writeheader()
        for hash in hashes:
            writer.writerow(hash)

    csvFile.close()
    return file_path


def fetch_hashes(domain, username, password, host_identifier,file_path):
    file_hash_path = fetch_hash_from_path.main(domain, username, password, host_identifier, file_path,args.limit)
    return file_hash_path


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
        print row


class PathParser:

    def parse_resgistry_paths(self, input_list, name):
        hashes = []
        json.dumps(input_list)
        for input in input_list:
            input = input['data']

            self.process_path_with_quotes(input, name, hashes)
        return hashes

    def process_path_string(self, input, name, hashes):
        self.process_path_with_quotes(input, name, hashes)
        self.process_path_containing_comma(input, name, hashes)
        self.process_path_with_spaces(input, name, hashes)
        self.process_path_without_spaces(input, name, hashes)

    def process_path_with_quotes(self, input, name, hashes):
        file_paths_within_quotes = re.findall(r'"(.*?)"', input)
        if len(file_paths_within_quotes) > 0:
            for path in file_paths_within_quotes:
                self.process_path_containing_comma(path, name, hashes)
                input = input.replace('"' + path + '"', '')
        else:
            input = self.process_path_containing_comma(input, name, hashes)
        return input

    def process_path_containing_comma(self, input, name, hashes):
        if "," in input:
            file_path_separated_by_comma = input.split(",")
            for path in file_path_separated_by_comma:
                if path and path[0] != "-":
                    hashes.append({'path': path.split(" ")[0], 'name': name})
                input = input.replace(path, '')
            input = input.replace(",", '')
        else:
            input = self.process_path_with_spaces(input, name, hashes)
        return input

    def process_path_with_spaces(self, input, name, hashes):
        file_paths_with_spaces = re.findall(r'\S+\\\S+\s\S+\\\S+\.\S+', input)
        if len(file_paths_with_spaces):
            for path in file_paths_with_spaces:
                input = input.replace(path, '')
                hashes.append({'path': '"' + path + '"', 'name': name})
        input = self.process_path_without_spaces(input, name, hashes)
        return input

    def process_path_without_spaces(self, input, name, hashes):
        file_paths_without_spaces = re.findall(r'\S+\.\S+', input)
        for path in file_paths_without_spaces:
            input = input.replace(path, '')
            hashes.append({'path': path, 'name': name})
        return input


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

    parser.add_argument('--limit',

                        help='Limit',type=int)
    args = parser.parse_args()
    print('PolyLogyx')
    print('Scanning for autoruns across the hosts... ')
    main(args.domain, args.username, args.password, args.host_identifier)
