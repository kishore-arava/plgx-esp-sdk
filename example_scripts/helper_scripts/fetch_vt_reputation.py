#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to get the vt reputation from the list of indicators using a csv file.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import time
from functools import reduce

from virus_total_apis import PublicApi as VirusTotalPublicApi
import pandas as pd

indicators = ['md5', 'sha1', 'sha256', 'hash']
sleep_time = 15
max_indicators_per_request = 4


def main(vt_api_key, file_path):
    vt = VirusTotalPublicApi(vt_api_key)
    return read_csv(file_path, vt)


def read_csv(file_path, vt):
    import csv
    unique_indicators = []
    with open(file_path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        indicator_column_exist = False
        indicator_index = -1
        existing_indicators = []
        for row in csv_reader:
            if line_count == 0:
                # print(f'Column names are {", ".join(row)}')
                for column in row:
                    if column in indicators:
                        indicator_column_exist = True
                        indicator_index = row.index(column)
                        break
                if not indicator_column_exist:
                    raise Exception("No valid indicators provided")

                line_count += 1
            else:
                existing_indicators.append(row[indicator_index])
                line_count += 1
        unique_indicators = reduce(lambda l, x: l if x in l else l + [x], existing_indicators, [])

    x = list(divide_chunks(unique_indicators, max_indicators_per_request))
    print("{0} indicators found".format(str(len(unique_indicators))))
    import os
    file_name = os.path.basename(file_path)  # eds_report.csv
    location = os.path.dirname(file_path)
    file_vt_score_output_path = location + "/" + file_name.split(".")[0] + "_vt_reputation" + "." + \
                                file_name.split(".")[1]
    df = pd.read_csv(file_path)
    bad_hashes = 0

    for i in range(len(x)):
        indicator_list = x[i]
        current_max=(i + 1) * 4
        if current_max>len(unique_indicators):
            current_max=len(unique_indicators)
        print(("Fetching virustotal reputation for indicator : {0}".format(
            str(i * 4 + 1) + "-" + str(current_max) + " of " + str(len(unique_indicators)))))
        response = vt.get_file_report(",".join(indicator_list))

        if response['response_code'] == 200 and 'results' in response and len(response['results']) > 0:
            for result in response['results']:
                if 'resource' in result:
                    if 'positives' in response['results']:
                        if response['results']['positives'] > 0:
                            bad_hashes += 1
                        score = str(response['results']['positives']) + "/" + str(response['results']['total'])
                        df.loc[df[column] == response['results']['resource'], 'vt_score'] = score

                    elif 'positives' in result:
                        if result['positives'] > 0:
                            bad_hashes += 1
                        score = str(result['positives']) + "/" + str(result['total'])
                        df.loc[df[column] == result['resource'], 'vt_score'] = score

        time.sleep(sleep_time)
    df.to_csv(file_vt_score_output_path, encoding='utf-8', index=False)
    if bad_hashes > 0:
        print("{0} bad indicator present".format(str(bad_hashes)))
    else:
        print("No bad indicator present")
    print("Created a file with the vt_score at : " + file_vt_score_output_path)
    return file_vt_score_output_path


def divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VT API key.')

    parser.add_argument('--vt_api_key', help='VT API key', required=True)
    parser.add_argument('--file_path', help='CSV File Path', required=True)
    args = parser.parse_args()

    main(args.vt_api_key, args.file_path)
