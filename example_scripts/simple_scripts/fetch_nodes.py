#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple scripts to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
"""

import argparse
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.getcwd())))
from polylogyx_apis.api import PolylogyxApi


def main(domain=None, username=None, password=None):
    polylogyx_api = PolylogyxApi(domain=domain, username=username, password=password)

    response=polylogyx_api.get_nodes()

    print(json.dumps(response, sort_keys=False, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')

    parser.add_argument('--username',

                        help='Admin username', required=True)

    parser.add_argument('--domain',

                        help='Domain/Ip of the server', required=True)
    parser.add_argument('--password',

                        help='Admin password', required=True)

    args = parser.parse_args()

    main(args.domain, args.username, args.password)
