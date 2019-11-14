#!/usr/bin/env python
# -*- coding: utf-8 -*-

__title__ = 'polylogyx-api'
__version__ = '1.0.0'
__author__ = 'PolyLogyx'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2019 PolyLogyx'

try:
    import requests
except ImportError:
    pass

from .api import PolylogyxApi, ApiError
