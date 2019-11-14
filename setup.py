#!/usr/bin/env python
import os
import sys

from codecs import open

from setuptools import setup

import polylogyx_apis

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

version = polylogyx_apis.__version__

if not version:
    raise RuntimeError('Cannot find version information')

with open('README.rst', 'r', 'utf-8') as f:
    readme = f.read()

setup(name='polylogyx-api',
      version=polylogyx_apis.__version__,
      description='PolyLogyx REST API',
      long_description=readme ,
      url='https://github.com/polylogyx/polylogyx-api',
      author='polylogyx',
      author_email='info@polylogyx.com',
      license=polylogyx_apis.__license__,
      zip_safe=False,
      classifiers=['Development Status :: 5 - Production/Stable',
                   'Intended Audience :: Developers',
                   'Natural Language :: English',
                   'License :: OSI Approved :: MIT License',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3.7',],
      packages=['polylogyx_apis'],
      package_data={'': ['LICENSE', 'NOTICE']},
      package_dir={'polylogyx_apis': 'polylogyx_apis'},
      include_package_data=True,
      install_requires=["requests >= 2.2.1","websocket_client>=0.13.0","pandas>=0.22.0"])
