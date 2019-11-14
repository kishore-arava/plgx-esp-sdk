
polylogyx-api
==============


Installation
------------

Install the additional dependencies using the below command

.. code-block:: bash

    $ python setup.py install


Usage
-----
.. code-block:: python

    from __future__ import print_function
    import json
    from polylogyx_apis import PolylogyxApi

    polylogyx_api = PolylogyxApi(domain='<IP/DOMAIN>', username='<USERNAME>',password='<PASSWORD>')
    response = polylogyx_api.get_nodes()
    print(json.dumps(response, sort_keys=False, indent=4))



Documentation
-------------

You're looking at it.


License
-------

MIT Copyright (c) 2019 **polylogyx**
