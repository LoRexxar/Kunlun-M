# -*- coding: utf-8 -*-

"""
    demo
    ~~~~

    just demo for secret 

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

PHP_IS_REPAIR_DEFAULT = {
    "urlencode": [1000, 10001, 10002],
    "rawurlencode": [1000, 10001, 10002],
    "htmlspecialchars": [1000, 10001, 10002],
    "htmlentities": [1000, 10001, 10002],
    "md5": [1000, 10001, 10002],
    "ldap_escape": [1010],
    "mysql_real_escape_string": [1004, 1005, 1006],
    "addslashes": [1004, 1005, 1006],
    "intval": [1004, 1005, 1006],
    "escapeshellcmd": [1009, 1011],
    "escapeshellarg": [1009, 1011],
}

PHP_IS_CONTROLLED_DEFAULT = [
    "$_GET",
]
