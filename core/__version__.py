import sys
import platform

__title__ = 'KunLun-M'
__description__ = 'Code Security Audit'
__url__ = 'https://github.com/LoRexxar/Kunlun-M'
__issue_page__ = 'https://github.com/LoRexxar/Kunlun-M/issues/new'
__python_version__ = sys.version.split()[0]
__platform__ = platform.platform()
__version__ = '2.0 beta3'
__author__ = 'LoRexxar'
__author_email__ = 'LoRexxar@gmail.com'
__license__ = 'MIT License'
__copyright__ = 'Copyright (C) 2017 LoRexxar. All Rights Reserved'
__introduction__ = """
 _   __            _                      ___  ___
| | / /           | |                     |  \/  |
| |/ / _   _ _ __ | |    _   _ _ __       | .  . |
|    \| | | | '_ \| |   | | | | '_ \ _____| |\/| |
| |\  \ |_| | | | | |___| |_| | | | |_____| |  | |
\_| \_/\__,_|_| |_\_____/\__,_|_| |_|     \_|  |_/  -v{version}

GitHub: https://github.com/LoRexxar/Kunlun-M

KunLun-M is a static code analysis system that automates the detecting vulnerabilities and security issue.

{{detail}}

""".format(version=__version__)
__epilog__ = """Usage:
  python {m} scan -t {td}
  python {m} scan -t {td} -r 1000, 1001
  python {m} scan -t {td} -tp wordpress
  python {m} scan -t {td} -d -uc
  
  python {m} list rule -k php
""".format(m='kunlun.py', td='tests/vulnerabilities')
__scan_epilog__ = """Usage:
  python {m} scan -t {td}
  python {m} scan -t {td} -r 1000, 1001
  python {m} scan -t {td} -tp wordpress
  python {m} scan -t {td} -f json -o /tmp/report.json 
  python {m} scan -t {td} --debug
  python {m} scan -t {td} -d -u
  python {m} scan -t {td} --lan php -b vendor --debug
  python {m} scan -t {td} --lan php -tp roundcube -d -uc

""".format(m='kunlun.py', td='tests/vulnerabilities')