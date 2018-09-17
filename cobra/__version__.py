import sys
import platform

__title__ = 'cobra'
__description__ = 'Code Security Audit'
__url__ = 'https://github.com/LoRexxar/Cobra-W'
__issue_page__ = 'https://github.com/LoRexxar/Cobra-W/issues/new'
__python_version__ = sys.version.split()[0]
__platform__ = platform.platform()
__version__ = '1.1.0'
__author__ = 'LoRexxar'
__author_email__ = 'LoRexxar@gmail.com'
__license__ = 'MIT License'
__copyright__ = 'Copyright (C) 2017 LoReexar. All Rights Reserved'
__introduction__ = """
  ____      _                  __        __
 / ___|___ | |__  _ __ __ _    \ \      / /
| |   / _ \| '_ \| '__/ _` |    \ \ /\ / / 
| |__| (_) | |_) | | | (_| | --- \ V  V /  
 \____\___/|_.__/|_|  \__,_|      \_/\_/  v{version}

GitHub: https://github.com/LoRexxar/Cobra-W

Cobra is a static code analysis system that automates the detecting vulnerabilities and security issue.""".format(version=__version__)
__epilog__ = """Usage:
  python {m} -t {td}
  python {m} -t {td} -r 1000, 1001
  python {m} -t {td} -s wordpress
  python {m} -t {td} -f json -o /tmp/report.json 
  python {m} -t {td} --debug
""".format(m='cobra.py', td='tests/vulnerabilities')
