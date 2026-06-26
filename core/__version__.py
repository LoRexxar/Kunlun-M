import sys
import platform

__title__ = 'KunLun-M'
__description__ = 'Static Code Security Analysis'
__url__ = 'https://github.com/LoRexxar/Kunlun-M'
__issue_page__ = 'https://github.com/LoRexxar/Kunlun-M/issues/new'
__python_version__ = sys.version.split()[0]
__platform__ = platform.platform()
__version__ = '2.17.0'
__author__ = 'LoRexxar'
__author_email__ = 'LoRexxar@gmail.com'
__license__ = 'MIT License'
__copyright__ = 'Copyright (C) 2017 LoRexxar. All Rights Reserved'

_LOGO = r"""
 _   __            _                      ___  ___
| | / /           | |                     |  \/  |
| |/ / _   _ _ __ | |    _   _ _ __       | .  . |
|    \| | | | '_ \| |   | | | | '_ \ _____| |\/| |
|\ \  \ |_| | | | | |___| |_| | | | |_____| |  | |
\_| \_/\__,_|_| |_|\_____/\__,_|_| |_|     \_|  |_/  -v{version}
""".format(version=__version__)

__introduction__ = _LOGO + """GitHub: https://github.com/LoRexxar/Kunlun-M

KunLun-M is a static code security analysis system.
Supports 14 languages with AST-based graph engine for taint analysis.

{detail}

"""

__epilog__ = """Quick Start:
  python {m} init                              Initialize database
  python {m} scan -t <target>                  Scan a project
  python {m} scan -t <target> -lan php          Scan with specific language
  python {m} scan -t <target> -f html -o r.html Export HTML report
  python {m} console                           Interactive console (with graph REPL)
  python {m} web -p 9999                       Web dashboard
  python {m} analyze overview                  AST graph analysis
  python {m} export-project -p <project>       Export project archive
  python {m} export-neo4j -p <project>         Export AST graph to Neo4j

Full docs: https://github.com/LoRexxar/Kunlun-M/tree/develop/docs
""".format(m='kunlun.py')

__scan_epilog__ = """Examples:
  python {m} scan -t {td}                              Scan default
  python {m} scan -t {td} -lan php                      Specify language
  python {m} scan -t {td} -r 1000,1001                  Only specific rules
  python {m} scan -t {td} -tp wordpress                 Apply tamper
  python {m} scan -t {td} -f json -o report.json       JSON report
  python {m} scan -t {td} -f html -o report.html       HTML report
  python {m} scan -t {td} -f md -o report.md            Markdown report
  python {m} scan -t {td} -b vendor,node_modules        Exclude paths
  python {m} scan -t {td} --without-vendor              Skip SCA scan
  python {m} scan -t {td} --debug                       Debug mode
""".format(m='kunlun.py', td='<target>')
