# -*- coding: utf-8 -*-

from Kunlun_M.settings import project_directory
from utils.file import FileParseAll


vul_path = project_directory+'/tests/vulnerabilities/'
file_list = [(u'.p12', {'count': 1, 'list': [u'v.p12']}), (u'.php', {'count': 2, 'list': [u'v.php', u'v_parser.php']}), (u'.txt', {'count': 1, 'list': [u'requirements.txt']}), (u'.xml', {'count': 1, 'list': [u'pom.xml']})]


def test_FileParseAll():
    f = FileParseAll(file_list, vul_path)
    match = "echo"
    result = f.grep(match)
    assert 'echo' in result[0][2]
