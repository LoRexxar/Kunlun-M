import os
from core.rule import Rule

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

def test_vulnerabilities():
    vulnerabilities = Rule().vulnerabilities
    assert isinstance(vulnerabilities, list)
    assert len(vulnerabilities) > 0


def test_rules():
    rules = Rule().rules
    rules_list = Rule().rules()
    assert isinstance(rules, object)
    assert isinstance(rules_list, dict)
    first_key = next(iter(rules_list))
    assert first_key.startswith('CVI_')
    assert isinstance(rules_list[first_key], object)
