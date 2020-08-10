# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.utils import timezone

from Kunlun_M.const import TAMPER_TYPE


class ScanTask(models.Model):
    task_name = models.CharField(max_length=50)
    target_path = models.CharField(max_length=300)
    parameter_config = models.CharField(max_length=100)
    last_scan_time = models.DateTimeField()
    is_finished = models.BooleanField(default=False)


#     table = PrettyTable(
#         ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
#          'Commit(Author)', 'Source Code Content', 'Analysis'])
class ScanResultTask(models.Model):
    scan_task_id = models.IntegerField()
    result_id = models.IntegerField()
    cvi_id = models.CharField(max_length=20)
    rule_id = models.IntegerField()
    language = models.CharField(max_length=20)
    vulfile_path = models.CharField(max_length=200)
    source_code = models.CharField(max_length=200)
    rule_type = models.IntegerField()


class Rules(models.Model):
    rule_name = models.CharField(max_length=50)
    svid = models.CharField(max_length=10)
    language = models.CharField(max_length=20)
    author = models.CharField(max_length=20)
    vulnerability = models.CharField(max_length=30)
    description = models.TextField()
    status = models.BooleanField(default=True)
    match_mode = models.CharField(max_length=50)
    match = models.CharField(max_length=200)
    vul_function = models.CharField(max_length=30, default=None)
    main_function = models.TextField()


# roundcube "Filter-Function" show [1000, 10001, 10002]
class Tampers(models.Model):
    tam_name = models.CharField(max_length=30)
    tam_type = models.IntegerField()
    tam_key = models.CharField(max_length=200)
    tam_value = models.CharField(max_length=200)
