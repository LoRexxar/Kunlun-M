# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import traceback
from datetime import datetime

from django.db import models
from django.db import connection
from django.db.utils import OperationalError
from django import db

from Kunlun_M.const import TAMPER_TYPE
from utils.log import logger

import uuid


class ScanTask(models.Model):
    task_name = models.CharField(max_length=50)
    target_path = models.CharField(max_length=300)
    parameter_config = models.CharField(max_length=500)
    last_scan_time = models.DateTimeField(auto_now=True)
    visit_token = models.CharField(max_length=64, default=uuid.uuid4)
    is_finished = models.BooleanField(default=False)


#     table = PrettyTable(
#         ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
#          'Commit(Author)', 'Source Code Content', 'Analysis'])
class ScanResultTask(models.Model):
    scan_task_id = models.IntegerField()
    result_id = models.IntegerField()
    cvi_id = models.CharField(max_length=20)
    language = models.CharField(max_length=20)
    vulfile_path = models.CharField(max_length=200)
    source_code = models.CharField(max_length=200)
    result_type = models.CharField(max_length=100)
    is_unconfirm = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)


class Rules(models.Model):
    rule_name = models.CharField(max_length=50)
    svid = models.CharField(max_length=10)
    language = models.CharField(max_length=20)
    author = models.CharField(max_length=20)
    description = models.TextField(null=True)
    status = models.BooleanField(default=True)
    match_mode = models.CharField(max_length=50)
    match = models.CharField(max_length=500)
    # for solidity
    match_name = models.CharField(max_length=100, default=None, null=True)
    black_list = models.CharField(max_length=100, default=None, null=True)
    # for chrome ext
    keyword = models.CharField(max_length=200, default=None, null=True)
    # for regex
    unmatch = models.CharField(max_length=200, default=None, null=True)
    vul_function = models.CharField(max_length=50, default=None, null=True)
    main_function = models.TextField()


# roundcube "Filter-Function" show [1000, 10001, 10002]
class Tampers(models.Model):
    tam_name = models.CharField(max_length=30)
    tam_type = models.CharField(max_length=100)
    tam_key = models.CharField(max_length=200)
    tam_value = models.CharField(max_length=200)


class NewEvilFunc(models.Model):
    svid = models.IntegerField()
    scan_task_id = models.IntegerField()
    func_name = models.CharField(max_length=200)
    origin_func_name = models.CharField(max_length=200, null=True)
    is_active = models.BooleanField(default=True)


# 数据流模板表
def get_dataflow_table(name, isnew=False):

    prefix = ""

    if isnew:
        prefix = "_{}".format(datetime.today().strftime("%Y%m%d"))

    table_name = "DataFlow_{}{}".format(name, prefix)

    class DataFlowTemplate(models.Model):
        node_locate = models.CharField(max_length=1000)
        node_sort = models.IntegerField()
        source_node = models.CharField(max_length=500)
        node_type = models.CharField(max_length=500)
        sink_node = models.CharField(max_length=500, null=True)

        @staticmethod
        def is_exists():
            return table_name in connection.introspection.table_names()

        class Meta:
            db_table = table_name

    return DataFlowTemplate


def get_dataflow_class(name, isnew=False, isrenew=False):
    DateflowObject = get_dataflow_table(name, isnew)

    if DateflowObject.is_exists() and isrenew:
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(DateflowObject)

    if not DateflowObject.is_exists():
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(DateflowObject)

    return DateflowObject


# 结果流模板表
def get_resultflow_table(table_name):
    # prefix = "_{}".format(datetime.today().strftime("%Y%m%d"))

    class ResultFlowTemplate(models.Model):
        vul_id = models.IntegerField()
        node_type = models.CharField(max_length=50)
        node_content = models.CharField(max_length=500)
        node_path = models.CharField(max_length=300)
        node_source = models.TextField(null=True)
        node_lineno = models.CharField(max_length=20, null=True)

        @staticmethod
        def is_exists():
            return table_name in connection.introspection.table_names()

        class Meta:
            db_table = table_name

    return ResultFlowTemplate


def get_resultflow_class(prefix):

    table_name = "ResultFlow_{:08d}".format(prefix)

    ResultflowObject = get_resultflow_table(table_name)

    if not ResultflowObject.is_exists():
        old_table_name = "ResultFlow_{:04d}".format(prefix)
        oldResultflowObject = get_resultflow_table(old_table_name)

        if oldResultflowObject.is_exists():
            return oldResultflowObject

        with connection.schema_editor() as schema_editor:

            try:
                schema_editor.create_model(ResultflowObject)

            except OperationalError:
                pass

    # 适配旧版本
    with connection.schema_editor() as schema_editor:
        try:
            node_source = models.TextField(null=True, db_column="node_source")
            node_source.set_attributes_from_name("node_source")
            schema_editor.add_field(ResultflowObject, node_source)
        except OperationalError:
            pass

    return ResultflowObject
