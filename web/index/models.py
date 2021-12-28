# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import traceback
from django.db.utils import IntegrityError
from datetime import datetime

from django.db import models
from django.db import connection
from django.db.utils import OperationalError
import django.utils.timezone as timezone
from django import db

from Kunlun_M.const import TAMPER_TYPE
from utils.log import logger
from utils.utils import compare_vendor, abstract_version

import json
import uuid
import hashlib


def md5(content):
    """
    MD5 Hash
    :param content:
    :return:
    """
    content = content.encode('utf8')
    return hashlib.md5(content).hexdigest()


def check_effective(pre_versions):
    return_versions = []

    for pv in pre_versions:
        if pv:
            return_versions.append(pv)

    return return_versions


class Project(models.Model):
    project_name = models.CharField(max_length=200)
    project_des = models.TextField(null=True)
    project_origin = models.CharField(max_length=500, null=True)
    project_hash = models.CharField(max_length=32)


def search_project_by_name(project_name):
    """
        支持*语法的查询
        :param project_name:
        :return:
        """
    if not project_name:
        ps = Project.objects.all().order_by('-id')
        return ps

    if project_name.startswith('*'):
        if project_name.endswith('*'):
            ps = Project.objects.filter(project_name__icontains=project_name.strip('*')).order_by('-id')

        else:
            ps = Project.objects.filter(project_name__iendswith=project_name.strip('*')).order_by('-id')

    else:
        if project_name.endswith('*'):
            ps = Project.objects.filter(project_name__istartswith=project_name.strip('*')).order_by('-id')

        else:
            ps = Project.objects.filter(project_name__iexact=project_name.strip('*')).order_by('-id')

    return ps


class ProjectVendors(models.Model):
    project_id = models.IntegerField()
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=50, null=True)
    language = models.CharField(max_length=20)
    ext = models.CharField(max_length=100, null=True, default=None)
    hash = models.CharField(max_length=32)

    def save(self, *args, **kwargs):

        self.hash = md5("{},{},{}".format(self.project_id, self.name, self.language))
        super().save(*args, **kwargs)


def update_and_new_project_vendor(project_id, name, version, language, ext=None):
    hash = md5("{},{},{}".format(project_id, name, language))
    vendor = ProjectVendors.objects.filter(hash=hash, project_id=project_id, ext=ext).first()

    if vendor:
        if vendor.version != version:
            logger.debug("[Vendors] Component {} update to version {}".format(name, version))

            vendor.version = version
            try:
                vendor.save()
            except IntegrityError:
                logger.warn("[Model Save] vendor model not changed")

    else:
        v = ProjectVendors(project_id=project_id, name=name, version=version, language=language, ext=ext)
        v.save()

    return True


class VendorVulns(models.Model):
    # vuln
    vuln_id = models.CharField(max_length=200)
    title = models.TextField()
    description = models.TextField()
    severity = models.IntegerField()
    cves = models.TextField()
    reference = models.TextField()
    # affect vendor
    vendor_name = models.CharField(max_length=200)
    affected_versions = models.TextField(null=True)


def update_and_new_vendor_vuln(vendor, vuln):
    # v = VendorVulns.objects.filter(vuln_id=vuln["vuln_id"], vendor_name=vendor["name"], vendor_version=vendor["version"]).first()
    v = VendorVulns.objects.filter(vuln_id=vuln["vuln_id"]).first()

    # 检查版本比较
    if v:
        prev_versions = check_effective(v.affected_versions.split(','))

        if vendor["version"] not in prev_versions:
            prev_versions.append(vendor["version"])
            v.affected_versions = ','.join(prev_versions)
            v.description = vuln["description"]
            v.reference = vuln["reference"]

            try:
                v.save()
            except IntegrityError:
                logger.warn("[Model Save] vuln model not changed")

        if vuln["title"] != v.title or vuln["cves"] != v.cves:
            logger.debug("[Vendors] Vuln {} update".format(v.vuln_id))
            v.title = vuln["title"]
            v.description = vuln["description"]
            v.severity = vuln["severity"]
            v.cves = vuln["cves"]
            v.reference = vuln["reference"]
            try:
                v.save()
            except IntegrityError:
                logger.warn("[Model Save] vuln model not changed")
    else:
        v = VendorVulns(vuln_id=vuln["vuln_id"],
                        title=vuln["title"], description=vuln["description"],
                        severity=vuln["severity"], cves=vuln["cves"], reference=vuln["reference"],
                        vendor_name=vendor["name"], affected_versions=','.join(vuln["affected_versions"]))
        v.save()

    return v.id


class ScanTask(models.Model):
    project_id = models.IntegerField(default=0)
    task_name = models.CharField(max_length=200)
    target_path = models.CharField(max_length=300)
    parameter_config = models.TextField()
    last_scan_time = models.DateTimeField(default=timezone.now)
    visit_token = models.CharField(max_length=64, default=uuid.uuid4)
    is_finished = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # 检查project存不存在，如果不存在，那么新建一个
        project = Project.objects.filter(id=self.project_id).first()

        if not project:
            project2 = Project.objects.filter(project_hash=md5(self.task_name)).first()

            if project2:
                self.project_id = project2.id
            else:
                p = Project(project_name=self.task_name, project_hash=md5(self.task_name))
                p.save()
                self.project_id = p.id

        super().save(*args, **kwargs)


def get_and_check_scantask_project_id(scantask_id):
    st = ScanTask.objects.filter(id=scantask_id).first()
    if st.project_id:
        return st.project_id

    p = Project.objects.filter(project_hash=md5(st.task_name)).first()
    if not p:
        p = Project(project_name=st.task_name, project_hash=md5(st.task_name))
        p.save()

        st.project_id = p.id
        st.save()
    return p.id


def check_and_new_project_id(scantask_id, task_name, project_origin, project_des=""):
    st = ScanTask.objects.filter(id=scantask_id).first()
    p = Project.objects.filter(project_hash=md5(task_name)).first()

    if not p:
        p2 = Project(project_name=st.task_name, project_des=project_des, project_hash=md5(task_name), project_origin=project_origin)
        p2.save()

        st.project_id = p.id
        st.save()
    else:
        p.project_des = project_des
        p.project_origin = project_origin
        try:
            p.save()
        except IntegrityError:
            logger.warn("[Model Save] Project model not changed")

    return p.id


#     table = PrettyTable(
#         ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
#          'Commit(Author)', 'Source Code Content', 'Analysis'])
class ScanResultTask(models.Model):
    scan_project_id = models.IntegerField(default=0)
    scan_task_id = models.IntegerField()
    # result_id = models.IntegerField()
    cvi_id = models.CharField(max_length=20)
    language = models.CharField(max_length=20)
    vulfile_path = models.CharField(max_length=200)
    source_code = models.CharField(max_length=200)
    result_type = models.CharField(max_length=100)
    vul_hash = models.CharField(max_length=32, default=None)
    is_unconfirm = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):

        if not self.scan_project_id:
            scan_task = ScanTask.objects.filter(id=self.scan_task_id).first()
            self.scan_project_id = scan_task.project_id

        self.vul_hash = md5("{},{},{},{},{}".format(self.scan_project_id, self.cvi_id, self.language, self.vulfile_path, self.source_code))

        # 加入去重检查
        srts = ScanResultTask.objects.filter(vul_hash=self.vul_hash)

        if len(srts) > 1:
            # 如果存在，那么重复
            srts.last().delete()

            return self.save(*args, **kwargs)

        super().save(*args, **kwargs)


def get_and_check_scanresult(scan_task_id):
    srtn = ScanResultTask.objects.filter(scan_task_id=scan_task_id).first()

    if not srtn:
        return ScanResultTask

    scan_project_id = srtn.scan_project_id

    if scan_project_id:
        return ScanResultTask

    else:
        srts = ScanResultTask.objects.filter(scan_task_id=scan_task_id)
        project_id = get_and_check_scantask_project_id(scan_task_id)

        for srt in srts:
            srt.scan_project_id = project_id
            srt.save()

    return ScanResultTask


def check_update_or_new_scanresult(scan_task_id, cvi_id, language, vulfile_path, source_code, result_type,
                                   is_unconfirm, is_active):
    # 优化基础扫描结果
    if str(cvi_id).startswith('5'):
        vulfile_path = vulfile_path.split(':')[0]

    # 如果漏洞hash存在，那么更新信息，如果hash不存在，那么新建漏洞
    scan_project_id = get_and_check_scantask_project_id(scan_task_id)
    vul_hash = md5("{},{},{},{},{}".format(scan_project_id, cvi_id, language, vulfile_path, source_code))

    sr = ScanResultTask.objects.filter(vul_hash=vul_hash).first()
    if sr:
        logger.debug("[Database] Scan Result id {} exist. update.".format(sr.id))

        sr.scan_task_id = scan_task_id
        sr.cvi_id = cvi_id
        sr.language = language
        sr.vulfile_path = vulfile_path
        sr.source_code = source_code
        sr.result_type = result_type
        sr.is_unconfirm = is_unconfirm

        try:
            sr.save()
        except IntegrityError:
            logger.warn("[Model Save] Model param not changed")

        return False

    else:
        sr = ScanResultTask(scan_project_id=scan_project_id, scan_task_id=scan_task_id, cvi_id=cvi_id, language=language, vulfile_path=vulfile_path, source_code=source_code, result_type=result_type,
                            is_unconfirm=is_unconfirm, is_active=is_active)
        sr.save()

    return sr


class Rules(models.Model):
    rule_name = models.CharField(max_length=50)
    svid = models.CharField(max_length=10)
    language = models.CharField(max_length=20)
    author = models.CharField(max_length=20)
    description = models.TextField(null=True)
    level = models.IntegerField(default=5)
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
    project_id = models.IntegerField(default=0)
    func_name = models.CharField(max_length=200)
    origin_func_name = models.CharField(max_length=200, null=True)
    func_hash = models.CharField(max_length=32, default=None)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):

        if not self.project_id:
            self.project_id = get_and_check_scantask_project_id(self.scan_task_id)

        self.func_hash = md5("{},{},{},{}".format(self.project_id, self.svid, self.func_name, self.origin_func_name))

        # 添加去重
        nefs = NewEvilFunc.objects.filter(func_hash=self.func_hash)

        if len(nefs) > 1:
            # 如果存在，那么重复
            nefs.last().delete()

            return self.save(*args, **kwargs)

        super().save(*args, **kwargs)


def get_and_check_evil_func(task_id):
    nefs = NewEvilFunc.objects.filter(scan_task_id=task_id)

    for nef in nefs:
        project_id = nef.project_id

        if project_id:
            continue

        else:
            project_id = get_and_check_scantask_project_id(task_id)
            nef.project_id = project_id
            nef.save()

    return nefs


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


def get_resultflow_class(scanid):

    scanid = int(scanid)
    table_name = "ResultFlow_{:08d}".format(scanid)

    ResultflowObject = get_resultflow_table(table_name)

    if not ResultflowObject.is_exists():
        old_table_name = "ResultFlow_{:04d}".format(scanid)
        oldResultflowObject = get_resultflow_table(old_table_name)

        if oldResultflowObject.is_exists():
            return oldResultflowObject

        # 将resultflow在同一个project的储存在同一张表，检查project获取id
        st = ScanTask.objects.filter(id=scanid).first()
        projectid = st.project_id

        table_name = "ResultFlow_1{:08d}".format(projectid)
        ResultflowObject = get_resultflow_table(table_name)

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
