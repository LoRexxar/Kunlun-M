#!/usr/bin/env python
# encoding: utf-8
"""
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: mofei.py
@time: 2021/9/27 11:47
@desc:

"""

import json
import requests

from Kunlun_M.settings import MURPHYSEC_TOKEN
from utils.log import logger

__MURPHYSECAPI = "https://api.murphysec.com/cert/v1/check"
__MURPHYSECVULAPI = "https://api.murphysec.com/cert/v1/latest"


def get_vulns_from_murphysec(language, package_name, version):
    datas = {
        "comp_name": package_name,
        "version": version,
        "language": language,
        "filter":{
            "level": "严重|高危"
        }
    }

    headers = {
        "Authorization": "Bearer {}".format(MURPHYSEC_TOKEN),
        "Content-Type": "application/json"
    }
    result = []

    r = requests.post(url=__MURPHYSECAPI, headers=headers, data=json.dumps(datas))

    if r.status_code == 200:
        data = json.loads(r.content)

        if data["code"] == 400:
            logger.warning("[Vendor][Murphysec Scan] QPS limit.")
            return result

        elif data["code"] == 401:
            logger.error("[Vendor][Murphysec Scan] Api Token error.")

        else:
            vuls = data["data"]["vuln_info"]

            for vul in vuls:
                vuln = {}
                vuln["vuln_id"] = vul["no"]
                vuln["title"] = vul["title"]
                # reference
                urls = []
                for u in vul["references"]:
                    urls.append(u["url"])

                vuln["reference"] = json.dumps(urls)
                vuln["description"] = """{}

受影响的版本范围: {}
存在危害的相关代码片段:\n {}
""".format(vul["description"], vul["effect"][0]["affected_version"], vul["vuln_code_usage"])

                # get cve
                cves = [vul["cve_id"], vul["cnvd_id"]]
                vuln["cves"] = json.dumps(cves)
                # get severity

                # 如果非强烈建议修复，则减3分
                severity = int(vul["cvss"])
                if vul["suggest"] != "强烈建议修复":
                    severity -= 3

                vuln["severity"] = severity

                # affected_versions
                # affected_versions = []
                # for av in vul["effect"]:
                #     affected_versions.append(av["version_end_excluding"])

                vuln["affected_versions"] = [version]

                result.append(vuln)

    return result
