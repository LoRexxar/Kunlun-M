import json
import requests
from urllib.parse import quote

__DEPSDEVAPIURL = "https://deps.dev/_/s/{ecosystem}/p/{package}/v/{version}"
__DEPSDEVADVISORYURL = "https://deps.dev/_/advisory/{source}/{source_id}"
__SEVERITY_DICT = {
    "UNKNOWN": 1,
    "NONE": 1,
    "LOW": 3,
    "MEDIUM": 5,
    "HIGH": 7,
    "CRITICAL": 10,
}


def get_vulns_from_depsdev(ecosystem, package_name, version):
    result = []

    package_name = quote(package_name, safe='')
    url = __DEPSDEVAPIURL.format(ecosystem=ecosystem, package=package_name, version=version)

    resp = requests.get(url)
    if resp.status_code == 200:
        data = json.loads(resp.content)

        # 获取组件自身漏洞
        if "version" in data.keys():  # deps.dev版本展示有错误，有一些组件展示的与go.mod中不一致
            if len(data["version"]["advisories"]) > 0:
                for advisorie in data["version"]["advisories"]:
                    vuln = {}
                    vuln["vuln_id"] = advisorie["sourceID"]
                    vuln["title"] = advisorie["title"]
                    vuln["severity"] = __SEVERITY_DICT[advisorie["severity"]]
                    vuln["description"] = advisorie["description"]

                    cves = []
                    for cve in advisorie["CVEs"]:
                        cves.append(cve)

                    vuln["cves"] = json.dumps(cves)
                    vuln["reference"] = advisorie["sourceURL"]

                    # 获取全部影响版本
                    source = advisorie["source"]
                    affected_versions = __get_affected_versions(package_name, source, vuln["vuln_id"])
                    vuln["affected_versions"] = affected_versions

                    result.append(vuln)

    return result


def __get_affected_versions(package_name, source, source_id):
    result = []

    url = __DEPSDEVADVISORYURL.format(source=source, source_id=source_id)
    resp = requests.get(url)
    if resp.status_code == 200:
        data = json.loads(resp.content)

        for pkg in data["packages"]:
            if pkg["package"]["name"] != package_name:
                continue

            if len(pkg["versionsAffected"]) > 0:
                for version in pkg["versionsAffected"]:
                    result.append(version["version"])
    return result
