import json
import requests
from urllib.parse import quote

__DEPSDEVAPIURL = "https://deps.dev/_/s/{eco_system}/p/{package}/v/{version}/dependencies"
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

    resp = requests.get(url, timeout=6)
    if resp.status_code == 200:
        data = json.loads(resp.content)
        if "dependencies" in data.keys():
            for pack in data['dependencies']:
                if len(pack['advisories']) > 0:
                    for advisory in pack['advisories']:
                        vul = {"vuln_id": advisory["sourceID"], "title": advisory["title"],
                               "severity": __SEVERITY_DICT[advisory["severity"]],
                               "description": advisory["description"]}

                        if advisory["CVEs"]:
                            cves = [cve for cve in advisory["CVEs"]]
                            vul["cves"] = json.dumps(cves)
                        vul["reference"] = advisory["sourceURL"]
                        # 获取全部影响版本
                        source = advisory["source"]
                        affected_versions = __get_affected_versions(package_name, source, vul["vuln_id"])
                        vul["affected_versions"] = affected_versions

                        result.append(vul)
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
