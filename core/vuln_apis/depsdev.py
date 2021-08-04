import json
import requests
from urllib.parse import quote

DEPSDEVAPIURL = "https://deps.dev/_/s/{ecosystem}/p/{package}/v/{version}"

def get_vulns_from_depsdev(ecosystem, package_name, version):
    result = []

    package_name = quote(package_name, safe='')
    url = DEPSDEVAPIURL.format(ecosystem=ecosystem, package=package_name, version=version)

    resp = requests.get(url)
    if resp.status_code == 200:
        data = json.loads(resp.content)

        # 获取组件自身漏洞
        if "version" in data.keys(): # deps.dev版本展示有错误，有一些组件展示的与go.mod中不一致
            if len(data["version"]["advisories"]) > 0:
                for advisorie in data["version"]["advisories"]:
                    vuln = {}
                    vuln["vuln_id"] = advisorie["sourceID"]
                    vuln["title"] = advisorie["title"]
                    vuln["severity"] = advisorie["severity"]
                    vuln["description"] = advisorie["description"]

                    cves = []
                    for cve in advisorie["CVEs"]:
                        cves.append(cve)

                    vuln["cves"] = json.dumps(cves)
                    vuln["reference"] = advisorie["sourceURL"]

                    result.append(vuln)

    return result