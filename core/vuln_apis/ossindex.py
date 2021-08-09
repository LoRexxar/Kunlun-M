import json
import requests

OSSINDEXAPI = "https://ossindex.sonatype.org/api/v3/component-report"


def get_vulns_from_ossindex(ecosystem, package_name, version):
    result = []
    coordinate = "pkg:{ecosystem}/{package}@{version}".format(ecosystem=ecosystem, package=package_name, version=version)
    body = {"coordinates": [coordinate]}
    resp = requests.post(OSSINDEXAPI, json=body)
    if resp.status_code == 200:
        data = json.loads(resp.content)
        for advisorie in data[0]["vulnerabilities"]:
            vuln = {}
            vuln["vuln_id"] = advisorie.get("displayName", "")
            vuln["title"] = advisorie.get("title", "")
            vuln["reference"] = advisorie.get("reference", "")
            vuln["description"] = advisorie.get("description", "")
            # get cve
            cves = []
            cve = advisorie.get("cve", "")
            if cve != "":
                cves.append(cve)
            vuln["cves"] = json.dumps(cves)
            # get severity
            cvss3_score = advisorie.get("cvssScore", -1.0)
            vuln["severity"] = int(cvss3_score)

            result.append(vuln)

    return result

