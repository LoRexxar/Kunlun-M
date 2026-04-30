import json
import requests

__OSSINDEXAPI = "https://ossindex.sonatype.org/api/v3/component-report"


def get_vulns_from_ossindex_batch(ecosystem, items, timeout=8, chunk_size=100):
    result = {}
    items = [(n, v) for (n, v) in items if n and v]
    if not items:
        return result

    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        coordinates = [
            "pkg:{ecosystem}/{package}@{version}".format(ecosystem=ecosystem, package=package_name, version=version)
            for (package_name, version) in chunk
        ]
        body = {"coordinates": coordinates}

        resp = requests.post(__OSSINDEXAPI, json=body, timeout=timeout)
        if resp.status_code != 200:
            for k in chunk:
                result[k] = []
            continue

        data = json.loads(resp.content)
        for comp, (package_name, version) in zip(data, chunk):
            vulns = []
            for advisorie in comp.get("vulnerabilities", []) if isinstance(comp, dict) else []:
                vuln = {}
                vuln["vuln_id"] = advisorie.get("displayName", "")
                vuln["title"] = advisorie.get("title", "")
                vuln["reference"] = advisorie.get("reference", "")
                vuln["description"] = advisorie.get("description", "")

                cves = []
                cve = advisorie.get("cve", "")
                if cve:
                    cves.append(cve)
                vuln["cves"] = json.dumps(cves)

                cvss3_score = advisorie.get("cvssScore", -1.0)
                try:
                    vuln["severity"] = int(float(cvss3_score))
                except Exception:
                    vuln["severity"] = 5

                vuln["affected_versions"] = [version]
                vulns.append(vuln)

            result[(package_name, version)] = vulns

    return result


def get_vulns_from_ossindex(ecosystem, package_name, version):
    r = get_vulns_from_ossindex_batch(ecosystem, [(package_name, version)], timeout=8, chunk_size=1)
    return r.get((package_name, version), [])

