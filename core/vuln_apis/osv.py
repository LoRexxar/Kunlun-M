import json
import requests

__OSV_QUERY_URL = "https://api.osv.dev/v1/query"
__OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

__SEVERITY_DICT = {
    "UNKNOWN": 1,
    "NONE": 1,
    "LOW": 3,
    "MODERATE": 5,
    "MEDIUM": 5,
    "HIGH": 7,
    "CRITICAL": 10,
}


def _osv_severity_to_score(vuln):
    dbs = vuln.get("database_specific", {}) if isinstance(vuln, dict) else {}
    sev = dbs.get("severity")
    if isinstance(sev, str):
        return __SEVERITY_DICT.get(sev.upper(), 5)

    return 5


def _osv_references(vuln):
    refs = []
    for r in vuln.get("references", []) if isinstance(vuln, dict) else []:
        url = r.get("url")
        if url:
            refs.append(url)

    if not refs:
        return ""
    if len(refs) == 1:
        return refs[0]
    return json.dumps(refs)


def _osv_cves(vuln):
    aliases = vuln.get("aliases", []) if isinstance(vuln, dict) else []
    cves = [a for a in aliases if isinstance(a, str) and a.upper().startswith("CVE-")]
    return json.dumps(cves)


def _osv_to_vuln_dict(vuln, version):
    vuln_id = vuln.get("id", "")
    title = vuln.get("summary") or vuln_id
    description = vuln.get("details", "")

    return {
        "vuln_id": vuln_id,
        "title": title or "",
        "reference": _osv_references(vuln),
        "description": description or "",
        "cves": _osv_cves(vuln),
        "severity": _osv_severity_to_score(vuln),
        "affected_versions": [version],
    }


def query_osv_batch(ecosystem, items, timeout=8, chunk_size=100):
    result = {}
    items = [(n, v) for (n, v) in items if n and v]
    if not items:
        return result

    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        body = {
            "queries": [
                {
                    "package": {"ecosystem": ecosystem, "name": name},
                    "version": version
                } for (name, version) in chunk
            ]
        }

        resp = requests.post(__OSV_QUERYBATCH_URL, json=body, timeout=timeout)
        if resp.status_code != 200:
            for k in chunk:
                result[k] = []
            continue

        data = json.loads(resp.content)
        results = data.get("results", [])
        for (name, version), one in zip(chunk, results):
            vulns = []
            for v in one.get("vulns", []) if isinstance(one, dict) else []:
                if isinstance(v, dict):
                    vulns.append(_osv_to_vuln_dict(v, version))
            result[(name, version)] = vulns

    return result


def get_vulns_from_osv(ecosystem, package_name, version):
    r = query_osv_batch(ecosystem, [(package_name, version)], timeout=8, chunk_size=1)
    return r.get((package_name, version), [])


def query_osv_single(ecosystem, package_name, version, timeout=8):
    body = {"package": {"ecosystem": ecosystem, "name": package_name}, "version": version}
    resp = requests.post(__OSV_QUERY_URL, json=body, timeout=timeout)
    if resp.status_code != 200:
        return []

    data = json.loads(resp.content)
    vulns = []
    for v in data.get("vulns", []) if isinstance(data, dict) else []:
        if isinstance(v, dict):
            vulns.append(_osv_to_vuln_dict(v, version))
    return vulns

