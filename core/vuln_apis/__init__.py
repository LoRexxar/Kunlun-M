import importlib
from Kunlun_M.const import VENDOR_ECOSYSTEM


def get_vulns_from_source(language, vendor_name, vendor_version):
    result = []

    sources = VENDOR_ECOSYSTEM.get(language, {})
    for source in sources.keys():
        ecosystem = sources[source]

        module = importlib.import_module(__name__ + "." + source)
        func = getattr(module, "get_vulns_from_" + source, None)

        if func:
            vulns = func(ecosystem, vendor_name, vendor_version)
            result.extend(vulns)

    return result
