import importlib
import traceback

from utils.log import logger
from Kunlun_M.const import VENDOR_ECOSYSTEM
from Kunlun_M.settings import ACTIVE_SCA_SYSTEM


def get_vulns_from_source(language, vendor_name, vendor_version):
    result = []

    sources = VENDOR_ECOSYSTEM.get(language, {})
    for source in sources.keys():
        ecosystem = sources[source]

        if source not in ACTIVE_SCA_SYSTEM:
            continue

        module = importlib.import_module(__name__ + "." + source)
        func = getattr(module, "get_vulns_from_" + source, None)

        try:
            if func:
                vulns = func(ecosystem, vendor_name, vendor_version)
                result.extend(vulns)

        except KeyboardInterrupt:
            raise

        except:
            logger.error("[Vendor Scan] EcoSystem {} get error.\n{}".format(source, traceback.format_exc()))

    return result


