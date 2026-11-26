# Copyright (c) MONAI Consortium
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

from ._version import get_versions

PY_REQUIRED_MAJOR = 3
PY_REQUIRED_MINOR = 7

version_dict = get_versions()
__version__ = version_dict.get("version", "0+unknown")
__revision_id__ = version_dict.get("full-revisionid")
del get_versions, version_dict

__copyright__ = "Copyright (c) MONAI Consortium"

__basedir__ = os.path.dirname(__file__)

if not (sys.version_info.major == PY_REQUIRED_MAJOR and sys.version_info.minor >= PY_REQUIRED_MINOR):
    raise RuntimeError(
        "MONAILabel requires Python {}.{} or higher. But the current Python is: {}".format(
            PY_REQUIRED_MAJOR, PY_REQUIRED_MINOR, sys.version
        ),
    )


def print_config(file=sys.stdout):
    from collections import OrderedDict

    import numpy as np
    import torch

    output = OrderedDict()
    output["MONAILabel"] = __version__
    output["Numpy"] = np.version.full_version
    output["Pytorch"] = torch.__version__

    for k, v in output.items():
        print(f"{k} version: {v}", file=file, flush=True)
    print(f"MONAILabel rev id: {__revision_id__}")
