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

import glob
import importlib.util
import inspect
import logging
import os
import sys
from distutils.util import strtobool
from typing import List

from monailabel.interfaces.exception import MONAILabelError, MONAILabelException

logger = logging.getLogger(__name__)


def unload_module(name):
    modules = []
    for m in sorted(sys.modules):
        if m == name or m.startswith(f"{name}."):
            modules.append(m)

    if modules and strtobool(os.environ.get("MONAI_LABEL_RELOAD_APP_LIB", "true")):
        logger.info(f"Remove/Reload previous Modules: {modules}")
        for m in modules:
            del sys.modules[m]


def module_from_file(module_name, file_path):
    app_dir = os.path.dirname(file_path)
    sys.path.insert(0, app_dir)
    unload_module("lib")

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    sys.path.remove(app_dir)
    logger.debug(f"module: {module}")
    return module


def is_subclass(n, o, class_c):
    if inspect.isclass(o) and n != class_c:
        b = [cls.__name__ for cls in o.__bases__]
        logger.debug(f"Base classes => {b}")
        if class_c in b:
            logger.info(f"Subclass for {class_c} Found: {o}")
            return True
    return False


def get_class_of_subclass(module, class_c):
    logger.debug(f"{module} => {class_c}")
    for n, o in inspect.getmembers(module):
        if not inspect.isclass(o):
            continue

        logger.debug(f"{n} => {o}")
        if is_subclass(n, o, class_c):
            return o
    return None


def get_class_of_subclass_from_file(module_name, file_path, class_c):
    return get_class_of_subclass(module_from_file(module_name, file_path), class_c)


def to_expression(class_path, class_args):
    key_val = []
    for key in class_args:
        val = class_args[key]
        if isinstance(val, str):
            val = f"'{val}'"
        elif isinstance(val, tuple) or isinstance(val, list):
            vals = []
            for v in val:
                if isinstance(v, str):
                    v = f"'{v}'"
                else:
                    v = str(v)
                vals.append(v)
            if isinstance(val, tuple):
                val = f"({', '.join(vals)})"
            else:
                val = f"[{', '.join(vals)}]"
        else:
            val = str(val)
        key_val.append(f"{key}={val}")
    return f"{class_path}({', '.join(key_val)})"


def class_args_to_exp(c, mappings=None):
    class_name = c["name"]
    class_name = mappings.get(class_name, class_name) if mappings else class_name
    class_args = c.get("args", {})
    return to_expression(class_name, class_args)


def get_class_info(exp, handle_bool=True):
    if isinstance(exp, dict):
        return exp["name"], exp["args"]
    if exp.find("(") == -1:
        return exp, {}

    def foo(**kwargs):
        return kwargs

    if handle_bool:
        exp = exp.replace("=true", "=True").replace("=false", "=False")  # safe to assume
        exp = exp.replace(" true", " True").replace(" false", " False")
    class_path = exp[: exp.find("(")]
    class_args = exp[exp.find("(") + 1 : -1] if exp.find("(") >= 0 else None

    logger.debug(f"Eval Input:: {class_path} => {class_args}")
    class_args = eval("foo(" + class_args + ")") if class_args else None

    logger.debug(f"{class_path} => {class_args}")
    return class_path, class_args


def init_class(class_path, class_args):
    if "." not in class_path:
        raise MONAILabelException(
            MONAILabelError.CLASS_INIT_ERROR, "Class path need to be in the form [module/file].[class_name]."
        )
    module_name, class_name = class_path.rsplit(".", 1)

    m = importlib.import_module(module_name)
    importlib.reload(m)
    c = getattr(m, class_name)
    return c(**class_args) if class_args else c()


def init_class_from_exp(exp):
    class_path, class_args = get_class_info(exp)
    return init_class(class_path, class_args)


def get_class_names(p, subclass=None) -> List[str]:
    logger = logging.getLogger(__name__)

    result = []
    logger.debug(f"Module File Path: {p.__file__}")

    if os.path.basename(p.__file__).startswith("__"):
        current_dir = os.path.dirname(p.__file__)
        current_module_name = p.__package__

        for file in glob.glob(current_dir + "/*.py*"):
            name = os.path.splitext(os.path.basename(file))[0]
            if name.startswith("__"):
                continue

            module = importlib.import_module("." + name, package=current_module_name)
            for m in dir(module):
                c = getattr(module, m)
                if not c or inspect.isabstract(c):
                    continue
                if (
                    inspect.isclass(c)
                    and c.__module__ == module.__name__
                    and (not subclass or is_subclass(c.__name__, c, subclass))
                ):
                    result.append(c.__module__ + "." + c.__name__)

    else:
        for m in dir(p):
            c = getattr(p, m)
            if not c or inspect.isabstract(c):
                continue
            if (
                inspect.isclass(c)
                and c.__module__ == p.__name__
                and (not subclass or is_subclass(c.__name__, c, subclass))
            ):
                result.append(c.__module__ + "." + c.__name__)

    return result
