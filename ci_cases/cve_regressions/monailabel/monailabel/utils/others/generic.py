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

import distutils.util
import hashlib
import json
import logging
import mimetypes
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict

import torch
from monai.apps import download_url
from monai.bundle import download, get_bundle_versions
from monai.bundle.scripts import get_all_bundles_list

from monailabel.config import settings
from monailabel.utils.others.modelzoo_list import MAINTAINED_BUNDLES

logger = logging.getLogger(__name__)


def file_ext(name) -> str:
    suffixes = []
    for s in reversed(pathlib.Path(name).suffixes):
        if len(s) > 10:
            break
        suffixes.append(s)
    return "".join(reversed(suffixes)) if name else ""


def remove_file(path: str) -> None:
    if path and os.path.exists(path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)


def get_basename(path):
    """Gets the basename of a file.

    Ref: https://stackoverflow.com/questions/8384737/extract-file-name-from-path-no-matter-what-the-os-path-format
    """
    head, tail = os.path.split(path)
    return tail or os.path.basename(head)


def get_basename_no_ext(path):
    p = get_basename(path)
    e = file_ext(p)
    return p.rstrip(e)


def run_command(command, args=None, plogger=None):
    plogger = plogger if plogger else logger
    cmd = [command]
    if args:
        args = [str(a) for a in args]
        cmd.extend(args)

    plogger.info("Running Command:: {}".format(" ".join(cmd)))
    process = subprocess.Popen(
        cmd,
        # stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        env=os.environ.copy(),
    )

    while process.poll() is None:
        line = process.stdout.readline()
        line = line.rstrip()
        if line:
            plogger.info(line.rstrip()) if plogger else print(line)

    plogger.info(f"Return code: {process.returncode}")
    process.stdout.close()
    return process.returncode


def init_log_config(log_config, app_dir, log_file, root_level=None):
    if not log_config or not os.path.exists(log_config):
        default_log_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        default_config = os.path.realpath(os.path.join(default_log_dir, "logging.json"))

        log_dir = os.path.join(app_dir, "logs")
        log_config = tempfile.NamedTemporaryFile(suffix=".json").name
        os.makedirs(log_dir, exist_ok=True)

        # if not os.path.exists(log_config):
        shutil.copyfile(default_config, log_config)
        with open(log_config) as f:
            c = f.read()

        c = c.replace("${LOGDIR}", log_dir.replace("\\", r"\\"))
        c = c.replace("${LOGFILE}", os.path.join(log_dir, log_file).replace("\\", r"\\"))

        with open(log_config, "w") as f:
            f.write(c)

    with open(log_config) as f:
        j = json.load(f)

    if root_level and j["root"]["level"] != root_level:
        j["root"]["level"] = root_level
        with open(log_config, "w") as f:
            json.dump(j, f, indent=2)

    return log_config


def get_mime_type(file):
    m_type = mimetypes.guess_type(file, strict=False)
    logger.debug(f"Guessed Mime Type for Image: {m_type}")

    if m_type is None or m_type[0] is None:
        m_type = "application/octet-stream"
    else:
        m_type = m_type[0]
    logger.debug(f"Final Mime Type: {m_type}")
    return m_type


def file_checksum(file, algo="SHA256"):
    if algo not in ["SHA256", "SHA512", "MD5"]:
        raise ValueError("unsupported hashing algorithm %s" % algo)

    with open(file, "rb") as content:
        hash = hashlib.new(algo)
        while True:
            chunk = content.read(8192)
            if not chunk:
                break
            hash.update(chunk)
        return f"{algo}:{hash.hexdigest()}"


def gpu_memory_map():
    """Get the current gpu usage.

    Returns
    -------
    usage: dict
        Keys are device ids as integers.
        Values are memory usage as integers in MB.
    """
    logger.info("Using nvidia-smi command")
    if shutil.which("nvidia-smi") is None:
        logger.info("nvidia-smi command didn't work! - Using default image size [128, 128, 64]")
        return {0: 4300}

    result = subprocess.check_output(
        ["nvidia-smi", "--query-gpu=memory.free", "--format=csv,nounits,noheader"], encoding="utf-8"
    )

    # Convert lines into a dictionary
    gpu_memory = [int(x) for x in result.strip().split("\n")]
    gpu_memory_map = dict(zip(range(len(gpu_memory)), gpu_memory))
    return gpu_memory_map


def gpu_count():
    return torch.cuda.device_count()


def download_file(url, path, delay=1, skip_on_exists=True):
    if skip_on_exists and os.path.exists(path):
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)
    logger.info(f"Downloading resource: {path} from {url}")

    download_url(url, path)
    if delay > 0:
        time.sleep(delay)


def device_list():
    devices = [] if torch.cuda.is_available() else ["cpu"]
    if torch.cuda.device_count() == 1:
        devices.append(torch.cuda.get_device_name(0))
    else:
        for i in range(torch.cuda.device_count()):
            devices.append(f"{torch.cuda.get_device_name(i)}:{i}")

    return devices


def device_map():
    devices = {} if torch.cuda.is_available() else {"cpu": "cpu"}
    if torch.cuda.device_count() == 1:
        devices[torch.cuda.get_device_name(0)] = "cuda"
    else:
        for i in range(torch.cuda.device_count()):
            devices[f"{torch.cuda.get_device_name(i)}:{i}"] = f"cuda:{i}"

    return devices


def name_to_device(device):
    device = device if device else "cuda" if torch.cuda.is_available() else "cpu"
    device = device if isinstance(device, str) else device[0]
    if device.startswith("cuda") and not torch.cuda.is_available():
        device = "cpu"
    return device_map().get(device, device)


def create_dataset_from_path(folder, image_dir="images", label_dir="labels", img_ext=".jpg", lab_ext=".png"):
    def _list_files(d, ext):
        files = [i for i in os.listdir(d) if i.endswith(ext)]
        return sorted(os.path.join(d, i) for i in files)

    image_dir = os.path.join(folder, image_dir) if image_dir else folder
    images = _list_files(image_dir, img_ext)

    label_dir = os.path.join(folder, label_dir) if label_dir else folder
    labels = _list_files(label_dir, lab_ext)

    for i, l in zip(images, labels):
        if get_basename_no_ext(i) != get_basename_no_ext(l):
            logger.warning(f"NO MATCH: {i} => {l}")

    return [
        {"image": i, "label": l} for i, l in zip(images, labels) if get_basename_no_ext(i) == get_basename_no_ext(l)
    ]


def strtobool(s):
    return False if s is None else s if isinstance(s, bool) else bool(distutils.util.strtobool(s))


def is_openslide_supported(name):
    ext = file_ext(name)
    supported_ext = (".bif", ".mrxs", ".ndpi", ".scn", ".svs", ".svslide", ".tif", ".tiff", ".vms", ".vmu")
    if ext and ext in supported_ext:
        return True
    return False


def get_zoo_bundle(model_dir, conf, models, conf_key):
    zoo_repo = conf.get("zoo_repo", settings.MONAI_ZOO_REPO)
    zoo_info = get_all_bundles_list()

    # filter model zoo bundle with MONAI Label supported bundles according to the maintaining list, return all version bundles list
    available = [i[0] for i in zoo_info if i[0] in MAINTAINED_BUNDLES]
    available_with_version = {b: get_bundle_versions(b)["all_versions"] for b in available}

    available_both = available + [k + "_v" + v for k, versions in available_with_version.items() for v in versions]

    version_to_name = {k + "_v" + v: k for k, versions in available_with_version.items() for v in versions}
    name_to_version = {k + "_v" + v: v for k, versions in available_with_version.items() for v in versions}
    if not models:
        print("")
        print("---------------------------------------------------------------------------------------")
        print("Get models from bundle configs, Please provide --conf models <bundle name>")
        print("Following are the available bundles.  You can pass comma (,) separated names to pass multiple")
        print(f"   -c {conf_key}")
        print("        {}".format(" \n        ".join(available)))
        print("---------------------------------------------------------------------------------------")
        print("")
        exit(-1)

    # First check whether the bundle model directory is available and in model-zoo, if no, check local bundle directory.
    # Use zoo bundle if both exist
    invalid_zoo = [m for m in models if m not in available_both]

    invalid = [m for m in invalid_zoo if not os.path.isdir(os.path.join(model_dir, m))]
    if invalid:
        print("")
        print("---------------------------------------------------------------------------------------")
        print(f"Invalid Model(s) are provided: {invalid}, either not in model zoo or not supported with MONAI Label")
        print("Following are the available models.  You can pass comma (,) separated names to pass multiple")
        print("Available bundle with latest tags:")
        print(f"   -c {conf_key}")
        print("        {}".format(" \n        ".join(available)))
        print("Or provide valid local bundle directories")
        print("---------------------------------------------------------------------------------------")
        print("")
        exit(-1)

    bundles: Dict[str, str] = {}

    for k in models:
        p = os.path.join(model_dir, k)
        if k not in available_both:
            logger.info(f"+++ Adding Bundle from Local: {k} => {p}")
        else:
            logger.info(f"+++ Adding Bundle from Zoo: {k} => {p}")
            if not os.path.exists(p):
                name = k if k in available else version_to_name.get(k)
                version = None if k in available else name_to_version.get(k)
                download(name=name, version=version, bundle_dir=model_dir, source="monaihosting", repo=zoo_repo)
                if version:
                    shutil.move(os.path.join(model_dir, name), p)
        bundles[k] = p

    return bundles


def get_bundle_models(app_dir, conf, conf_key="models"):
    """
    The funtion to get bundle models either from available model zoo or local files.
    MONAI Label maintains a list of supported bundles, non-labeling bundles are not supported.
    This function will filter available bundles according to the maintaining list.

    Args:
        app_dir: the app directory path
        conf: configs of start_server command
        conf_key: default to "models" for monaibundle app, if radiology app wants to use bundle models, "--conf bundles <names>" is used.

    Returns:
        a dictionary that contains the available bundles.

    Example:
        Bundle name: spleen_ct_segmentation, this will use latest version of the bundle.
        BUndle name with specific version: spleen_ct_segmentation_v0.4.0, this will download the specified version.
    """
    model_dir = os.path.join(app_dir, "model")

    zoo_source = conf.get("zoo_source", settings.MONAI_ZOO_SOURCE)

    models = conf.get(conf_key)
    models = models.split(",") if models else []
    models = [m.strip() for m in models]

    if zoo_source == "monaihosting":  # if in github env, access model zoo
        bundles = get_zoo_bundle(model_dir, conf, models, conf_key)
    else:  # if not in github env, no "model zoo" access, users either provide bundles locally, or auto download with latest
        bundles: Dict[str, str] = {}
        for k in models:
            p = os.path.join(model_dir, k)
            if os.path.isdir(p):
                logger.info(f"+++ Adding Bundle from Local: {k} => {p}")
            else:
                logger.info(f"+++ Adding Bundle from NGC: {k} => {p}")
                pattern = re.compile(r"(?P<name>.+)_v(?P<version>\d+\.\d+\.\d+)")
                match = pattern.match(k)
                if match:
                    name = match.group("name")
                    version = match.group("version") or None
                else:
                    name = k
                    version = None
                download(name=name, version=version, bundle_dir=model_dir, source=zoo_source)

            bundles[k] = p

    logger.info(f"+++ Using Bundle Models: {list(bundles.keys())}")
    return bundles


def path_to_uri(path) -> str:
    return pathlib.Path(path).absolute().as_uri()


def handle_torch_linalg_multithread(req):
    try:
        if torch.cuda.is_available():
            torch.inverse(torch.eye(1, device=req.get("device") if req else None))
    except RuntimeError:
        pass


def md5_digest(s: str) -> str:
    if sys.version_info.minor < 9:
        return hashlib.md5(s.encode("utf-8")).hexdigest()
    return hashlib.md5(s.encode("utf-8"), usedforsecurity=False).hexdigest()
