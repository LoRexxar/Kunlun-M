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

import copy
import logging
import multiprocessing
import os
import platform
import random
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any, Callable, Dict, Optional, Sequence, Union

import requests
import schedule
import torch
from dicomweb_client import DICOMwebClient

# added to support connecting to DICOM Store Google Cloud
from dicomweb_client.ext.gcp.session_utils import create_session_from_gcp_credentials
from dicomweb_client.session_utils import create_session_from_user_pass
from monai.apps import download_and_extract
from timeloop import Timeloop

from monailabel.config import settings
from monailabel.datastore.dicom import DICOMwebClientX, DICOMWebDatastore
from monailabel.datastore.dsa import DSADatastore
from monailabel.datastore.local import LocalDatastore
from monailabel.datastore.xnat import XNATDatastore
from monailabel.interfaces.datastore import Datastore, DefaultLabelTag
from monailabel.interfaces.exception import MONAILabelError, MONAILabelException
from monailabel.interfaces.tasks.batch_infer import BatchInferImageType, BatchInferTask
from monailabel.interfaces.tasks.infer_v2 import InferTask
from monailabel.interfaces.tasks.scoring import ScoringMethod
from monailabel.interfaces.tasks.strategy import Strategy
from monailabel.interfaces.tasks.train import TrainTask
from monailabel.interfaces.utils.wsi import create_infer_wsi_tasks
from monailabel.tasks.activelearning.random import Random
from monailabel.tasks.train.bundle import BundleTrainTask
from monailabel.utils.async_tasks.task import AsyncTask
from monailabel.utils.others.generic import (
    file_checksum,
    handle_torch_linalg_multithread,
    is_openslide_supported,
    name_to_device,
    strtobool,
)
from monailabel.utils.others.pathology import create_asap_annotations_xml, create_dsa_annotations_json
from monailabel.utils.sessions import Sessions

logger = logging.getLogger(__name__)


class MONAILabelApp:
    """
    Default Pre-trained Path for downloading models
    """

    PRE_TRAINED_PATH: str = "https://github.com/Project-MONAI/MONAILabel/releases/download/data"

    def __init__(
        self,
        app_dir: str,
        studies: str,
        conf: Dict[str, str],
        name: str = "",
        description: str = "",
        version: str = "2.0",
        labels: Union[Optional[Sequence[str]], Optional[Dict[Any, Any]]] = None,
    ):
        """
        Base Class for Any MONAI Label App

        :param app_dir: path for your App directory
        :param studies: path for studies/datalist
        :param conf: dictionary of key/value pairs provided by user while running the app

        """
        self.app_dir = app_dir
        self.studies = studies
        self.conf = conf if conf else {}

        self.name = name
        self.description = description
        self.version = version
        self.labels = labels

        self._datastore: Datastore = self.init_datastore()

        self._infers = self.init_infers()
        self._trainers = self.init_trainers() if settings.MONAI_LABEL_TASKS_TRAIN else {}
        self._strategies = self.init_strategies() if settings.MONAI_LABEL_TASKS_STRATEGY else {}
        self._scoring_methods = self.init_scoring_methods() if settings.MONAI_LABEL_TASKS_SCORING else {}
        self._batch_infer = self.init_batch_infer() if settings.MONAI_LABEL_TASKS_BATCH_INFER else {}

        self._auto_update_scoring = settings.MONAI_LABEL_AUTO_UPDATE_SCORING
        self._sessions = self._load_sessions(load=settings.MONAI_LABEL_SESSIONS)

        self._infers_threadpool = (
            None
            if settings.MONAI_LABEL_INFER_CONCURRENCY < 0
            else ThreadPoolExecutor(max_workers=settings.MONAI_LABEL_INFER_CONCURRENCY, thread_name_prefix="INFER")
        )

        # control call back requests
        self._server_mode = bool(strtobool(conf.get("server_mode", "false")))

    def init_infers(self) -> Dict[str, InferTask]:
        return {}

    def init_trainers(self) -> Dict[str, TrainTask]:
        return {}

    def init_strategies(self) -> Dict[str, Strategy]:
        return {"random": Random()}

    def init_scoring_methods(self) -> Dict[str, ScoringMethod]:
        return {}

    def init_batch_infer(self) -> Callable:
        return BatchInferTask()

    def init_datastore(self) -> Datastore:
        logger.info(f"Init Datastore for: {self.studies}")
        if self.studies.startswith("http://") or self.studies.startswith("https://"):
            self.studies = self.studies.rstrip("/").strip()
            return self.init_remote_datastore()

        return LocalDatastore(
            self.studies,
            extensions=settings.MONAI_LABEL_DATASTORE_FILE_EXT,
            auto_reload=settings.MONAI_LABEL_DATASTORE_AUTO_RELOAD,
            read_only=settings.MONAI_LABEL_DATASTORE_READ_ONLY,
        )

    def init_remote_datastore(self) -> Datastore:
        if settings.MONAI_LABEL_DATASTORE.lower() == "xnat":
            return self._init_xnat_datastore()
        if settings.MONAI_LABEL_DATASTORE.lower() == "dsa":
            return self._init_dsa_datastore()

        return self._init_dicomweb_datastore()

    def _init_dicomweb_datastore(self) -> Datastore:
        logger.info(f"Using DICOM WEB: {self.studies}")

        dw_session = None
        if "googleapis.com" in self.studies:
            logger.info("Creating DICOM Credentials for Google Cloud")
            dw_session = create_session_from_gcp_credentials()
            dw_client = DICOMwebClient(url=self.studies, session=dw_session)
        else:
            if settings.MONAI_LABEL_DICOMWEB_USERNAME and settings.MONAI_LABEL_DICOMWEB_PASSWORD:
                dw_session = create_session_from_user_pass(
                    settings.MONAI_LABEL_DICOMWEB_USERNAME, settings.MONAI_LABEL_DICOMWEB_PASSWORD
                )
            dw_client = DICOMwebClientX(
                url=self.studies,
                session=dw_session,
                qido_url_prefix=settings.MONAI_LABEL_QIDO_PREFIX,
                wado_url_prefix=settings.MONAI_LABEL_WADO_PREFIX,
                stow_url_prefix=settings.MONAI_LABEL_STOW_PREFIX,
            )

        self._download_dcmqi_tools()

        cache_path = settings.MONAI_LABEL_DICOMWEB_CACHE_PATH
        cache_path = cache_path.strip() if cache_path else ""
        fetch_by_frame = settings.MONAI_LABEL_DICOMWEB_FETCH_BY_FRAME
        search_filter = settings.MONAI_LABEL_DICOMWEB_SEARCH_FILTER
        convert_to_nifti = settings.MONAI_LABEL_DICOMWEB_CONVERT_TO_NIFTI
        return DICOMWebDatastore(
            client=dw_client,
            search_filter=search_filter,
            cache_path=cache_path if cache_path else None,
            fetch_by_frame=fetch_by_frame,
            convert_to_nifti=convert_to_nifti,
        )

    def _init_dsa_datastore(self) -> Datastore:
        logger.info(f"Using DSA: {self.studies}")
        return DSADatastore(
            api_url=self.studies,
            api_key=settings.MONAI_LABEL_DATASTORE_API_KEY,
            folder=settings.MONAI_LABEL_DATASTORE_PROJECT,
            annotation_groups=settings.MONAI_LABEL_DATASTORE_DSA_ANNOTATION_GROUPS,
            asset_store_path=settings.MONAI_LABEL_DATASTORE_ASSET_PATH,
        )

    def _init_xnat_datastore(self) -> Datastore:
        logger.info(f"Using XNAT: {self.studies}")
        return XNATDatastore(
            api_url=self.studies,
            username=settings.MONAI_LABEL_DATASTORE_USERNAME,
            password=settings.MONAI_LABEL_DATASTORE_PASSWORD,
            project=settings.MONAI_LABEL_DATASTORE_PROJECT,
            asset_path=settings.MONAI_LABEL_DATASTORE_ASSET_PATH,
            cache_path=settings.MONAI_LABEL_DATASTORE_CACHE_PATH,
        )

    def info(self):
        """
        Provide basic information about APP.  This information is passed to client.
        """
        meta = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "labels": self.labels,
            "models": {k: v.info() for k, v in self._infers.items() if v.is_valid()},
            "trainers": {k: v.info() for k, v in self._trainers.items()},
            "strategies": {k: v.info() for k, v in self._strategies.items()},
            "scoring": {k: v.info() for k, v in self._scoring_methods.items()},
            "train_stats": {k: v.stats() for k, v in self._trainers.items()},
            "datastore": self._datastore.status(),
        }

        # If labels are not provided, aggregate from all individual infers
        if not self.labels:
            merged = []
            for labels in [v.get("labels", []) for v in meta["models"].values()]:
                if labels and isinstance(labels, dict):
                    labels = [k for k, _ in sorted(labels.items(), key=lambda item: item[1])]  # type: ignore
                for label in labels:
                    if label not in merged:
                        merged.append(label)
            meta["labels"] = merged

        return meta

    def infer(self, request, datastore=None):
        """
        Run Inference for an exiting pre-trained model.

        Args:
            request: JSON object which contains `model`, `image`, `params` and `device`
            datastore: Datastore object.  If None then use default app level datastore to save labels if applicable

                For example::

                    {
                        "device": "cuda"
                        "model": "segmentation_spleen",
                        "image": "file://xyz",
                        "save_label": "true/false",
                        "label_tag": "original"
                    }

        Raises:
            MONAILabelException: When ``model`` is not found

        Returns:
            JSON containing `label` and `params`
        """
        model = request.get("model")
        if not model:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                "Model is not provided for Inference Task",
            )

        task = self._infers.get(model)
        if not task:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                f"Inference Task is not Initialized. There is no model '{model}' available",
            )

        request = copy.deepcopy(request)
        request["description"] = task.description

        image_id = request["image"]
        if isinstance(image_id, str):
            datastore = datastore if datastore else self.datastore()
            if os.path.exists(image_id):
                request["save_label"] = False
            else:
                request["image"] = datastore.get_image_uri(request["image"])

            if os.path.isdir(request["image"]):
                logger.info("Input is a Directory; Consider it as DICOM")

            logger.debug(f"Image => {request['image']}")
        else:
            request["save_label"] = False

        if self._infers_threadpool:

            def run_infer_in_thread(t, r):
                handle_torch_linalg_multithread(r)
                return t(r)

            f = self._infers_threadpool.submit(run_infer_in_thread, t=task, r=request)
            result_file_name, result_json = f.result(request.get("timeout", settings.MONAI_LABEL_INFER_TIMEOUT))
        else:
            result_file_name, result_json = task(request)

        label_id = None
        if result_file_name and os.path.exists(result_file_name):
            tag = request.get("label_tag", DefaultLabelTag.ORIGINAL)
            save_label = request.get("save_label", False)
            if save_label:
                label_id = datastore.save_label(
                    image_id, result_file_name, tag, {"model": model, "params": result_json}
                )
            else:
                label_id = result_file_name

        return {"label": label_id, "tag": DefaultLabelTag.ORIGINAL, "file": result_file_name, "params": result_json}

    def batch_infer(self, request, datastore=None):
        """
        Run batch inference for an existing pre-trained model.

        Args:
            request: JSON object which contains `model`, `params` and `device`
            datastore: Datastore object.  If None then use default app level datastore to fetch the images

                For example::

                    {
                        "device": "cuda"
                        "model": "segmentation_spleen",
                        "images": "unlabeled",
                        "label_tag": "original"
                    }

        Raises:
            MONAILabelException: When ``model`` is not found

        Returns:
            JSON containing `label` and `params`
        """
        return self._batch_infer(request, datastore if datastore else self.datastore(), self.infer)

    def scoring(self, request, datastore=None):
        """
        Run scoring task over labels.

        Args:
            request: JSON object which contains `model`, `params` and `device`
            datastore: Datastore object.  If None then use default app level datastore to fetch the images

                For example::

                    {
                        "device": "cuda"
                        "method": "dice",
                        "y": "final",
                        "y_pred": "original",
                    }

        Raises:
            MONAILabelException: When ``method`` is not found

        Returns:
            JSON containing result of scoring method
        """
        method = request.get("method")
        if not method:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                "Method is not provided for Scoring Task",
            )

        task = self._scoring_methods.get(method)
        if not task:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                f"Scoring Task is not Initialized. There is no such scoring method '{method}' available",
            )

        request = copy.deepcopy(request)
        return task(copy.deepcopy(request), datastore if datastore else self.datastore())

    def datastore(self) -> Datastore:
        return self._datastore

    def train(self, request):
        """
        Run Training.  User APP has to implement this method to run training

        Args:
            request: JSON object which contains train configs that are part APP info

                For example::

                    {
                        "model": "mytrain",
                        "device": "cuda"
                        "max_epochs": 1,
                    }

        Returns:
            JSON containing train stats
        """
        model = request.get("model")
        if not model:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                "Model is not provided for Training Task",
            )

        task = self._trainers.get(model)
        if not task:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                f"Train Task is not Initialized. There is no model '{model}' available; {request}",
            )

        request = copy.deepcopy(request)
        result = task(request, self.datastore())

        # Run all scoring methods
        if self._auto_update_scoring:
            self.async_scoring(None)
        return result

    def next_sample(self, request):
        """
        Run Active Learning selection.  User APP has to implement this method to provide next sample for labelling.

        Args:
            request: JSON object which contains active learning configs that are part APP info

                For example::

                    {
                        "strategy": "random"
                    }

        Returns:
            JSON containing next image info that is selected for labeling
        """
        strategy = request.get("strategy")
        strategy = strategy if strategy else "random"

        task = self._strategies.get(strategy)
        if task is None:
            raise MONAILabelException(
                MONAILabelError.APP_INIT_ERROR,
                f"ActiveLearning Task is not Initialized. There is no such strategy '{strategy}' available",
            )

        res = task(request, self.datastore())
        if not res or not res.get("id"):
            return {}

        res["path"] = self._datastore.get_image_uri(res["id"])

        # Run all scoring methods
        if self._auto_update_scoring:
            self.async_scoring(None)

        return res

    def on_init_complete(self):
        logger.info("App Init - completed")

        # Run all scoring methods
        if self._auto_update_scoring:
            self.async_scoring(None)

        # Run Cleanup Jobs
        def cleanup_sessions(instance):
            instance.cleanup_sessions()

        cleanup_sessions(self)
        time_loop = Timeloop()
        schedule.every(5).minutes.do(cleanup_sessions, self)

        @time_loop.job(interval=timedelta(seconds=30))
        def run_scheduler():
            schedule.run_pending()

        time_loop.start(block=False)

    def on_save_label(self, image_id, label_id):
        """
        Callback method when label is saved into datastore by a remote client
        """
        logger.info(f"New label saved for: {image_id} => {label_id}")

    # TODO :: Allow model files to be monitored and call this method when it is published (during training)
    # def on_model_published(self, model):
    #    pass

    def server_mode(self, mode: bool):
        self._server_mode = mode

    def async_scoring(self, method, params=None):
        if not method and not self._scoring_methods:
            return {}

        methods = [method] if method else list(self._scoring_methods.keys())
        result = {}
        for m in methods:
            if self._server_mode:
                request = {"method": m}
                request.update(params[m] if params and params.get(m) else {})
                res, _ = AsyncTask.run("scoring", request=request, params=params, enqueue=True)
                result[m] = res
            else:
                url = f"/scoring/{m}"
                p = params[m] if params and params.get(m) else None
                result[m] = self._local_request(url, p, "Scoring")
        return result[method] if method else result

    def async_training(self, model, params=None, enqueue=False):
        if not model and not self._trainers:
            return {}

        models = list(self._trainers.keys()) if not model else [model] if isinstance(model, str) else model
        enqueue = True if len(models) > 1 else enqueue
        result = {}
        for m in models:
            if self._server_mode:
                request = {"model": m}
                request.update(params[m] if params and params.get(m) else {})
                res, _ = AsyncTask.run("train", request=request, params=params, enqueue=enqueue)
                result[m] = res
            else:
                url = f"/train/{m}?enqueue={enqueue}"
                p = params[m] if params and params.get(m) else None
                result[m] = self._local_request(url, p, "Training")
        return result[models[0]] if len(models) == 1 else result

    def async_batch_infer(self, model, images: BatchInferImageType, params=None):
        if self._server_mode:
            request = {"model": model, "images": images}
            res, _ = AsyncTask.run("batch_infer", request=request, params=params)
            return res

        url = f"/batch/infer/{model}?images={images}"
        return self._local_request(url, params, "Batch Infer")

    def _local_request(self, url, params, action):
        params = params if params else {}
        response = requests.post(f"http://127.0.0.1:{settings.MONAI_LABEL_SERVER_PORT}{url}", json=params)

        if response.status_code != 200:
            logger.error(f"Failed To Trigger {action}: {response.text}")
        return response.json() if response.status_code == 200 else None

    def _download_dcmqi_tools(self):
        target = os.path.join(self.app_dir, "bin")
        os.makedirs(target, exist_ok=True)

        dcmqi_tools = ["itkimage2segimage", "itkimage2segimage.exe"]
        existing = [tool for tool in dcmqi_tools if shutil.which(tool) or os.path.exists(os.path.join(target, tool))]
        logger.debug(f"Existing Tools: {existing}")

        if len(existing) in [len(dcmqi_tools), len(dcmqi_tools) // 2]:
            logger.debug("No need to download dcmqi tools")
            return

        target_os = "win64.zip" if any(platform.win32_ver()) else "linux.tar.gz"
        with tempfile.TemporaryDirectory() as tmp:
            download_and_extract(
                url=f"https://github.com/QIICR/dcmqi/releases/download/v1.2.4/dcmqi-1.2.4-{target_os}", output_dir=tmp
            )
            for root, _, files in os.walk(tmp):
                for f in files:
                    if f in dcmqi_tools:
                        shutil.copy(os.path.join(root, f), target)

    def _load_sessions(self, load=False):
        if not load:
            return None
        return Sessions(settings.MONAI_LABEL_SESSION_PATH, settings.MONAI_LABEL_SESSION_EXPIRY)

    def cleanup_sessions(self):
        if not self._sessions:
            return
        count = self._sessions.remove_expired()
        logger.debug(f"Total sessions cleaned up: {count}")

    def sessions(self):
        return self._sessions

    def infer_wsi(self, request, datastore=None):
        model = request.get("model")
        if not model:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                "Model is not provided for WSI/Inference Task",
            )

        task = self._infers.get(model)
        if not task:
            raise MONAILabelException(
                MONAILabelError.INVALID_INPUT,
                f"WSI/Inference Task is not Initialized. There is no model '{model}' available",
            )

        img_id = request["image"]
        image = img_id
        request_c = copy.deepcopy(task.config())
        request_c.update(request)
        request = request_c

        # Possibly direct image (numpy)
        if not isinstance(image, str):
            res = self.infer(request, datastore)
            logger.info(f"Latencies: {res.get('params', {}).get('latencies')}")
            return res

        request = copy.deepcopy(request)
        if not os.path.exists(image):
            datastore = datastore if datastore else self.datastore()
            image = datastore.get_image_uri(request["image"])

        # Possibly region (e.g. DSA)
        if not os.path.exists(image):
            image = datastore.get_image(img_id, request)
            if isinstance(datastore, DSADatastore):
                request["annotations"] = datastore.get_annotations_by_image_id(img_id)

            if not isinstance(image, str):
                request["image"] = image
                res = self.infer(request, datastore)
                logger.info(f"Latencies: {res.get('params', {}).get('latencies')}")
                return res

        # simple image
        if not is_openslide_supported(image):
            res = self.infer(request, datastore)
            logger.info(f"Latencies: {res.get('params', {}).get('latencies')}")
            return res

        start = time.time()
        infer_tasks = create_infer_wsi_tasks(request, image)
        if len(infer_tasks) > 1:
            logger.info(f"WSI Infer Request (final): {request}")

        logger.debug(f"Total WSI Tasks: {len(infer_tasks)}")
        request["logging"] = request.get("logging", "WARNING" if len(infer_tasks) > 1 else "INFO")

        multi_gpu = request.get("multi_gpu", True)
        multi_gpus = request.get("gpus", "all")
        gpus = (
            list(range(torch.cuda.device_count())) if not multi_gpus or multi_gpus == "all" else multi_gpus.split(",")
        )
        device = name_to_device(request.get("device", "cuda"))
        device_ids = [f"cuda:{id}" for id in gpus] if multi_gpu else [device]

        res_json = {"annotations": [None] * len(infer_tasks)}
        for idx, t in enumerate(infer_tasks):
            t["logging"] = request["logging"]
            t["device"] = (
                device_ids[idx % len(device_ids)]
                if len(infer_tasks) > 1
                else device_ids[random.randint(0, len(device_ids) - 1)]
            )

        total = len(infer_tasks)
        max_workers = request.get("max_workers", 0)
        max_workers = max_workers if max_workers else max(1, multiprocessing.cpu_count() // 2)
        max_workers = min(max_workers, multiprocessing.cpu_count())

        if len(infer_tasks) > 1 and (max_workers == 0 or max_workers > 1):
            logger.info(f"MultiGpu: {multi_gpu}; Using Device(s): {device_ids}; Max Workers: {max_workers}")
            futures = {}
            with ThreadPoolExecutor(max_workers if max_workers else None, "WSI Infer") as executor:
                for t in infer_tasks:
                    futures[t["id"]] = t, executor.submit(self._run_infer_wsi_task, t)

                for tid, (t, future) in futures.items():
                    res = future.result()
                    res_json["annotations"][tid] = res
                    finished = len([a for a in res_json["annotations"] if a])
                    logger.info(
                        f"{img_id} => {tid} => {t['device']} => {finished} / {total}; Latencies: {res.get('latencies')}"
                    )
        else:
            for t in infer_tasks:
                tid = t["id"]
                res = self._run_infer_wsi_task(t, multi_thread=False)
                res_json["annotations"][tid] = res
                finished = len([a for a in res_json["annotations"] if a])
                logger.info(
                    f"{img_id} => {tid} => {t['device']} => {finished} / {total}; Latencies: {res.get('latencies')}"
                )

        latency_total = time.time() - start
        logger.debug(f"WSI Infer Time Taken: {latency_total:.4f}")

        bbox = request.get("location", [0, 0])
        bbox.extend(request.get("size", [0, 0]))
        res_json["name"] = f"MONAILabel Annotations - {model} for {bbox}"
        res_json["description"] = task.description
        res_json["model"] = request.get("model")
        res_json["location"] = request.get("location")
        res_json["size"] = request.get("size")

        res_json["latencies"] = {
            "total": round(latency_total, 2),
            "tsum": round(sum(a["latencies"]["total"] for a in res_json["annotations"]) / max(1, max_workers), 2),
            "pre": round(sum(a["latencies"]["pre"] for a in res_json["annotations"]) / max(1, max_workers), 2),
            "post": round(sum(a["latencies"]["post"] for a in res_json["annotations"]) / max(1, max_workers), 2),
            "infer": round(sum(a["latencies"]["infer"] for a in res_json["annotations"]) / max(1, max_workers), 2),
        }

        res_file = None
        output = request.get("output", "dsa")
        logger.debug(f"+++ WSI Inference Output Type: {output}")

        loglevel = request.get("logging", "INFO").upper()
        if output == "asap":
            logger.info("+++ Generating ASAP XML Annotation")
            res_file, total_annotations = create_asap_annotations_xml(res_json, loglevel)
        elif output == "dsa":
            logger.info("+++ Generating DSA JSON Annotation")
            res_file, total_annotations = create_dsa_annotations_json(res_json, loglevel)
        else:
            logger.info("+++ Return Default JSON Annotation")
            total_annotations = -1

        if len(infer_tasks) > 1:
            logger.info(
                f"Total Time Taken: {time.time() - start:.4f}; "
                f"Total WSI Infer Time: {latency_total:.4f}; "
                f"Total Annotations: {total_annotations}; "
                f"Latencies: {res_json['latencies']}"
            )
        return {"file": res_file, "params": res_json}

    def _run_infer_wsi_task(self, task, multi_thread=True):
        req = copy.deepcopy(task)
        req["result_write_to_file"] = False

        if multi_thread:
            handle_torch_linalg_multithread(req)
        res = self.infer(req)
        return res.get("params", {})

    def model_file(self, model, validate=True):
        task = self._infers.get(model)
        return task.get_path(validate) if task else None

    def bundle_path(self, model):
        task = self._trainers.get(model)
        return task.bundle_path if isinstance(task, BundleTrainTask) else None

    def model_info(self, model):
        file = self.model_file(model)
        if not file or not os.path.exists(file):
            return None

        s = os.stat(file)
        checksum = file_checksum(file)

        info = {"checksum": checksum, "modified_time": int(s.st_mtime)}
        task = self._trainers.get(model)
        train_stats = task.stats() if task else None
        if train_stats:
            info["train_stats"] = train_stats
        return info
