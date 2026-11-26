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

import json
import logging
import os
import pathlib
import shutil
import tempfile
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.background import BackgroundTasks
from fastapi.responses import FileResponse

from monailabel.config import RBAC_ADMIN, RBAC_ANNOTATOR, RBAC_USER, settings
from monailabel.endpoints.user.auth import RBAC, User
from monailabel.interfaces.app import MONAILabelApp
from monailabel.interfaces.datastore import Datastore, DefaultLabelTag
from monailabel.interfaces.utils.app import app_instance
from monailabel.utils.others.generic import file_checksum, get_mime_type, remove_file

logger = logging.getLogger(__name__)
train_tasks: List = []
train_process: Dict = dict()

router = APIRouter(
    prefix="/datastore",
    tags=["Datastore"],
    responses={404: {"description": "Not found"}},
)


class ResultType(str, Enum):
    train = "train"
    stats = "stats"
    all = "all"


def datastore(output: Optional[ResultType] = None):
    d: Datastore = app_instance().datastore()
    output = output if output else ResultType.stats

    logger.debug(f"output type: {output}")
    if output == ResultType.all:
        return d.json()
    if output == ResultType.train:
        return d.datalist()
    return d.status()


def add_image(
    background_tasks: BackgroundTasks,
    image: Optional[str] = None,
    params: str = Form("{}"),
    file: UploadFile = File(...),
    user: Optional[str] = None,
):
    logger.info(f"Image: {image}; File: {file}; params: {params}")
    file_ext = "".join(pathlib.Path(file.filename).suffixes) if file.filename else ".nii.gz"

    image_id = image if image else os.path.basename(file.filename).replace(file_ext, "")
    image_file = tempfile.NamedTemporaryFile(suffix=file_ext).name

    with open(image_file, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        background_tasks.add_task(remove_file, image_file)

    instance: MONAILabelApp = app_instance()
    save_params: Dict[str, Any] = json.loads(params) if params else {}
    if user:
        save_params["user"] = user
    image_id = instance.datastore().add_image(image_id, image_file, save_params)
    return {"image": image_id}


def remove_image(id: str, user: Optional[str] = None):
    logger.info(f"Removing Image: {id} by {user}")
    instance: MONAILabelApp = app_instance()
    instance.datastore().remove_image(id)
    return {}


def save_label(
    background_tasks: BackgroundTasks,
    image: str,
    params: str = Form("{}"),
    tag: str = DefaultLabelTag.FINAL.value,
    label: UploadFile = File(...),
    user: Optional[str] = None,
):
    logger.info(f"Saving Label for {image} for tag: {tag} by {user}")
    file_ext = "".join(pathlib.Path(label.filename).suffixes) if label.filename else ".nii.gz"
    label_file = tempfile.NamedTemporaryFile(suffix=file_ext).name
    tag = tag if tag else DefaultLabelTag.FINAL.value

    with open(label_file, "wb") as buffer:
        shutil.copyfileobj(label.file, buffer)
        background_tasks.add_task(remove_file, label_file)

    instance: MONAILabelApp = app_instance()
    save_params: Dict[str, Any] = json.loads(params) if params else {}
    logger.info(f"Save Label params: {params}")

    label_id = instance.datastore().save_label(image, label_file, tag, save_params)
    res = instance.on_save_label(image, label_id)
    res = res if res else {}
    res.update(
        {
            "image": image,
            "label": label_id,
        }
    )
    return res


def remove_label(id: str, tag: str, user: Optional[str] = None):
    logger.info(f"Removing Label: {id} by {user}")
    instance: MONAILabelApp = app_instance()
    instance.datastore().remove_label(id, tag)
    return {}


def download_image(image: str, check_only=False, check_sum=None):
    instance: MONAILabelApp = app_instance()
    image = instance.datastore().get_image_uri(image)
    if not os.path.isfile(image):
        raise HTTPException(status_code=404, detail="Image NOT Found")

    if check_only:
        if check_sum:
            fields = check_sum.split(":")
            algo = "SHA256" if len(fields) == 1 else fields[0]
            digest = check_sum.lstrip(algo + ":") if len(fields) > 1 else check_sum
            if digest != file_checksum(image, algo=algo):
                raise HTTPException(status_code=404, detail="Image NOT Found (checksum failed)")
        return {}
    return FileResponse(image, media_type=get_mime_type(image), filename=os.path.basename(image))


def download_label(label: str, tag: str, check_only=False):
    instance: MONAILabelApp = app_instance()
    label = instance.datastore().get_label_uri(label, tag)
    if not os.path.isfile(label):
        raise HTTPException(status_code=404, detail="Label NOT Found")

    if check_only:
        return {}
    return FileResponse(label, media_type=get_mime_type(label), filename=os.path.basename(label))


def get_image_info(image: str):
    instance: MONAILabelApp = app_instance()
    return instance.datastore().get_image_info(image)


def update_image_info(image: str, info: str = Form("{}"), user: Optional[str] = None):
    logger.info(f"Update Image Info: {image} by {user}")

    instance: MONAILabelApp = app_instance()
    i = json.loads(info)
    if user:
        i["user"] = user
    return instance.datastore().update_image_info(image, i)


def get_label_info(label: str, tag: str):
    instance: MONAILabelApp = app_instance()
    return instance.datastore().get_label_info(label, tag)


def update_label_info(label: str, tag: str, info: str = Form("{}"), user: Optional[str] = None):
    logger.info(f"Update Label Info: {label} for {tag} by {user}")

    instance: MONAILabelApp = app_instance()
    i = json.loads(info)
    if user:
        i["user"] = user
    return instance.datastore().update_label_info(label, tag, i)


def download_dataset(limit_cases: Optional[int] = None):
    instance: MONAILabelApp = app_instance()
    path = instance.datastore().get_dataset_archive(limit_cases)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="ZIP archive NOT Found")
    return FileResponse(path, media_type=get_mime_type(path), filename="dataset.zip")


@router.get("/", summary=f"{RBAC_USER}Get All Images/Labels from datastore")
async def api_datastore(
    output: Optional[ResultType] = None,
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER)),
):
    return datastore(output)


@router.put("/", summary=f"{RBAC_ANNOTATOR}Upload new Image", include_in_schema=False, deprecated=True)
@router.put("/image", summary=f"{RBAC_ANNOTATOR}Upload new Image")
async def api_add_image(
    background_tasks: BackgroundTasks,
    image: Optional[str] = None,
    params: str = Form("{}"),
    file: UploadFile = File(...),
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return add_image(background_tasks, image, params, file, user.username)


@router.delete(
    "/", summary=f"{RBAC_ADMIN}Remove Image and corresponding labels", include_in_schema=False, deprecated=True
)
@router.delete("/image", summary=f"{RBAC_ADMIN}Remove Image and corresponding labels")
async def api_remove_image(id: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ADMIN))):
    return remove_image(id, user.username)


@router.head("/image", summary=f"{RBAC_USER}Check If Image Exists")
async def api_check_image(
    image: str,
    check_sum: Optional[str] = None,
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER)),
):
    return download_image(image, check_only=True, check_sum=check_sum)


@router.get("/image", summary=f"{RBAC_USER}Download Image")
async def api_download_image(image: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER))):
    return download_image(image)


@router.get("/image/info", summary=f"{RBAC_USER}Get Image Info")
async def api_get_image_info(image: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER))):
    return get_image_info(image)


@router.put("/image/info", summary=f"{RBAC_ANNOTATOR}Update Image Info")
async def api_put_image_info(
    image: str,
    info: str = Form("{}"),
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return update_image_info(image, info, user.username)


@router.put("/label", summary=f"{RBAC_ANNOTATOR}Save Finished Label")
async def api_save_label(
    background_tasks: BackgroundTasks,
    image: str,
    params: str = Form("{}"),
    tag: str = DefaultLabelTag.FINAL.value,
    label: UploadFile = File(...),
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return save_label(background_tasks, image, params, tag, label, user.username)


@router.delete("/label", summary=f"{RBAC_ADMIN}Remove Label")
async def api_remove_label(id: str, tag: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ADMIN))):
    return remove_label(id, tag, user.username)


@router.head("/label", summary=f"{RBAC_USER}Check If Label Exists")
async def api_check_label(image: str, tag: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER))):
    return download_label(image, tag, check_only=True)


@router.get("/label", summary=f"{RBAC_USER}Download Label")
async def api_download_label(label: str, tag: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER))):
    return download_label(label, tag)


@router.get("/label/info", summary=f"{RBAC_USER}Get Label Info")
async def api_get_label_info(label: str, tag: str, user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_USER))):
    return get_label_info(label, tag)


@router.put("/label/info", summary=f"{RBAC_ANNOTATOR}Update Label Info")
async def api_put_label_info(
    label: str,
    tag: str,
    info: str = Form("{}"),
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return update_label_info(label, tag, info, user.username)


@router.put("/updatelabelinfo", summary=f"{RBAC_ANNOTATOR}Update label info", include_in_schema=False, deprecated=True)
async def api_update_label_info(
    label: str,
    tag: str,
    params: str = Form("{}"),
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return update_label_info(label, tag, params, user.username)


@router.get("/dataset", summary=f"{RBAC_ANNOTATOR}Download full dataset as ZIP archive")
async def api_download_dataset(
    limit_cases: Optional[int] = None,
    user: User = Depends(RBAC(settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR)),
):
    return download_dataset(limit_cases)
