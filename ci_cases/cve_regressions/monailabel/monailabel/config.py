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
from importlib.metadata import distributions
from typing import Any, Dict, List, Optional

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


def is_package_installed(name):
    return name in sorted(x.name for x in distributions())


class Settings(BaseSettings):
    MONAI_LABEL_API_STR: str = ""
    MONAI_LABEL_PROJECT_NAME: str = "MONAILabel"

    MONAI_LABEL_APP_DIR: str = ""
    MONAI_LABEL_STUDIES: str = ""
    MONAI_LABEL_APP_CONF: Dict[str, Any] = {}

    MONAI_LABEL_AUTH_ENABLE: bool = False
    MONAI_LABEL_AUTH_REALM_URI: str = "http://localhost:8080/realms/monailabel"
    MONAI_LABEL_AUTH_TIMEOUT: int = 10
    MONAI_LABEL_AUTH_TOKEN_USERNAME: str = "preferred_username"
    MONAI_LABEL_AUTH_TOKEN_EMAIL: str = "email"
    MONAI_LABEL_AUTH_TOKEN_NAME: str = "name"
    MONAI_LABEL_AUTH_TOKEN_ROLES: str = "realm_access#roles"
    MONAI_LABEL_AUTH_CLIENT_ID: str = "monailabel-app"

    MONAI_LABEL_AUTH_ROLE_ADMIN: str = "monailabel-admin"
    MONAI_LABEL_AUTH_ROLE_REVIEWER: str = "monailabel-reviewer"
    MONAI_LABEL_AUTH_ROLE_ANNOTATOR: str = "monailabel-annotator"
    MONAI_LABEL_AUTH_ROLE_USER: str = "monailabel-user"

    MONAI_LABEL_TASKS_TRAIN: bool = True
    MONAI_LABEL_TASKS_STRATEGY: bool = True
    MONAI_LABEL_TASKS_SCORING: bool = True
    MONAI_LABEL_TASKS_BATCH_INFER: bool = True

    MONAI_LABEL_DATASTORE: str = ""
    MONAI_LABEL_DATASTORE_URL: str = ""
    MONAI_LABEL_DATASTORE_USERNAME: str = ""
    MONAI_LABEL_DATASTORE_PASSWORD: str = ""
    MONAI_LABEL_DATASTORE_API_KEY: str = ""
    MONAI_LABEL_DATASTORE_CACHE_PATH: str = ""
    MONAI_LABEL_DATASTORE_PROJECT: str = ""
    MONAI_LABEL_DATASTORE_ASSET_PATH: str = ""

    MONAI_LABEL_DATASTORE_DSA_ANNOTATION_GROUPS: str = ""

    MONAI_LABEL_DICOMWEB_USERNAME: str = ""  # will be deprecated; use MONAI_LABEL_DATASTORE_USERNAME
    MONAI_LABEL_DICOMWEB_PASSWORD: str = ""  # will be deprecated; use MONAI_LABEL_DATASTORE_PASSWORD
    MONAI_LABEL_DICOMWEB_CACHE_PATH: str = ""  # will be deprecated; use MONAI_LABEL_DATASTORE_CACHE_PATH
    MONAI_LABEL_QIDO_PREFIX: Optional[str] = None
    MONAI_LABEL_WADO_PREFIX: Optional[str] = None
    MONAI_LABEL_STOW_PREFIX: Optional[str] = None
    MONAI_LABEL_DICOMWEB_FETCH_BY_FRAME: bool = False
    MONAI_LABEL_DICOMWEB_CONVERT_TO_NIFTI: bool = True
    MONAI_LABEL_DICOMWEB_SEARCH_FILTER: Dict[str, Any] = {"Modality": "CT"}
    MONAI_LABEL_DICOMWEB_CACHE_EXPIRY: int = 7200
    MONAI_LABEL_DICOMWEB_PROXY_TIMEOUT: float = 30.0
    MONAI_LABEL_DICOMWEB_READ_TIMEOUT: float = 5.0

    MONAI_LABEL_DATASTORE_AUTO_RELOAD: bool = True
    MONAI_LABEL_DATASTORE_READ_ONLY: bool = False
    MONAI_LABEL_DATASTORE_FILE_EXT: List[str] = [
        "*.nii.gz",
        "*.nii",
        "*.nrrd",
        "*.jpg",
        "*.png",
        "*.tif",
        "*.svs",
        "*.xml",
    ]

    MONAI_LABEL_SERVER_PORT: int = 8000
    MONAI_LABEL_CORS_ORIGINS: List[AnyHttpUrl] = []

    MONAI_LABEL_AUTO_UPDATE_SCORING: bool = True

    MONAI_LABEL_SESSIONS: bool = True
    MONAI_LABEL_SESSION_PATH: str = ""
    MONAI_LABEL_SESSION_EXPIRY: int = 3600

    MONAI_LABEL_INFER_CONCURRENCY: int = -1
    MONAI_LABEL_INFER_TIMEOUT: int = 600
    MONAI_LABEL_TRACKING_ENABLED: bool = True
    MONAI_LABEL_TRACKING_URI: str = ""

    MONAI_ZOO_SOURCE: str = os.environ.get("BUNDLE_DOWNLOAD_SRC", "monaihosting")
    MONAI_ZOO_REPO: str = "Project-MONAI/model-zoo/hosting_storage_v1"
    MONAI_ZOO_AUTH_TOKEN: str = ""

    # Refer: https://github.com/facebookresearch/sam2?tab=readme-ov-file#model-description
    # Refer: https://huggingface.co/facebook/sam2-hiera-large
    MONAI_SAM_MODEL_PT: str = (
        "https://huggingface.co/facebook/sam2.1-hiera-large/resolve/main/sam2.1_hiera_large.pt"
        if is_package_installed("SAM-2")
        else "https://huggingface.co/facebook/sam2-hiera-large/resolve/main/sam2_hiera_large.pt"
    )
    MONAI_SAM_MODEL_CFG: str = (
        "https://huggingface.co/facebook/sam2.1-hiera-large/resolve/main/sam2.1_hiera_l.yaml"
        if is_package_installed("SAM-2")
        else "https://huggingface.co/facebook/sam2-hiera-large/resolve/main/sam2_hiera_l.yaml"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
RBAC_ADMIN = f"|RBAC: {settings.MONAI_LABEL_AUTH_ROLE_ADMIN}| - " if settings.MONAI_LABEL_AUTH_ENABLE else ""
RBAC_REVIEWER = f"|RBAC: {settings.MONAI_LABEL_AUTH_ROLE_REVIEWER}| - " if settings.MONAI_LABEL_AUTH_ENABLE else ""
RBAC_ANNOTATOR = f"|RBAC: {settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR}| - " if settings.MONAI_LABEL_AUTH_ENABLE else ""
RBAC_USER = f"|RBAC: {settings.MONAI_LABEL_AUTH_ROLE_USER}| - " if settings.MONAI_LABEL_AUTH_ENABLE else ""
