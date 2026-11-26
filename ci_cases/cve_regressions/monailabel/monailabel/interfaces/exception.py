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

from enum import Enum


class MONAILabelError(Enum):
    """
    Attributes:
        SERVER_ERROR -            Server Error
        UNKNOWN_ERROR -           Unknown Error
        CLASS_INIT_ERROR -        Class Initialization Error
        MODEL_IMPORT_ERROR -      Model Import Error
        INFERENCE_ERROR -         Inference Error
        TRANSFORM_ERROR -         Transform Error
        INVALID_INPUT -           Invalid Input

        APP_INIT_ERROR -          Initialization Error
        APP_INFERENCE_FAILED -    Inference Failed
        APP_TRAIN_FAILED -        Train Failed
        APP_ERROR APP -           General Error
    """

    SERVER_ERROR = "SERVER_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    CLASS_INIT_ERROR = "CLASS_INIT_ERROR"
    MODEL_IMPORT_ERROR = "MODEL_IMPORT_ERROR"
    INFERENCE_ERROR = "INFERENCE_ERROR"
    TRANSFORM_ERROR = "TRANSFORM_ERROR"
    INVALID_INPUT = "INVALID_INPUT"

    APP_INIT_ERROR = "APP_INIT_ERROR"
    APP_INFERENCE_FAILED = "APP_INFERENCE_FAILED"
    APP_TRAIN_FAILED = "APP_TRAIN_FAILED"
    APP_ERROR = "APP_ERROR"


class MONAILabelException(Exception):
    """
    MONAI Label Exception
    """

    __slots__ = ["error", "msg"]

    def __init__(self, error: MONAILabelError, msg: str):
        super().__setattr__("error", error)
        super().__setattr__("msg", msg)


class ImageNotFoundException(MONAILabelException):
    def __init__(self, msg: str):
        super().__init__(MONAILabelError.APP_ERROR, msg)


class LabelNotFoundException(MONAILabelException):
    def __init__(self, msg: str):
        super().__init__(MONAILabelError.APP_ERROR, msg)
