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

from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional


class DefaultLabelTag(str, Enum):
    ORIGINAL = "original"
    FINAL = "final"


class Datastore(metaclass=ABCMeta):
    @abstractmethod
    def name(self) -> str:
        """
        Return the human-readable name of the datastore

        :return: the name of the dataset
        """
        pass

    @abstractmethod
    def set_name(self, name: str):
        """
        Set the name of the datastore

        :param name: a human-readable name for the datastore
        """
        pass

    @abstractmethod
    def description(self) -> str:
        """
        Return the user-set description of the dataset

        :return: the user-set description of the dataset
        """
        pass

    @abstractmethod
    def set_description(self, description: str):
        """
        A human-readable description of the datastore

        :param description: string for description
        """
        pass

    @abstractmethod
    def datalist(self) -> List[Dict[str, Any]]:
        """
        Return a dictionary of image and label pairs corresponding to the 'image' and 'label'
        keys respectively

        :return: the {'image': image, 'label': label} pairs for training
        """
        pass

    @abstractmethod
    def get_labels_by_image_id(self, image_id: str) -> Dict[str, str]:
        """
        Retrieve all label ids for the given image id

        :param image_id: the desired image's id
        :return: label ids mapped to the appropriate `LabelTag` as Dict[LabelTag, str]
        """
        pass

    @abstractmethod
    def get_label_by_image_id(self, image_id: str, tag: str) -> str:
        """
        Retrieve label id for the given image id and tag

        :param image_id: the desired image's id
        :param tag: matching tag name
        :return: label id
        """
        pass

    @abstractmethod
    def get_image(self, image_id: str, params=None) -> Any:
        """
        Retrieve image object based on image id

        :param image_id: the desired image's id
        :param params: any optional params
        :return: return the "image"
        """
        pass

    @abstractmethod
    def get_image_uri(self, image_id: str) -> str:
        """
        Retrieve image uri based on image id

        :param image_id: the desired image's id
        :return: return the image uri
        """
        pass

    @abstractmethod
    def get_label(self, label_id: str, label_tag: str, params=None) -> Any:
        """
        Retrieve image object based on label id

        :param label_id: the desired label's id
        :param label_tag: the matching label's tag
        :param params: any optional params
        :return: return the "label"
        """
        pass

    @abstractmethod
    def get_label_uri(self, label_id: str, label_tag: str) -> str:
        """
        Retrieve label uri based on image id

        :param label_id: the desired label's id
        :param label_tag: the matching label's tag
        :return: return the label uri
        """
        pass

    @abstractmethod
    def get_image_info(self, image_id: str) -> Dict[str, Any]:
        """
        Get the image information for the given image id

        :param image_id: the desired image id
        :return: image info as a list of dictionaries Dict[str, Any]
        """
        pass

    @abstractmethod
    def get_label_info(self, label_id: str, label_tag: str) -> Dict[str, Any]:
        """
        Get the label information for the given label id

        :param label_id: the desired label id
        :param label_tag: the matching label tag
        :return: label info as a list of dictionaries Dict[str, Any]
        """
        pass

    @abstractmethod
    def get_labeled_images(self, label_tag: Optional[str] = None, labels: Optional[List[str]] = None) -> List[str]:
        """
        Get all images that have a corresponding final label

        :param label_tag: the matching label tag
        :param labels: list of matching labels
        :return: list of image ids List[str]
        """
        pass

    @abstractmethod
    def get_unlabeled_images(self, label_tag: Optional[str] = None, labels: Optional[List[str]] = None) -> List[str]:
        """
        Get all images that have no corresponding final label

        :param label_tag: the matching label tag
        :param labels: list of matching labels
        :return: list of image ids List[str]
        """
        pass

    @abstractmethod
    def list_images(self) -> List[str]:
        """
        Return list of image ids available in the datastore

        :return: list of image ids List[str]
        """
        pass

    @abstractmethod
    def get_dataset_archive(self, limit_cases: Optional[int]) -> str:
        """
        Retrieve ZIP archive of the full dataset containing images,
        labels and metadata

        :param limit_cases: limit the included cases to this number
        :return: path to ZIP archive of the full dataset
        """
        pass

    @abstractmethod
    def refresh(self) -> None:
        """
        Refresh the datastore
        """
        pass

    @abstractmethod
    def add_image(self, image_id: str, image_filename: str, image_info: Dict[str, Any]) -> str:
        """
        Save a image for the given image id and return the newly saved image's id

        :param image_id: the image id for the image;  If None then base filename will be used
        :param image_filename: the path to the image file
        :param image_info: additional info for the image
        :return: the image id for the saved image filename
        """
        pass

    @abstractmethod
    def remove_image(self, image_id: str) -> None:
        """
        Remove image for the datastore.  This will also remove all associated labels.

        :param image_id: the image id for the image to be removed from datastore
        """
        pass

    @abstractmethod
    def save_label(self, image_id: str, label_filename: str, label_tag: str, label_info: Dict[str, Any]) -> str:
        """
        Save a label for the given image id and return the newly saved label's id

        :param image_id: the image id for the label
        :param label_filename: the path to the label file
        :param label_tag: the user-provided tag for the label
        :param label_info: additional info for the label
        :return: the label id for the given label filename
        """
        pass

    @abstractmethod
    def remove_label(self, label_id: str, label_tag: str) -> None:
        """
        Remove label from the datastore

        :param label_id: the label id for the label to be removed from datastore
        :param label_tag: the label tag for the label to be removed from datastore
        """
        pass

    @abstractmethod
    def update_image_info(self, image_id: str, info: Dict[str, Any]) -> None:
        """
        Update (or create a new) info tag for the desired image

        :param image_id: the id of the image we want to add/update info
        :param info: a dictionary of custom image information Dict[str, Any]
        """
        pass

    @abstractmethod
    def update_label_info(self, label_id: str, label_tag: str, info: Dict[str, Any]) -> None:
        """
        Update (or create a new) info tag for the desired label

        :param label_id: the id of the label we want to add/update info
        :param label_tag: the matching label tag
        :param info: a dictionary of custom label information Dict[str, Any]
        """
        pass

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """
        Return current statistics of datastore
        """
        pass

    @abstractmethod
    def json(self):
        """
        Return json representation of datastore
        """
        pass
