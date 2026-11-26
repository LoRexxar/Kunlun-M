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
import fnmatch
import io
import json
import logging
import os
import pathlib
import shutil
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from filelock import FileLock
from pydantic import BaseModel
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from monailabel.interfaces.datastore import Datastore, DefaultLabelTag
from monailabel.interfaces.exception import ImageNotFoundException, LabelNotFoundException
from monailabel.utils.others.generic import file_ext, remove_file

logger = logging.getLogger(__name__)


class DataModel(BaseModel):
    ext: str = ""
    info: Dict[str, Any] = {}


class ImageLabelModel(BaseModel):
    image: DataModel
    labels: Dict[str, DataModel] = {}  # tag => label

    def tags(self):
        return self.labels.keys()


class LocalDatastoreModel(BaseModel):
    name: str
    description: str
    images_dir: str = ""
    labels_dir: str = "labels"
    objects: Dict[str, ImageLabelModel] = {}

    # will be ignored while saving...
    base_path: str = ""

    def tags(self):
        tags = set()
        for v in self.objects.values():
            tags.update(v.tags())
        return tags

    def filter_by_tag(self, tag: str):
        return {k: v for k, v in self.objects.items() if v.labels.get(tag)}

    def label(self, id: str, tag: str):
        obj = self.objects.get(id)
        return obj.labels.get(tag) if obj else None

    def image_path(self):
        return os.path.join(self.base_path, self.images_dir) if self.base_path else self.images_dir

    def label_path(self, tag):
        path = os.path.join(self.labels_dir, tag) if tag else self.labels_dir
        return os.path.join(self.base_path, path) if self.base_path else path

    def labels_path(self):
        path = self.labels_dir
        return {tag: os.path.join(path, tag) if self.base_path else path for tag in self.tags()}


class LocalDatastore(Datastore):
    """
    Class to represent a datastore local to the MONAI-Label Server

    Attributes
    ----------
    `name: str`
        The name of the datastore

    `description: str`
        The description of the datastore
    """

    def __init__(
        self,
        datastore_path: str,
        images_dir: str = ".",
        labels_dir: str = "labels",
        datastore_config: str = "datastore_v2.json",
        extensions=("*.nii.gz", "*.nii"),
        auto_reload=False,
        read_only=False,
    ):
        """
        Creates a `LocalDataset` object

        Parameters:

        `datastore_path: str`
            a string to the directory tree of the desired dataset

        `datastore_config: str`
            optional file name of the dataset configuration file (by default `dataset.json`)
        """
        self._datastore_path = datastore_path
        self._datastore_config_path = os.path.join(datastore_path, datastore_config)
        self._extensions = [extensions] if isinstance(extensions, str) else extensions
        self._ignore_event_count = 0
        self._ignore_event_config = False
        self._config_ts = 0
        self._auto_reload = auto_reload

        logging.getLogger("filelock").setLevel(logging.ERROR)

        logger.info(f"Auto Reload: {auto_reload}; Extensions: {self._extensions}")

        os.makedirs(self._datastore_path, exist_ok=True)

        self._lock_file = os.path.join(datastore_path, ".lock")
        self._datastore: LocalDatastoreModel = LocalDatastoreModel(
            name="new-dataset", description="New Dataset", images_dir=images_dir, labels_dir=labels_dir
        )
        self._datastore.base_path = self._datastore_path
        self._init_from_datastore_file(throw_exception=True)

        os.makedirs(self._datastore.image_path(), exist_ok=True)
        os.makedirs(self._datastore.label_path(None), exist_ok=True)
        os.makedirs(self._datastore.label_path(DefaultLabelTag.FINAL), exist_ok=True)
        os.makedirs(self._datastore.label_path(DefaultLabelTag.ORIGINAL), exist_ok=True)

        # reconcile the loaded datastore file with any existing files in the path
        if not read_only:
            self._reconcile_datastore()

        if auto_reload:
            logger.info("Start observing external modifications on datastore (AUTO RELOAD)")
            # Image Dir
            include_patterns = [f"{self._datastore.image_path()}{os.path.sep}{ext}" for ext in [*extensions]]

            # Label Dir(s)
            label_dirs = self._datastore.labels_path()
            label_dirs[DefaultLabelTag.FINAL] = self._datastore.label_path(DefaultLabelTag.FINAL)
            label_dirs[DefaultLabelTag.ORIGINAL] = self._datastore.label_path(DefaultLabelTag.ORIGINAL)
            for label_dir in label_dirs.values():
                include_patterns.extend(f"{label_dir}{os.path.sep}{ext}" for ext in [*extensions])

            # Config
            include_patterns.append(self._datastore_config_path)

            self._handler = PatternMatchingEventHandler(patterns=include_patterns)
            self._handler.on_created = self._on_any_event
            self._handler.on_deleted = self._on_any_event
            self._handler.on_modified = self._on_modify_event

            try:
                self._ignore_event_count = 0
                self._ignore_event_config = False
                self._observer = PollingObserver() if self._is_on_mount(self._datastore.image_path()) else Observer()
                self._observer.schedule(self._handler, recursive=True, path=self._datastore_path)
                self._observer.start()
            except OSError as e:
                logger.error(
                    "Failed to start File watcher. "
                    "Local datastore will not update if images and labels are moved from datastore location."
                )
                logger.error(str(e))

    def name(self) -> str:
        """
        Dataset name (if one is assigned)

        Returns:
            name (str): Dataset name as string
        """
        return self._datastore.name

    def set_name(self, name: str):
        """
        Sets the dataset name in a standardized format (lowercase, no spaces).

            Parameters:
                name (str): Desired dataset name
        """
        self._datastore.name = name
        self._update_datastore_file()

    def description(self) -> str:
        """
        Gets the description field for the dataset

        :return description: str
        """
        return self._datastore.description

    def set_description(self, description: str):
        """
        Set a description for the dataset

        :param description: str
        """
        self._datastore.description = description
        self._update_datastore_file()

    def _to_id(self, file: str) -> Tuple[str, str]:
        ext = file_ext(file)
        extensions = [e.replace("*", "") for e in self._extensions]
        for e in extensions:
            if file.endswith(e):
                ext = e
        id = file.replace(ext, "")
        return id, ext

    def _filename(self, id: str, ext: str) -> str:
        return id + ext

    def _to_bytes(self, file):
        return io.BytesIO(pathlib.Path(file).read_bytes())

    def datalist(self, full_path=True) -> List[Dict[str, Any]]:
        """
        Return a dictionary of image and label pairs corresponding to the 'image' and 'label'
        keys respectively

        :return: the {'label': image, 'label': label} pairs for training
        """

        tag = DefaultLabelTag.FINAL
        image_path = self._datastore.image_path()
        label_path = self._datastore.label_path(tag)

        ds = []
        for k, v in self._datastore.filter_by_tag(tag).items():
            ds.append(
                {
                    "image": os.path.realpath(os.path.join(image_path, self._filename(k, v.image.ext))),
                    "label": os.path.realpath(os.path.join(label_path, self._filename(k, v.labels[tag].ext))),
                }
            )

        if not full_path:
            ds = json.loads(json.dumps(ds).replace(f"{self._datastore_path.rstrip(os.pathsep)}{os.pathsep}", ""))
        return ds

    def get_image(self, image_id: str, params=None) -> Any:
        """
        Retrieve image object based on image id

        :param image_id: the desired image's id
        :param params: any optional params
        :return: return the "image"
        """
        uri = self.get_image_uri(image_id)
        return self._to_bytes(uri) if uri else None

    def get_image_uri(self, image_id: str) -> str:
        """
        Retrieve image uri based on image id

        :param image_id: the desired image's id
        :return: return the image uri
        """
        obj = self._datastore.objects.get(image_id)
        name = self._filename(image_id, obj.image.ext) if obj else ""
        return str(os.path.realpath(os.path.join(self._datastore.image_path(), name))) if obj else ""

    def get_image_info(self, image_id: str) -> Dict[str, Any]:
        """
        Get the image information for the given image id

        :param image_id: the desired image id
        :return: image info as a list of dictionaries Dict[str, Any]
        """
        obj = self._datastore.objects.get(image_id)
        info = copy.deepcopy(obj.image.info) if obj else {}
        if obj:
            name = self._filename(image_id, obj.image.ext)
            path = os.path.realpath(os.path.join(self._datastore.image_path(), name))
            info["path"] = path
        return info

    def get_label(self, label_id: str, label_tag: str, params=None) -> Any:
        """
        Retrieve image object based on label id

        :param label_id: the desired label's id
        :param label_tag: the matching label's tag
        :param params: any optional params
        :return: return the "label"
        """
        uri = self.get_label_uri(label_id, label_tag)
        return self._to_bytes(uri) if uri else None

    def get_label_uri(self, label_id: str, label_tag: str) -> str:
        """
        Retrieve label uri based on image id

        :param label_id: the desired label's id
        :param label_tag: the matching label's tag
        :return: return the label uri
        """
        label = self._datastore.label(label_id, label_tag)
        name = self._filename(label_id, label.ext) if label else ""
        return str(os.path.realpath(os.path.join(self._datastore.label_path(label_tag), name))) if label else ""

    def get_labels_by_image_id(self, image_id: str) -> Dict[str, str]:
        """
        Retrieve all label ids for the given image id

        :param image_id: the desired image's id
        :return: label ids mapped to the appropriate `LabelTag` as Dict[LabelTag, str]
        """
        obj = self._datastore.objects.get(image_id)
        return {tag: image_id for tag in obj.labels} if obj else {}

    def get_label_by_image_id(self, image_id: str, tag: str) -> str:
        """
        Retrieve label id for the given image id and tag

        :param image_id: the desired image's id
        :param tag: matching tag name
        :return: label id
        """
        return self.get_labels_by_image_id(image_id).get(tag, "")

    def get_label_info(self, label_id: str, label_tag: str) -> Dict[str, Any]:
        """
        Get the label information for the given label id

        :param label_id: the desired label id
        :param label_tag: the matching label tag
        :return: label info as a list of dictionaries Dict[str, Any]
        """
        label = self._datastore.label(label_id, label_tag)
        info: Dict[str, Any] = label.info if label else {}
        return info

    def get_labeled_images(self, label_tag: Optional[str] = None, labels: Optional[List[str]] = None) -> List[str]:
        """
        Get all images that have a corresponding label

        :return: list of image ids List[str]
        """
        return [k for k, v in self._datastore.objects.items() if v.labels.get(DefaultLabelTag.FINAL)]

    def get_unlabeled_images(self, label_tag: Optional[str] = None, labels: Optional[List[str]] = None) -> List[str]:
        """
        Get all images that have no corresponding label

        :return: list of image ids List[str]
        """
        return [k for k, v in self._datastore.objects.items() if not v.labels.get(DefaultLabelTag.FINAL)]

    def list_images(self) -> List[str]:
        """
        Return list of image ids available in the datastore

        :return: list of image ids List[str]
        """
        return list(self._datastore.objects.keys())

    def get_dataset_archive(self, limit_cases: Optional[int]) -> str:
        """
        Retrieve ZIP archive of the full dataset containing images,
        labels and metadata

        :param limit_cases: limit the included cases to this number
        :return: path to ZIP archive of the full dataset
        """
        dl = self.datalist()

        assert len(dl) > 0, "ZIP archive was not created, nothing to include"

        if limit_cases and limit_cases in list(range(1, len(dl))):
            logger.info(f"Number of cases in datalist reduced to: {limit_cases} of {len(dl)} case(s)")
            dl = dl[:limit_cases]

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            with zipfile.ZipFile(temp_file, mode="x") as archive:
                logger.info(f"ZIP archive will be written to: {archive.filename}")
                for d in dl:
                    # write image and corresponding label file to archive
                    for key in d.keys():
                        path = d[key]
                        archive.write(path, arcname=os.path.join(key, os.path.basename(path)))
                # add metadata
                datastore_metadata: str = self._datastore.model_dump_json(exclude={"base_path"})
                archive.writestr("metadata.json", datastore_metadata)

            assert archive.filename is not None, "ZIP archive could not be created"

            return archive.filename

    def _on_any_event(self, event):
        if self._ignore_event_count:
            logger.debug(f"Ignoring event by count: {self._ignore_event_count} => {event}")
            self._ignore_event_count = max(self._ignore_event_count - 1, 0)
            return

        logger.debug(f"Event: {event}")
        self.refresh()

    def _on_modify_event(self, event):
        # handle modify events only for config path; rest ignored
        if event.src_path != self._datastore_config_path:
            return

        if self._ignore_event_config:
            self._ignore_event_config = False
            return

        self._init_from_datastore_file()

    def refresh(self):
        """
        Refresh the datastore based on the state of the files on disk
        """
        self._reconcile_datastore()

    def add_image(self, image_id: str, image_filename: str, image_info: Dict[str, Any]) -> str:
        id, image_ext = self._to_id(os.path.basename(image_filename))
        if not image_id:
            image_id = id

        logger.info(f"Adding Image: {image_id} => {image_filename}")
        name = self._filename(image_id, image_ext)
        dest = os.path.realpath(os.path.join(self._datastore.image_path(), name))

        with FileLock(self._lock_file):
            logger.debug("Acquired the lock!")
            shutil.copy(image_filename, dest)

            image_info = image_info if image_info else {}
            image_info["ts"] = int(time.time())
            # image_info["checksum"] = file_checksum(dest)
            image_info["name"] = name

            self._datastore.objects[image_id] = ImageLabelModel(image=DataModel(info=image_info, ext=image_ext))
            self._update_datastore_file(lock=False)
        logger.debug("Released the lock!")
        return image_id

    def remove_image(self, image_id: str) -> None:
        logger.info(f"Removing Image: {image_id}")

        obj = self._datastore.objects.get(image_id)
        if not obj:
            raise ImageNotFoundException(f"Image {image_id} not found")

        # Remove all labels
        tags = list(obj.labels.keys())
        for tag in tags:
            self.remove_label(image_id, tag)

        # Remove Image
        name = self._filename(image_id, obj.image.ext)
        remove_file(os.path.realpath(os.path.join(self._datastore.image_path(), name)))

        if not self._auto_reload:
            self.refresh()

    def save_label(self, image_id: str, label_filename: str, label_tag: str, label_info: Dict[str, Any]) -> str:
        """
        Save a label for the given image id and return the newly saved label's id

        :param image_id: the image id for the label
        :param label_filename: the path to the label file
        :param label_tag: the tag for the label
        :param label_info: additional info for the label
        :return: the label id for the given label filename
        """
        logger.info(f"Saving Label for Image: {image_id}; Tag: {label_tag}; Info: {label_info}")
        obj = self._datastore.objects.get(image_id)
        if not obj:
            raise ImageNotFoundException(f"Image {image_id} not found")

        _, label_ext = self._to_id(os.path.basename(label_filename))
        label_id = image_id

        logger.info(f"Adding Label: {image_id} => {label_tag} => {label_filename}")
        label_path = self._datastore.label_path(label_tag)
        name = self._filename(image_id, label_ext)
        dest = os.path.join(label_path, name)

        with FileLock(self._lock_file):
            logger.debug("Acquired the lock!")
            os.makedirs(label_path, exist_ok=True)
            shutil.copy(label_filename, dest)

            label_info = label_info if label_info else {}
            label_info["ts"] = int(time.time())
            # label_info["checksum"] = file_checksum(dest)
            label_info["name"] = name

            obj.labels[label_tag] = DataModel(info=label_info, ext=label_ext)
            logger.info(f"Label Info: {label_info}")
            self._update_datastore_file(lock=False)
        logger.debug("Release the lock!")
        return label_id

    def remove_label(self, label_id: str, label_tag: str) -> None:
        logger.info(f"Removing label: {label_id} => {label_tag}")
        remove_file(self.get_label_uri(label_id, label_tag))

        if not self._auto_reload:
            self.refresh()

    def update_image_info(self, image_id: str, info: Dict[str, Any]) -> None:
        """
        Update (or create a new) info tag for the desired image

        :param image_id: the id of the image we want to add/update info
        :param info: a dictionary of custom image information Dict[str, Any]
        """
        obj = self._datastore.objects.get(image_id)
        if not obj:
            raise ImageNotFoundException(f"Image {image_id} not found")

        obj.image.info.update(info)
        self._update_datastore_file()

    def update_label_info(self, label_id: str, label_tag: str, info: Dict[str, Any]) -> None:
        """
        Update (or create a new) info tag for the desired label

        :param label_id: the id of the label we want to add/update info
        :param label_tag: the matching label tag
        :param info: a dictionary of custom label information Dict[str, Any]
        """
        label = self._datastore.label(label_id, label_tag)
        if not label:
            raise LabelNotFoundException(f"Label: {label_id} Tag: {label_tag} not found")

        label.info.update(info)
        self._update_datastore_file()

    def _list_files(self, path, patterns):
        files = os.listdir(path)

        filtered = dict()
        for pattern in patterns:
            matching = fnmatch.filter(files, pattern)
            for file in matching:
                filtered[os.path.basename(file)] = file
        return filtered

    def _reconcile_datastore(self):
        logger.debug("reconcile datastore...")
        invalidate = 0
        invalidate += self._remove_non_existing()
        invalidate += self._add_non_existing_images()

        labels_dir = self._datastore.label_path(None)
        logger.debug(f"Labels Dir {labels_dir}")

        tags = [f for f in os.listdir(labels_dir) if os.path.isdir(os.path.join(labels_dir, f))]
        logger.debug(f"Label Tags: {tags}")
        for tag in tags:
            invalidate += self._add_non_existing_labels(tag)

        invalidate += self._remove_non_existing()

        logger.info(f"Invalidate count: {invalidate}")
        if invalidate:
            logger.debug("Save datastore file to disk")
            self._update_datastore_file()
        else:
            logger.debug("No changes needed to flush to disk")

    def _add_non_existing_images(self) -> int:
        invalidate = 0
        self._init_from_datastore_file()

        local_images = self._list_files(self._datastore.image_path(), self._extensions)

        image_ids = list(self._datastore.objects.keys())
        for image_file in local_images:
            image_id, image_ext = self._to_id(image_file)
            if image_id not in image_ids:
                logger.info(f"Adding New Image: {image_id} => {image_file}")

                name = self._filename(image_id, image_ext)
                image_info = {
                    "ts": int(time.time()),
                    # "checksum": file_checksum(os.path.join(self._datastore.image_path(), name)),
                    "name": name,
                }

                invalidate += 1
                self._datastore.objects[image_id] = ImageLabelModel(image=DataModel(info=image_info, ext=image_ext))

        return invalidate

    def _add_non_existing_labels(self, tag) -> int:
        invalidate = 0
        self._init_from_datastore_file()

        local_labels = self._list_files(self._datastore.label_path(tag), self._extensions)

        image_ids = list(self._datastore.objects.keys())
        for label_file in local_labels:
            label_id, label_ext = self._to_id(label_file)

            obj = self._datastore.objects.get(label_id)
            if not obj or label_id not in image_ids:
                logger.warning(f"IGNORE:: No matching image exists for '{label_id}' to add [{label_file}]")
                continue

            if not obj.labels.get(tag):
                logger.info(f"Adding New Label: {tag} => {label_id} => {label_file}")

                name = self._filename(label_id, label_ext)
                label_info = {
                    "ts": int(time.time()),
                    # "checksum": file_checksum(os.path.join(self._datastore.label_path(tag), name)),
                    "name": name,
                }

                self._datastore.objects[label_id].labels[tag] = DataModel(info=label_info, ext=label_ext)
                invalidate += 1

        return invalidate

    def _remove_non_existing(self) -> int:
        invalidate = 0
        self._init_from_datastore_file()

        objects: Dict[str, ImageLabelModel] = {}
        for image_id, obj in self._datastore.objects.items():
            name = self._filename(image_id, obj.image.ext)
            if not os.path.exists(os.path.realpath(os.path.join(self._datastore.image_path(), name))):
                logger.info(f"Removing non existing Image Id: {image_id}")
                invalidate += 1
            else:
                labels: Dict[str, DataModel] = {}
                for tag, label in obj.labels.items():
                    name = self._filename(image_id, label.ext)
                    if not os.path.exists(os.path.realpath(os.path.join(self._datastore.label_path(tag), name))):
                        logger.info(f"Removing non existing Label Id: '{image_id}' for '{tag}'")
                        invalidate += 1
                    else:
                        labels[tag] = label
                obj.labels.clear()
                obj.labels.update(labels)
                objects[image_id] = obj

        self._datastore.objects.clear()
        self._datastore.objects.update(objects)
        return invalidate

    def _init_from_datastore_file(self, throw_exception=False):
        try:
            with FileLock(self._lock_file):
                logger.debug("Acquired the lock!")
                if os.path.exists(self._datastore_config_path):
                    ts = os.stat(self._datastore_config_path).st_mtime
                    if self._config_ts != ts:
                        logger.debug(f"Reload Datastore; old ts: {self._config_ts}; new ts: {ts}")
                        with open(self._datastore_config_path) as fp:
                            self._datastore = LocalDatastoreModel.model_validate_json(fp.read())
                        self._datastore.base_path = self._datastore_path
                        self._config_ts = ts
            logger.debug("Release the Lock...")
        except ValueError as e:
            logger.error(f"+++ Failed to load datastore => {e}")
            if throw_exception:
                raise e

    def _update_datastore_file(self, lock=True):
        def _write_to_file():
            logger.debug("+++ Datastore is updated...")
            self._ignore_event_config = True
            with open(self._datastore_config_path, "w") as f:
                f.write(json.dumps(self._datastore.model_dump(exclude={"base_path"}), indent=2, default=str))
            self._config_ts = os.stat(self._datastore_config_path).st_mtime

        if lock:
            with FileLock(self._lock_file):
                logger.debug("Acquired the Lock...")
                _write_to_file()
            logger.debug("Released the Lock...")
        else:
            _write_to_file()

    def _is_on_mount(self, path):
        while True:
            if path == os.path.dirname(path):
                return False
            elif os.path.ismount(path):
                return True
            path = os.path.dirname(path)

    def status(self) -> Dict[str, Any]:
        tags: dict = {}
        for obj in self._datastore.objects.values():
            for tag, _ in obj.labels.items():
                tags[tag] = tags.get(tag, 0) + 1

        return {
            "total": len(self.list_images()),
            "completed": len(self.get_labeled_images()),
            "label_tags": tags,
        }

    def json(self):
        return self._datastore.model_dump(exclude={"base_path"})
