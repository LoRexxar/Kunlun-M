import datetime
import logging
import re

import requests

from core import taskmanager
from core.schemas import observable, task
from core.schemas.observable import Observable, ObservableType


class DockerHubApi:
    """Base class for querying the DockerHub API."""

    @staticmethod
    def _make_request(endpoint) -> dict:
        response = requests.get(endpoint, allow_redirects=True)
        if response:
            return response.json()
        return {}

    @staticmethod
    def _iter_endpoint_pages(endpoint) -> dict:
        data = DockerHubApi._make_request(endpoint)
        while data:
            for result in data.get("results", []):
                yield result
            next = data.get("next")
            if next:
                data = DockerHubApi._make_request(next)
            else:
                data = {}

    @staticmethod
    def inspect_image(image, tag=None) -> dict:
        endpoint = f"https://hub.docker.com/v2/repositories/{image}"
        if tag:
            endpoint += f"/tags/{tag}/images"
        return DockerHubApi._make_request(endpoint)

    @staticmethod
    def inspect_user(user) -> dict:
        endpoint = f"https://hub.docker.com/v2/orgs/{user}"
        # if orgs does not exist, redirects to
        # https://hub.docker.com/v2/users/
        return DockerHubApi._make_request(endpoint)

    @staticmethod
    def user_images(user, page_size=50) -> iter:
        endpoint = f"https://hub.docker.com/v2/repositories/{user}?page_size={page_size}&ordering=last_updated"
        yield from DockerHubApi._iter_endpoint_pages(endpoint)

    @staticmethod
    def image_tags(image, page_size=100) -> iter:
        endpoint = f"https://hub.docker.com/v2/repositories/{image}/tags/?page_size={page_size}&page=1&name&ordering"
        yield from DockerHubApi._iter_endpoint_pages(endpoint)

    @staticmethod
    def image_full_details(image):
        if "/" not in image:
            return {}
        if ":" in image:
            image, tag = image.split(":")
        else:
            tag = ""
        image_metadata = DockerHubApi.inspect_image(image)
        if not image_metadata:
            return {}
        image_metadata["user"] = DockerHubApi.inspect_user(image_metadata["user"])
        image_metadata["tags"] = dict()
        if tag:
            image_metadata["tags"][tag] = DockerHubApi.inspect_image(image, tag)
        else:
            for tag in DockerHubApi.image_tags(image):
                tag_name = tag["name"]
                image_metadata["tags"][tag_name] = DockerHubApi.inspect_image(
                    image, tag_name
                )
        return image_metadata


FILE_REGEX: re.Pattern = re.compile(r"^\w+ file:([0-9a-f]{64}) .*", re.IGNORECASE)
DIGEST_REGEX: re.Pattern = re.compile(r"sha256:([0-9a-f]{64})$", re.IGNORECASE)


def get_image_context(metadata):
    context = {"source": "hub.docker.com"}
    if metadata:
        context["Analysis"] = "Image found"
        context["Image stats"] = {
            "Pulls": metadata.get("pull_count", "N/A"),
            "Last updated": metadata.get("last_updated", "N/A"),
            "Registered": metadata.get("date_registered", "N/A"),
            "Stars": metadata.get("star_count", "N/A"),
        }
        context["Image details"] = metadata.get("tags", "N/A")
        context["User details"] = metadata.get("user", "Unknown")
    else:
        context["Analysis"] = "Image not found"
    return context


def create_digest_context(image_obs, tag_name, image_tag):
    if not image_tag:
        return {}
    fullname = f"{image_obs.value}:{tag_name}"
    arch = image_tag.get("arch", "N/A")
    os = image_tag.get("os", "N/A")
    pushed = image_tag.get("last_pushed", "N/A")
    context = {"image name": fullname, "arch": f"{os}/{arch}", "pushed": pushed}
    return context


def create_digest_observable(image_obs, digest, context, link_type):
    logging.info(f"Add {image_obs.value}'s digest: {digest}")
    sha_obs = observable.save(value=digest, type="sha256", tags=["dockerhub"])
    if context:
        sha_obs.add_context("hub.docker.com", context)
    image_obs.link_to(sha_obs, link_type, "")
    return sha_obs


def make_relationships(image_obs, metadata):
    username = metadata.get("user", {}).get("username", "")
    if username:
        logging.info(f"Add dockerhub user_account: {username}")
        user_obs = observable.save(
            value=username,
            type="user_account",
            tags=["dockerhub"],
            account_type="dockerhub",
        )
        user_obs.link_to(image_obs, "owns", "")
    for tag_name, image_tags in metadata.get("tags", {}).items():
        for image_tag in image_tags:
            context = create_digest_context(image_obs, tag_name, image_tag)
            digest = DIGEST_REGEX.match(image_tag.get("digest", ""))
            if digest:
                create_digest_observable(
                    image_obs, digest.group(1), context, "generates"
                )
            for layer in image_tag.get("layers", []):
                layer_digest = DIGEST_REGEX.match(layer.get("digest", ""))
                if layer_digest:
                    create_digest_observable(
                        image_obs, layer_digest.group(1), context, "embeds"
                    )
                file_digest = FILE_REGEX.match(layer.get("instruction", ""))
                if file_digest:
                    create_digest_observable(
                        image_obs, file_digest.group(1), context, "adds"
                    )


class DockerHubImageAnalytics(task.OneShotTask):
    """DockerHubImageAnalytics queries docker hub to get more details related to
    docker_image observable.

    This analytics adds several information as context to docker_image:
    * Image stats: provide details about pulls, registered, updated
    * Image details: provide information related to image tags including
      layers information and instructions
    * User details: provides details about the user owning the image.

    This analytics also creates new observables:
    * user_account observable with account_type being dockerhub to link to a docker hub user
    * sha256 including image's digest, layers' digests and added files' digests
    """

    _defaults = {
        "name": "DockerHubImageAnalytics",
        "description": "Fetch metadata from docker hub for a docker image",
    }

    acts_on: list[ObservableType] = [
        ObservableType.container_image,
        ObservableType.docker_image,
    ]

    def each(self, observable_obj: Observable):
        if not (
            observable_obj.type == "docker_image"
            or (
                observable_obj.type == "container_image"
                and observable_obj.registry == "docker.io"
            )
        ):
            self.logger.info(
                f"Skipping {observable_obj.type} {observable_obj.value} not from docker.io"
            )
            return []
        metadata = DockerHubApi.image_full_details(observable_obj.value)

        if metadata is None:
            self.logger.info(f"Image metadata for {observable_obj.value} not found")
            return []

        context = get_image_context(metadata)
        observable_obj.add_context("hub.docker.com", context)
        make_relationships(observable_obj, metadata)


class DockerHubUserAnalytics(task.OneShotTask):
    """DockerHubUserAnalytics queries docker hub to get more details related to
    user_account observable of dockerhub type and fetch all their images.

    This analytics creates a new user_account observable with account type set to dockerhub.
    It also creates new container_image observables for each image owned by the user.
    """

    _defaults = {
        "name": "DockerHubUserAnalytics",
        "description": "Fetch metadata from docker hub for a dockerhub user account",
    }

    acts_on: list[ObservableType] = [ObservableType.user_account]

    def each(self, user_obj: Observable):
        if (
            not isinstance(user_obj, observable.UserAccount)
            or user_obj.account_type != "dockerhub"
        ):
            return []
        metadata = DockerHubApi.inspect_user(user_obj.value)
        if metadata is None:
            return []
        if date_joined := metadata.get("date_joined"):
            date_joined = datetime.datetime.strptime(
                date_joined, "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            if (
                user_obj.account_created is None
                or user_obj.account_created > date_joined
            ):
                user_obj.created = date_joined
                user_obj = user_obj.save()
        metadata.pop("date_joined", None)
        user_obj.add_context("hub.docker.com", metadata)
        for image in DockerHubApi.user_images(user_obj.value):
            image_name = f"{image['namespace']}/{image['name']}"
            self.logger.info(f"Save new image {image_name}")
            image_obs = observable.save(
                value=image_name, type="container_image", registry="docker.io"
            )
            user_obj.link_to(image_obs, "owns", "")


taskmanager.TaskManager.register_task(DockerHubImageAnalytics)
taskmanager.TaskManager.register_task(DockerHubUserAnalytics)
