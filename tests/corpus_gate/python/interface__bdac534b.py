from abc import ABC, abstractmethod


class FileStorageClient(ABC):
    PREFIX: str

    @abstractmethod
    def __init__(self, path: str):
        raise NotImplementedError

    @abstractmethod
    def file_path(self, file_name: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_file(self, file_name: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def put_file(self, file_name: str, contents: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_file(self, file_name: str) -> None:
        raise NotImplementedError
