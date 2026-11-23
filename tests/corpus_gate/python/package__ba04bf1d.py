from typing import Literal

from core.schemas import observable


class Package(observable.Observable):
    type: Literal["package"] = "package"
    version: str = None
    regitry_type: str = None
