from typing import ClassVar, Literal

from core.schemas import entity


class Phone(entity.Entity):
    type: Literal["phone"] = "phone"
    _type_filter: ClassVar[str] = "phone"
