import re
from typing import Literal

from pydantic import field_validator

from core.schemas import observable

BIC_MATCHER_REGEX = re.compile("^[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}?")


class BIC(observable.Observable):
    type: Literal["bic"] = "bic"

    @classmethod
    def validator(cls, value: str) -> bool:
        if BIC_MATCHER_REGEX.match(value):
            return True
        else:
            return False
