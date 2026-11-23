from typing import ClassVar, Literal

from core.schemas import indicator


class Query(indicator.Indicator):
    """Represents a query that can be sent to another system."""

    _type_filter: ClassVar[str] = "query"
    type: Literal["query"] = "query"

    query_type: str
    target_systems: list[str] = []
