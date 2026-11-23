from typing import ClassVar, Literal

from core.schemas import entity


class AttackPattern(entity.Entity):
    _type_filter: ClassVar[str] = "attack-pattern"
    type: Literal["attack-pattern"] = "attack-pattern"
    aliases: list[str] = []
    kill_chain_phases: list[str] = []
