import datetime
import json
import secrets
from typing import ClassVar, Literal

from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field, computed_field

from core import database_arango
from core.config.config import yeti_config
from core.helpers import now
from core.schemas import graph, rbac, roles
from core.schemas.model import YetiModel

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

RBAC_DEFAULT_ROLES = {
    "reader": roles.Role.READER,
    "writer": roles.Role.WRITER,
}
SECRET_KEY = yeti_config.get("auth", "secret_key")
if not SECRET_KEY:
    raise RuntimeError("You must set auth.secret_key in the configuration file.")
ALGORITHM = yeti_config.get("auth", "algorithm")


def create_access_token(
    data: dict, expires_delta: datetime.timedelta | None = None
) -> str:
    to_encode = data.copy()
    expire = None
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class RegisteredApiKey(BaseModel):
    name: str
    sub: str
    scopes: list[str]
    created: datetime.datetime = Field(default_factory=now)
    exp: datetime.datetime | None = None
    last_used: datetime.datetime | None = None
    enabled: bool = True

    @computed_field
    @property
    def expired(self) -> bool:
        if self.exp is None:
            return False
        return self.exp > datetime.datetime.now(tz=datetime.timezone.utc)


class User(YetiModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _collection_name: ClassVar[str] = "users"
    _root_type: Literal["user"] = "user"
    _type_filter: ClassVar[None] = None

    username: str
    enabled: bool = True
    admin: bool = False
    api_keys: dict[str, RegisteredApiKey] | None = {}

    global_role: int = RBAC_DEFAULT_ROLES[
        str(yeti_config.get("rbac", "default_global_role", default="writer"))
    ]

    @computed_field(return_type=Literal["user"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "User":
        return cls(**object)

    def create_api_key(
        self,
        key_name: str,
        scopes: list[str] | None = None,
        expiration_delta: datetime.timedelta | None = None,
    ) -> str:
        exp = None
        if expiration_delta:
            exp = datetime.datetime.now(datetime.timezone.utc) + expiration_delta
        api_key = RegisteredApiKey(
            name=key_name,
            sub=self.username,
            scopes=scopes or ["all"],
            exp=exp,
        )
        self.api_keys[key_name] = api_key
        self.save()
        return create_access_token(json.loads(api_key.model_dump_json()))

    def validate_api_key_payload(self, payload) -> RegisteredApiKey:
        sub = payload.get("sub")
        key_name = payload.get("name")
        if key_name not in self.api_keys or sub != self.username:
            raise ValueError("Could not validate credentials")

        key = self.api_keys[key_name]
        if not key.enabled:
            raise ValueError("API key disabled.")
        if key.expired:
            raise ValueError("API key expired.")

        return key

    def delete_api_key(self, api_key_name) -> None:
        api_keys = self.api_keys
        del api_keys[api_key_name]
        self.api_keys = None
        self.save()
        self.api_keys = api_keys
        self.save()

    def has_permissions(self, target: str, permissions: roles.Permission) -> bool:
        return graph.RoleRelationship.has_permissions(self, target, permissions)

    def has_global_role(self, role: roles.Permission) -> bool:
        return self.global_role & role == role

    def get_groups(self) -> list[rbac.Group]:
        """Get the groups this user is a member of."""
        groups, paths, total = self.neighbors(
            graph="acls",
            direction="outbound",
            max_hops=1,
            target_types=["rbacgroup"],
            user=self,
        )
        all_groups = {}
        for path in paths:
            for edge in path:
                assert isinstance(edge, graph.RoleRelationship)
                group = groups[edge.target]
                group._acls[self.username] = edge
                all_groups[group.name] = group
        return list(groups.values())


class UserSensitive(User):
    password: str = ""

    @classmethod
    def load(cls, object: dict) -> "UserSensitive":
        return cls(**object)

    def set_password(self, plain_password: str) -> None:
        self.password = pwd_context.hash(plain_password)

    def verify_password(self, plain_password: str) -> bool:
        return pwd_context.verify(plain_password, self.password)
