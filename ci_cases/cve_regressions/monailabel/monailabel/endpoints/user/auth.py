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
import logging
from typing import List, Sequence, Union

import jwt
import requests
from cachetools import cached
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

from monailabel.config import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


class Token(BaseModel):
    access_token: str
    token_type: str


@cached(cache={})
def get_public_key(realm_uri) -> str:
    logger.info(f"Fetching public key for: {realm_uri}")
    r = requests.get(url=realm_uri, timeout=settings.MONAI_LABEL_AUTH_TIMEOUT)
    r.raise_for_status()
    j = r.json()

    key = j["public_key"]
    return f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"


@cached(cache={})
def open_id_configuration(realm_uri):
    response = requests.get(
        url=f"{realm_uri}/.well-known/openid-configuration",
        timeout=settings.MONAI_LABEL_AUTH_TIMEOUT,
    )
    return response.json()


def token_uri():
    return open_id_configuration(settings.MONAI_LABEL_AUTH_REALM_URI).get("token_endpoint")


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    name: Union[str, None] = None
    roles: List[str] = []


DEFAULT_USER = User(
    username="admin",
    email="admin@monailabel.com",
    name="UNK",
    roles=[
        settings.MONAI_LABEL_AUTH_ROLE_ADMIN,
        settings.MONAI_LABEL_AUTH_ROLE_REVIEWER,
        settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR,
        settings.MONAI_LABEL_AUTH_ROLE_USER,
    ],
)


def from_token(token: str):
    if not settings.MONAI_LABEL_AUTH_ENABLE:
        return DEFAULT_USER

    options = {
        "verify_signature": True,
        "verify_aud": False,
        "verify_exp": True,
    }

    key = get_public_key(settings.MONAI_LABEL_AUTH_REALM_URI)
    payload = jwt.decode(token, key, options=options)

    username: str = payload.get(settings.MONAI_LABEL_AUTH_TOKEN_USERNAME)
    email: str = payload.get(settings.MONAI_LABEL_AUTH_TOKEN_EMAIL)
    name: str = payload.get(settings.MONAI_LABEL_AUTH_TOKEN_NAME)

    kr = settings.MONAI_LABEL_AUTH_TOKEN_ROLES.split("#")
    if len(kr) > 1:
        p = payload
        for r in kr:
            roles = p.get(r)
            p = roles
    else:
        roles = payload.get(kr[0])
    roles = [] if not roles else roles

    return User(username=username, email=email, name=name, roles=roles)


async def get_current_user(token: str = Depends(oauth2_scheme) if settings.MONAI_LABEL_AUTH_ENABLE else ""):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        return from_token(token)
    except InvalidTokenError as e:
        logger.error(e)
        raise credentials_exception


class RBAC:
    def __init__(self, roles: Union[str, Sequence[str]]):
        self.roles = roles

    async def __call__(self, user: User = Security(get_current_user)):
        if not settings.MONAI_LABEL_AUTH_ENABLE:
            return user

        roles = self.roles
        if isinstance(roles, str):
            roles = (
                [roles]
                if roles != "*"
                else [
                    settings.MONAI_LABEL_AUTH_ROLE_ADMIN,
                    settings.MONAI_LABEL_AUTH_ROLE_REVIEWER,
                    settings.MONAI_LABEL_AUTH_ROLE_ANNOTATOR,
                    settings.MONAI_LABEL_AUTH_ROLE_USER,
                ]
            )

        for role in roles:
            if role in user.roles:
                return user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f'Role "{role}" is required to perform this action',
        )
