from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SSHConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}[$]?$", min_length=1)
    auth: Literal["key", "password"] = "key"
    credential_ref: str | None = None

    @field_validator("credential_ref")
    @classmethod
    def reference_only(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", value):
            raise ValueError("credential_ref must be an external-store reference")
        return value


class Server(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    ssh: SSHConfig
    storage_roots: list[str] = Field(default_factory=list)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
                raise ValueError("invalid host") from None
            if any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in value.split(".")
            ):
                raise ValueError("invalid hostname") from None
            return value.lower()

    @field_validator("storage_roots")
    @classmethod
    def valid_roots(cls, value: list[str]) -> list[str]:
        from pathlib import PurePosixPath

        for path in value:
            p = PurePosixPath(path)
            if not p.is_absolute() or ".." in p.parts or str(p) != path:
                raise ValueError("storage roots must be canonical absolute paths")
        return value


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    servers: dict[str, Server] = Field(default_factory=dict)

    @field_validator("servers")
    @classmethod
    def valid_names(cls, value: dict[str, Server]) -> dict[str, Server]:
        if any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", n) for n in value):
            raise ValueError("invalid server name")
        return value
