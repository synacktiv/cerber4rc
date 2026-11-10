from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Mode(str, Enum):

    ACTIVE = "active"
    PASSIVE = "passive"


@dataclass(frozen=True, slots=True)
class Config:
    listen_host: str
    listen_port: int
    kdc_host: str
    kdc_port: int
    mode: Mode
    hash_prefix: str
    verbose: bool = False
    buffer_size: int = 4096
    socket_timeout: float = 30.0
    max_downgrade_attempts: int = 5
    keep_downgrading: bool = False
    machines: bool = False
    transparent: bool = False
