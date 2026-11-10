from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum, auto


class Phase(Enum):

    PROBE = auto()
    DOWNGRADE = auto()
    CAPTURED = auto()
    PASSTHROUGH = auto()


PrincipalKey = tuple[str, str]


@dataclass
class PrincipalState:
    phase: Phase = Phase.PROBE
    target_etype: int | None = None
    attempts: int = 0
    saved_error: bytes | None = None
    salt: str | None = None
    passthrough_reason: str | None = None
    has_pending_capture: bool = False


@dataclass
class Session:
    client_ip: str
    principal: PrincipalKey | None = None


class Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[PrincipalKey, PrincipalState] = {}

    def get(self, key: PrincipalKey) -> PrincipalState:
        with self._lock:
            state = self._states.get(key)
            if state is None:
                state = PrincipalState()
                self._states[key] = state
            return state
