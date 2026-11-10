from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

_ETYPE23_CIPHER_LEN = 52
_ETYPE_AES_CIPHER_LEN = 56


class CredentialStatus(Enum):

    PENDING = auto()
    VALID = auto()
    INVALID = auto()


@dataclass(frozen=True, slots=True)
class Credential:
    username: str
    realm: str
    etype: int
    cipher_hex: str
    john: str
    hashcat: str
    status: CredentialStatus = field(default=CredentialStatus.PENDING)


class UnsupportedEtypeError(ValueError):
    pass


def _rc4(username: str, realm: str, cipher: bytes) -> tuple[str, str]:
    if len(cipher) != _ETYPE23_CIPHER_LEN:
        raise ValueError(
            f"etype23 cipher must be {_ETYPE23_CIPHER_LEN} bytes, got {len(cipher)}"
        )
    checksum, enc_timestamp = cipher[:16], cipher[16:]
    john = f"$mskrb5${username}${realm}${checksum.hex()}${enc_timestamp.hex()}"
    hashcat = f"$krb5pa$23${username}${realm}$${enc_timestamp.hex()}{checksum.hex()}"
    return john, hashcat


def _aes(
    username: str, realm: str, cipher: bytes, etype: int, salt: str | None
) -> tuple[str, str]:
    if len(cipher) != _ETYPE_AES_CIPHER_LEN:
        raise ValueError(
            f"etype{etype} cipher must be {_ETYPE_AES_CIPHER_LEN} bytes, got {len(cipher)}"
        )
    salt = salt or f"{realm}{username}"
    john = f"$krb5pa${etype}${username}${realm}${salt}${cipher.hex()}"
    hashcat = f"$krb5pa${etype}${username}${realm}${cipher.hex()}"
    return john, hashcat


def build_credential(
    username: str,
    realm: str,
    etype: int,
    cipher_hex: str,
    salt: str | None = None,
) -> Credential:
    try:
        cipher = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise ValueError(f"cipher_hex is not valid hex: {exc}") from exc

    if etype == 23:
        john, hashcat = _rc4(username, realm, cipher)
    elif etype in (17, 18):
        john, hashcat = _aes(username, realm, cipher, etype, salt)
    else:
        raise UnsupportedEtypeError(f"no hash format for etype {etype}")

    return Credential(
        username=username,
        realm=realm,
        etype=etype,
        cipher_hex=cipher_hex,
        john=john,
        hashcat=hashcat,
    )
