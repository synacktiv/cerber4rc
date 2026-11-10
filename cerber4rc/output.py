from __future__ import annotations

import dataclasses
import threading
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .hashes import Credential, CredentialStatus


class Output:
    def __init__(self, hash_prefix: str, verbose: bool = False) -> None:
        self.console = Console()
        self.hash_prefix = hash_prefix
        self.verbose = verbose
        self._lock = threading.Lock()
        self._credentials: dict[str, Credential] = {}
        self._pending: dict[str, list[str]] = {}

    def event(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{ts}[/dim] {message}")

    def debug(self, message: str) -> None:
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            self.console.print(f"[dim]{ts} debug {message}[/dim]")

    def credential(self, cred: Credential) -> bool:
        with self._lock:
            if cred.cipher_hex in self._credentials:
                return False
            self._credentials[cred.cipher_hex] = cred
            principal = f"{cred.username}@{cred.realm}"
            self._pending.setdefault(principal, []).append(cred.cipher_hex)
        return True

    def _panel(
        self, cred: Credential, principal: str, title_suffix: str, border_style: str
    ) -> None:
        self.console.print(
            Panel(
                f"[bold]john[/bold]    {cred.john}\n"
                f"[bold]hashcat[/bold] {cred.hashcat}",
                title=f"{principal} (etype {cred.etype}) -- {title_suffix}",
                border_style=border_style,
            )
        )

    def resolve(self, principal: str, valid: bool) -> None:
        status = CredentialStatus.VALID if valid else CredentialStatus.INVALID
        title_suffix = "Verified" if valid else "Wrong password"
        border_style = "green" if valid else "yellow"
        with self._lock:
            for cipher_hex in self._pending.pop(principal, []):
                cred = dataclasses.replace(self._credentials[cipher_hex], status=status)
                self._credentials[cipher_hex] = cred
                self._panel(cred, principal, title_suffix, border_style)
                self._write(cred)

    def flush_pending(self) -> None:
        with self._lock:
            for principal, cipher_hexes in self._pending.items():
                for cipher_hex in cipher_hexes:
                    cred = self._credentials[cipher_hex]
                    self._panel(cred, principal, "Unverified -- no KDC verdict", "dim")
                    self._write(cred)
            self._pending.clear()

    def _write(self, cred: Credential) -> None:
        suffix = ".invalid" if cred.status is CredentialStatus.INVALID else ""
        with open(f"{self.hash_prefix}_john{suffix}", "a", encoding="utf-8") as f:
            f.write(cred.john + "\n")
        with open(f"{self.hash_prefix}_hashcat{suffix}", "a", encoding="utf-8") as f:
            f.write(cred.hashcat + "\n")

    def summary(self) -> None:
        with self._lock:
            credentials = list(self._credentials.values())
        if not credentials:
            self.event("[yellow]no credentials captured[/yellow]")
            return
        table = Table(title="Captured credentials")
        table.add_column("Principal")
        table.add_column("Etype")
        table.add_column("Hashcat")
        table.add_column("Status")
        for cred in credentials:
            table.add_row(
                f"{cred.username}@{cred.realm}",
                str(cred.etype),
                cred.hashcat,
                cred.status.name,
            )
        self.console.print(table)
