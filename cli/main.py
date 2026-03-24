"""
Claude Scanner CLI

Usage examples:
    claude-scanner auth login
    claude-scanner device list
    claude-scanner device add --hostname web01 --ip 10.0.1.10 --os linux
    claude-scanner scan start --devices web01,db01 --type full
    claude-scanner scan status <scan-id>
    claude-scanner report findings --severity critical --format csv
    claude-scanner discover --ranges 10.0.0.0/24
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="claude-scanner",
    help="Enterprise vulnerability scanner CLI",
    no_args_is_help=True,
)
auth_app = typer.Typer(help="Authentication commands")
device_app = typer.Typer(help="Device management")
scan_app = typer.Typer(help="Scan management")
report_app = typer.Typer(help="Report generation")

app.add_typer(auth_app, name="auth")
app.add_typer(device_app, name="device")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")

console = Console()

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".claude-scanner"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)


def _get_api_url() -> str:
    cfg = _load_config()
    return cfg.get("api_url") or os.getenv("SCANNER_API_URL") or "http://localhost:8000"


def _get_token() -> str:
    cfg = _load_config()
    token = cfg.get("token") or os.getenv("SCANNER_TOKEN") or ""
    if not token:
        console.print("[red]Not logged in. Run: claude-scanner auth login[/red]")
        raise typer.Exit(1)
    return token


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=_get_api_url(),
        headers={"Authorization": f"Bearer {_get_token()}"},
        timeout=60.0,
    )


def _handle_error(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        console.print(f"[red]Error {resp.status_code}: {detail}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Auth commands
# ---------------------------------------------------------------------------

@auth_app.command("login")
def auth_login(
    api_url: str = typer.Option("http://localhost:8000", "--url", help="API server URL"),
    username: str = typer.Option(..., "--username", "-u", prompt=True),
    password: str = typer.Option(..., "--password", "-p", prompt=True, hide_input=True),
) -> None:
    """Login and store auth token."""
    with httpx.Client(base_url=api_url, timeout=10.0) as client:
        resp = client.post("/auth/token", data={"username": username, "password": password})
        _handle_error(resp)
        token = resp.json()["access_token"]
        cfg = _load_config()
        cfg["api_url"] = api_url
        cfg["token"] = token
        _save_config(cfg)
        console.print(f"[green]Logged in as {username}[/green]")


@auth_app.command("logout")
def auth_logout() -> None:
    """Clear stored credentials."""
    cfg = _load_config()
    cfg.pop("token", None)
    _save_config(cfg)
    console.print("Logged out.")


@auth_app.command("whoami")
def auth_whoami() -> None:
    """Show current user."""
    with _client() as c:
        resp = c.get("/auth/me")
        _handle_error(resp)
        user = resp.json()
        console.print(f"Logged in as: [bold]{user['username']}[/bold] ({user['email']})")
        if user["is_admin"]:
            console.print("[yellow]Admin[/yellow]")


# ---------------------------------------------------------------------------
# Device commands
# ---------------------------------------------------------------------------

@device_app.command("list")
def device_list(
    search: Optional[str] = typer.Option(None, "--search", "-s"),
    os_type: Optional[str] = typer.Option(None, "--os"),
    status: Optional[str] = typer.Option(None, "--status"),
    page_size: int = typer.Option(50, "--limit"),
) -> None:
    """List registered devices."""
    params: dict = {"page_size": page_size}
    if search:
        params["search"] = search
    if os_type:
        params["os_type"] = os_type
    if status:
        params["status"] = status

    with _client() as c:
        resp = c.get("/devices", params=params)
        _handle_error(resp)
        data = resp.json()

    table = Table(title=f"Devices ({data['total']} total)")
    table.add_column("Hostname", style="cyan")
    table.add_column("IP Address")
    table.add_column("OS")
    table.add_column("Version")
    table.add_column("Status")
    table.add_column("Agent")
    table.add_column("Last Scanned")

    for d in data["items"]:
        status_color = {"online": "green", "offline": "red"}.get(d["status"], "yellow")
        table.add_row(
            d["hostname"],
            d["ip_address"],
            d["os_type"],
            d.get("os_version") or "—",
            f"[{status_color}]{d['status']}[/{status_color}]",
            "✓" if d["agent_installed"] else "—",
            d.get("last_scanned_at", "Never")[:10] if d.get("last_scanned_at") else "Never",
        )
    console.print(table)


@device_app.command("add")
def device_add(
    hostname: str = typer.Option(..., "--hostname", "-H"),
    ip: str = typer.Option(..., "--ip", "-i"),
    os_type: str = typer.Option("unknown", "--os"),
    credential_ref: Optional[str] = typer.Option(None, "--cred-ref", help="1Password item ID or vault/item"),
    tags: Optional[str] = typer.Option(None, "--tags", help='JSON tags e.g. \'{"env":"prod"}\''),
    notes: Optional[str] = typer.Option(None, "--notes"),
) -> None:
    """Register a new device."""
    payload: dict = {
        "hostname": hostname,
        "ip_address": ip,
        "os_type": os_type,
    }
    if credential_ref:
        payload["credential_ref"] = credential_ref
    if tags:
        payload["tags"] = json.loads(tags)
    if notes:
        payload["notes"] = notes

    with _client() as c:
        resp = c.post("/devices", json=payload)
        _handle_error(resp)
        d = resp.json()
        console.print(f"[green]Device registered:[/green] {d['hostname']} ({d['id']})")


@device_app.command("import")
def device_import(
    csv_file: Path = typer.Argument(..., help="CSV file with columns: hostname,ip_address,os_type,credential_ref"),
) -> None:
    """Bulk import devices from a CSV file."""
    import csv as csvlib
    rows = []
    with open(csv_file) as f:
        reader = csvlib.DictReader(f)
        for row in reader:
            rows.append({
                "hostname": row.get("hostname", ""),
                "ip_address": row.get("ip_address", ""),
                "os_type": row.get("os_type", "unknown"),
                "credential_ref": row.get("credential_ref") or None,
            })

    with _client() as c:
        resp = c.post("/devices/bulk-import", json=rows)
        _handle_error(resp)
        result = resp.json()
        console.print(f"[green]Created: {result['created']}[/green]  Skipped: {result['skipped']}")


# ---------------------------------------------------------------------------
# Scan commands
# ---------------------------------------------------------------------------

@scan_app.command("start")
def scan_start(
    name: str = typer.Option(..., "--name", "-n", prompt="Scan name"),
    devices: Optional[str] = typer.Option(None, "--devices", "-d", help="Comma-separated hostnames or IDs"),
    scan_type: str = typer.Option("full", "--type", "-t"),
    all_devices: bool = typer.Option(False, "--all", help="Scan all registered devices"),
) -> None:
    """Start a new scan job."""
    with _client() as c:
        if all_devices:
            resp = c.get("/devices", params={"page_size": 10000})
            _handle_error(resp)
            device_ids = [d["id"] for d in resp.json()["items"]]
        elif devices:
            # Resolve hostnames to IDs
            device_ids = []
            for identifier in devices.split(","):
                identifier = identifier.strip()
                resp = c.get("/devices", params={"search": identifier, "page_size": 5})
                _handle_error(resp)
                items = resp.json()["items"]
                if not items:
                    console.print(f"[red]Device not found: {identifier}[/red]")
                    raise typer.Exit(1)
                device_ids.append(items[0]["id"])
        else:
            console.print("[red]Specify --devices or --all[/red]")
            raise typer.Exit(1)

        payload = {"name": name, "scan_type": scan_type, "device_ids": device_ids}
        resp = c.post("/scans", json=payload)
        _handle_error(resp)
        job = resp.json()
        console.print(f"[green]Scan started:[/green] {job['id']}")
        console.print(f"Scanning {len(device_ids)} device(s). Use 'claude-scanner scan status {job['id']}' to check progress.")


@scan_app.command("status")
def scan_status(
    scan_id: str = typer.Argument(...),
) -> None:
    """Show scan job status and progress."""
    with _client() as c:
        resp = c.get(f"/scans/{scan_id}")
        _handle_error(resp)
        job = resp.json()

    status_color = {
        "completed": "green",
        "running": "yellow",
        "failed": "red",
        "cancelled": "dim",
    }.get(job["status"], "white")

    console.print(f"Scan: [bold]{job['name']}[/bold]")
    console.print(f"Status: [{status_color}]{job['status']}[/{status_color}]")
    console.print(f"Progress: {job['completed_devices']}/{job['total_devices']} devices "
                  f"({job['failed_devices']} failed)")

    table = Table(title="Targets")
    table.add_column("Device ID", style="dim")
    table.add_column("Status")
    table.add_column("Error")
    for t in job.get("targets", []):
        sc = {"completed": "green", "running": "yellow", "failed": "red"}.get(t["status"], "white")
        table.add_row(
            t["device_id"][:12] + "...",
            f"[{sc}]{t['status']}[/{sc}]",
            (t.get("error_message") or "")[:50],
        )
    console.print(table)


@scan_app.command("list")
def scan_list(limit: int = typer.Option(20, "--limit")) -> None:
    """List recent scan jobs."""
    with _client() as c:
        resp = c.get("/scans", params={"page_size": limit})
        _handle_error(resp)
        jobs = resp.json()

    table = Table(title="Scan Jobs")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Devices")
    table.add_column("Created")
    for j in jobs:
        sc = {"completed": "green", "running": "yellow", "failed": "red"}.get(j["status"], "white")
        table.add_row(
            j["id"][:12] + "...",
            j["name"],
            j["scan_type"],
            f"[{sc}]{j['status']}[/{sc}]",
            f"{j['completed_devices']}/{j['total_devices']}",
            j["created_at"][:16],
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@app.command("discover")
def discover(
    ranges: str = typer.Option(..., "--ranges", "-r", help="CIDR ranges, comma-separated"),
    name: str = typer.Option("Auto Discovery", "--name"),
) -> None:
    """Discover live hosts in IP ranges and register them."""
    target_ranges = [r.strip() for r in ranges.split(",")]
    payload = {"name": name, "target_ranges": target_ranges}
    with _client() as c:
        resp = c.post("/scans/discovery", json=payload)
        _handle_error(resp)
        job = resp.json()
    console.print(f"[green]Discovery job started:[/green] {job['id']}")
    console.print(f"Scanning {len(target_ranges)} range(s).")


# ---------------------------------------------------------------------------
# Report commands
# ---------------------------------------------------------------------------

@report_app.command("findings")
def report_findings(
    output: Path = typer.Option(Path("findings.csv"), "--output", "-o"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s"),
    device_id: Optional[str] = typer.Option(None, "--device"),
    status: Optional[str] = typer.Option(None, "--status"),
) -> None:
    """Export findings as CSV."""
    params: dict = {}
    if severity:
        params["severity"] = severity
    if device_id:
        params["device_id"] = device_id
    if status:
        params["status"] = status

    with _client() as c:
        resp = c.get("/reports/findings/csv", params=params)
        _handle_error(resp)
        output.write_bytes(resp.content)
    console.print(f"[green]Exported to {output}[/green]")


@report_app.command("pdf")
def report_pdf(
    scan_id: str = typer.Argument(...),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate PDF report for a scan."""
    if not output:
        output = Path(f"scan-report-{scan_id[:8]}.pdf")
    with _client() as c:
        resp = c.get(f"/reports/scans/{scan_id}/pdf")
        _handle_error(resp)
        output.write_bytes(resp.content)
    console.print(f"[green]PDF saved to {output}[/green]")


if __name__ == "__main__":
    app()
