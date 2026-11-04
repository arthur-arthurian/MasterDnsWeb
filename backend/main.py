from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    load_dotenv = None

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from config import config_router
from resolver_scanner import resolver_scanner_router
from service_controller import service_router
from system_stats import system_stats_router
from user import user_router
from ws import ws_router

def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_runtime_dir() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parent


APP_DIR = get_app_dir()
RUNTIME_DIR = get_runtime_dir()
DOTENV_FILE = APP_DIR / ".env"

if load_dotenv is not None:
    load_dotenv(dotenv_path=DOTENV_FILE, override=False)

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

STATIC_DIR = RUNTIME_DIR / "static"
STATIC_INDEX_FILE = STATIC_DIR / "index.html"



app = FastAPI(
    title="MasterDnsWeb API",
    description="",
    version="1.0.2"
)
_cors_env = os.getenv("CORS_ORIGINS", "")
_cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$" if not _cors_env else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(user_router)
app.include_router(config_router)
app.include_router(resolver_scanner_router)
app.include_router(service_router)
app.include_router(system_stats_router)
app.include_router(ws_router)


def frontend_bundle_exists() -> bool:
    return STATIC_INDEX_FILE.exists()


def resolve_frontend_path(relative_path: str) -> Path:
    requested_path = (STATIC_DIR / relative_path.lstrip("/")).resolve()

    if requested_path != STATIC_DIR.resolve() and STATIC_DIR.resolve() not in requested_path.parents:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    return requested_path


def serve_frontend(relative_path: str = ""):
    if not frontend_bundle_exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Frontend bundle not found")

    requested_path = resolve_frontend_path(relative_path)
    if requested_path.is_file():
        return FileResponse(requested_path)

    return FileResponse(STATIC_INDEX_FILE)


@app.get("/")
def root():
    if frontend_bundle_exists():
        return FileResponse(STATIC_INDEX_FILE)

    return {"status": "running", "message": "FastAPI server is running"}


@app.get("/api/health")
def health():
    return {"status": "running", "message": "FastAPI server is running"}

@app.get("/info")
def info():
    return {
        "name": "MasterDnsWeb API",
        "version": "1.0.2",
        "frontend_bundle": frontend_bundle_exists(),
    }


@app.get("/api/info")
def api_info():
    return info()


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    return serve_frontend(full_path)

def _find_service_template() -> Path | None:
    """Locate the systemd unit template file.

    Priority:
    1. Next to the source file (project root) in development.
    2. Next to the frozen executable (PyInstaller bundle).
    3. Current working directory as a fallback.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "masterdnsweb.service.tmpl",
    ]
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "masterdnsweb.service.tmpl")
    candidates.append(Path.cwd() / "masterdnsweb.service.tmpl")

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _extract_listen_port_from_profile(file_path: Path) -> int | None:
    """Extract LISTEN_PORT from a profile JSON file."""
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        configure = data.get("configure", {})
        port = configure.get("LISTEN_PORT")
        if port is not None:
            return int(port)
    except Exception:
        pass
    return None


def apply_iptables_for_instances() -> None:
    """Apply iptables rules for all instance listen ports.

    For every unique LISTEN_PORT found in data/*.json profiles:

        iptables -A INPUT -p tcp --dport <port> -j DROP
        iptables -A INPUT -p tcp -s 127.0.0.1 --dport <port> -j ACCEPT

    Runs only if iptables binary exists. Duplicate rules are skipped using
    iptables -C (check) before appending so restarting the panel does not
    pile up identical rules.
    """
    if shutil.which("iptables") is None:
        print("[iptables] iptables binary not found, skipping firewall rules")
        return

    try:
        data_dir = Path(__file__).resolve().parent.parent / "data"
        if not data_dir.exists():
            return

        ports: set[int] = set()
        for profile_file in data_dir.glob("*.json"):
            port = _extract_listen_port_from_profile(profile_file)
            if port is not None:
                ports.add(port)

        for port in sorted(ports):
            # Rule 1: Drop all external TCP traffic to the instance port
            check_drop = [
                "iptables", "-C", "INPUT", "-p", "tcp",
                "--dport", str(port), "-j", "DROP",
            ]
            if subprocess.run(check_drop, capture_output=True, check=False).returncode != 0:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-p", "tcp",
                     "--dport", str(port), "-j", "DROP"],
                    check=False,
                )

            # Rule 2: Allow localhost to reach the instance port
            check_accept = [
                "iptables", "-C", "INPUT", "-p", "tcp",
                "-s", "127.0.0.1", "--dport", str(port), "-j", "ACCEPT",
            ]
            if subprocess.run(check_accept, capture_output=True, check=False).returncode != 0:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-p", "tcp",
                     "-s", "127.0.0.1", "--dport", str(port), "-j", "ACCEPT"],
                    check=False,
                )

        print(f"[iptables] Applied rules for ports: {sorted(ports)}")
    except Exception as exc:
        # Non-fatal: the panel can still run without iptables rules
        print(f"[iptables] Could not apply firewall rules: {exc}")


def ensure_systemd_service() -> None:
    """Create and enable a systemd service for MasterDnsWeb on first run.

    Only runs for the frozen (PyInstaller) binary. If the unit file already
    exists it does nothing, so repeated starts are safe.
    """
    if not getattr(sys, "frozen", False):
        return

    try:
        bin_path = Path(sys.executable).resolve()
        work_dir = bin_path.parent
        unit_path = Path("/etc/systemd/system/masterdnsweb.service")

        if unit_path.exists():
            return

        template_path = _find_service_template()
        if template_path is None:
            print("[systemd] Template file not found, skipping service creation")
            return

        template = template_path.read_text(encoding="utf-8")
        unit_content = template.format(WORK_DIR=str(work_dir), BIN_PATH=str(bin_path))

        unit_path.write_text(unit_content, encoding="utf-8")

        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "enable", "masterdnsweb.service"], check=False)

        print(f"[systemd] Created and enabled {unit_path}")
    except Exception as exc:
        # Non-fatal: the panel can still run without the systemd service
        print(f"[systemd] Could not create service: {exc}")


if __name__ == "__main__":
    ensure_systemd_service()
    apply_iptables_for_instances()
    import uvicorn
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info"
    )
