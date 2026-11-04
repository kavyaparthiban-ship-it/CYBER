from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import venv
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
VENV = ROOT / ".venv"
API_HOST = "127.0.0.1"
API_PORT = 8000
WEB_HOST = "127.0.0.1"
WEB_PORT = 5173
API_URL = f"http://{API_HOST}:{API_PORT}"
WEB_URL = f"http://{WEB_HOST}:{WEB_PORT}"


def fail(message: str) -> None:
    raise RuntimeError(message)


def python_in_venv() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def run_setup(command: list[str], description: str, *, shell: bool = False) -> None:
    print(f"\n{description}...", flush=True)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        shell=shell,
        check=False,
    )
    if completed.returncode:
        fail(f"{description} failed (exit code {completed.returncode}).")


def prepare_python() -> Path:
    interpreter = python_in_venv()
    if not interpreter.exists():
        print("Creating the project Python environment...", flush=True)
        venv.EnvBuilder(with_pip=True).create(VENV)

    check = subprocess.run(
        [
            str(interpreter),
            "-c",
            "import fastapi, uvicorn, reportlab",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if check.returncode:
        run_setup(
            [str(interpreter), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")],
            "Installing backend dependencies",
        )
    return interpreter


def prepare_frontend() -> tuple[str, Path]:
    node = shutil.which("node")
    if not node:
        fail("Node.js is required. Install Node.js 18 or newer, then run `python run.py` again.")

    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        fail("npm was not found. Reinstall Node.js with npm included, then run `python run.py` again.")

    vite = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
    if not vite.exists():
        if os.name == "nt":
            run_setup("npm install --no-audit --no-fund", "Installing frontend dependencies", shell=True)
        else:
            run_setup([npm, "install", "--no-audit", "--no-fund"], "Installing frontend dependencies")
    if not vite.exists():
        fail("Vite was not installed successfully. Check frontend/package.json and rerun the launcher.")
    return node, vite


def port_is_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        return connection.connect_ex((host, port)) == 0


def service_is_ready(url: str, *, expected_body: bytes | None = None) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            if response.status != 200:
                return False
            body = response.read(16_384)
            return expected_body is None or expected_body in body
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def wait_for_service(process: subprocess.Popen, url: str, description: str) -> None:
    deadline = time.monotonic() + 60
    last_error = "not ready yet"
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            fail(f"{description} stopped during startup (exit code {return_code}).")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
                last_error = f"HTTP {response.status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    fail(f"{description} did not become ready within 60 seconds: {last_error}")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    if not (ROOT / "backend" / "app" / "main.py").is_file():
        fail("The backend files were not found. Run this script from the HACKGRID project folder.")
    if not (FRONTEND / "package.json").is_file():
        fail("frontend/package.json was not found. Restore the frontend files and try again.")

    api_ready = service_is_ready(f"{API_URL}/api/health", expected_body=b"hackgrid-ipsec-analyzer")
    web_ready = service_is_ready(WEB_URL, expected_body=b'id="root"')

    if port_is_in_use(API_HOST, API_PORT) and not api_ready:
        fail(f"Port {API_PORT} is occupied by a service that is not the HACKGRID API.")
    if port_is_in_use(WEB_HOST, WEB_PORT) and not web_ready:
        fail(f"Port {WEB_PORT} is occupied by a service that is not the HACKGRID dashboard.")

    if api_ready and web_ready:
        print("HACKGRID is already running. Opening the existing dashboard.", flush=True)
        print(f"Dashboard: {WEB_URL}", flush=True)
        webbrowser.open(WEB_URL)
        return 0

    interpreter = prepare_python() if not api_ready else None
    node, vite = prepare_frontend() if not web_ready else (None, None)

    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    api: subprocess.Popen | None = None
    web: subprocess.Popen | None = None
    try:
        if api_ready:
            print("Reusing the running HACKGRID API.", flush=True)
        else:
            print("\nStarting HACKGRID API...", flush=True)
            api = subprocess.Popen(
                [
                    str(interpreter), "-m", "uvicorn", "backend.app.main:app",
                    "--host", API_HOST, "--port", str(API_PORT),
                ],
                cwd=ROOT,
                env=environment,
            )
            wait_for_service(api, f"{API_URL}/api/health", "Backend API")

        if web_ready:
            print("Reusing the running HACKGRID dashboard.", flush=True)
        else:
            print("Starting HACKGRID dashboard...", flush=True)
            web = subprocess.Popen(
                [node, str(vite), "--host", WEB_HOST, "--port", str(WEB_PORT), "--strictPort"],
                cwd=FRONTEND,
                env=environment,
            )
            wait_for_service(web, WEB_URL, "Frontend")

        print(f"\nHACKGRID is running: {WEB_URL}", flush=True)
        print("Click 'Analyze demo data' to try the synthetic sample.", flush=True)
        print("Keep this window open. Press Ctrl+C to stop the application.", flush=True)
        webbrowser.open(WEB_URL)

        while True:
            if api is not None and api.poll() is not None:
                fail("The backend API stopped unexpectedly.")
            if web is not None and web.poll() is not None:
                fail("The frontend server stopped unexpectedly.")
            if api is None and not service_is_ready(f"{API_URL}/api/health", expected_body=b"hackgrid-ipsec-analyzer"):
                fail("The reused backend API stopped responding.")
            if web is None and not service_is_ready(WEB_URL, expected_body=b'id="root"'):
                fail("The reused frontend stopped responding.")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping HACKGRID...", flush=True)
        return 0
    finally:
        stop_process(web)
        stop_process(api)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"\nCould not start HACKGRID: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1) from error
