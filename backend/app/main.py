from __future__ import annotations

import time
import re
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from backend.app import auth
from backend.app import database
from backend.app.demo import build_demo_pcap
from backend.app.pcap import CaptureError, MAX_CAPTURE_BYTES, parse_pcap
from backend.app.reports import create_report
from backend.app.security import assess


ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "frontend" / "dist"
app = FastAPI(title="HACKGRID IPsec VPN Security Analyzer", version="0.1.0")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def _normalized_email(email: str) -> str:
    value = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(value):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return value


@app.post("/api/auth/signup")
def sign_up(credentials: Credentials, response: Response) -> dict[str, Any]:
    email = _normalized_email(credentials.email)
    if len(credentials.password) < 10:
        raise HTTPException(status_code=422, detail="Use a password with at least 10 characters.")
    user = database.create_user(email, auth.hash_password(credentials.password))
    if user is None:
        raise HTTPException(status_code=409, detail="An account with this email already exists. Sign in instead.")
    return {"user": auth.start_session(response, user)}


@app.post("/api/auth/login")
def sign_in(credentials: Credentials, response: Response) -> dict[str, Any]:
    email = _normalized_email(credentials.email)
    user = database.get_user_by_email(email)
    valid = user is not None and auth.verify_password(credentials.password, user["password_hash"])
    if not valid:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return {"user": auth.start_session(response, user)}


@app.get("/api/auth/me")
def who_am_i(user: Annotated[dict[str, Any], Depends(auth.current_user)]) -> dict[str, Any]:
    return {"user": {"email": user["email"]}}


@app.post("/api/auth/logout")
def sign_out(request: Request, response: Response) -> dict[str, bool]:
    return auth.end_session(request, response)


@app.on_event("startup")
def startup() -> None:
    database.initialize()


def _analyze(user_id: str, data: bytes, filename: str, demo: bool) -> dict:
    start = time.perf_counter()
    try:
        capture = parse_pcap(data)
    except CaptureError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    assessment = assess(capture.transforms)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    result = {
        "capture": capture.as_dict(),
        "assessment": assessment,
        "processing_ms": elapsed_ms,
        "ml": {
            "implemented": False,
            "prediction": None,
            "message": "Traffic classification is not implemented. No prediction or confidence score is available.",
        },
        "limitations": [
            "Offline classic PCAP v2.4 only; PCAPNG is unsupported.",
            "Only Ethernet and raw-IP link types are parsed.",
            "ESP payloads are not decrypted.",
            "IKE transforms are reported as offered, not negotiated.",
            "ML classification, live capture, blockchain, and PostgreSQL are not implemented.",
        ],
    }
    return database.save_analysis(user_id, filename, demo, result)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "hackgrid-ipsec-analyzer"}


@app.get("/api/ml/status")
def ml_status(_: Annotated[dict[str, Any], Depends(auth.current_user)]) -> dict:
    return {
        "implemented": False,
        "available": False,
        "message": "ML traffic classification is not implemented; no model, predictions, or confidence scores are provided.",
    }


@app.get("/api/sample")
def sample_capture(_: Annotated[dict[str, Any], Depends(auth.current_user)]) -> Response:
    data = build_demo_pcap()
    return Response(
        data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": 'attachment; filename="HACKGRID_DEMO_DATA_synthetic.pcap"'},
    )


@app.post("/api/analyze")
async def analyze(
    request: Request,
    user: Annotated[dict[str, Any], Depends(auth.current_user)],
    filename: str = "upload.pcap",
) -> dict:
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=415, detail="Only classic .pcap input is accepted; PCAPNG is not supported.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_CAPTURE_BYTES:
            raise HTTPException(status_code=413, detail=f"Capture exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB upload limit.")
        content.extend(chunk)
    data = bytes(content)
    return _analyze(user["id"], data, Path(filename).name, demo=False)


@app.post("/api/analyze/demo")
def analyze_demo(user: Annotated[dict[str, Any], Depends(auth.current_user)]) -> dict:
    return _analyze(user["id"], build_demo_pcap(), "HACKGRID_DEMO_DATA_synthetic.pcap", demo=True)


@app.get("/api/analysis/history")
def analysis_history(user: Annotated[dict[str, Any], Depends(auth.current_user)]) -> list[dict]:
    return database.history(user["id"])


@app.get("/api/analysis/{analysis_id}/report")
def analysis_report(
    analysis_id: str,
    user: Annotated[dict[str, Any], Depends(auth.current_user)],
) -> Response:
    analysis = database.get_analysis(analysis_id, user["id"])
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis was not found.")
    pdf = create_report(analysis)
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="HACKGRID_{analysis_id[:8]}_report.pdf"'},
    )


@app.get("/api/analysis/{analysis_id}")
def analysis_detail(
    analysis_id: str,
    user: Annotated[dict[str, Any], Depends(auth.current_user)],
) -> dict:
    analysis = database.get_analysis(analysis_id, user["id"])
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis was not found.")
    return analysis


@app.get("/api/dashboard/statistics")
def dashboard_statistics(user: Annotated[dict[str, Any], Depends(auth.current_user)]) -> dict:
    return database.statistics(user["id"])


if DIST.exists():
    from fastapi.staticfiles import StaticFiles

    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")


@app.get("/")
def root():
    index = DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return {
        "message": "API is running. Start the React development server with `cd frontend; npm run dev`.",
        "frontend": "http://127.0.0.1:5173",
        "health": "/api/health",
    }
