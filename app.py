from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.scanner import detect_target

app = FastAPI(
    title="Smartest Bug Hunter",
    description="OWASP security detector for web app reconnaissance and vulnerability detection.",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class ScanRequest(BaseModel):
    target_url: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def healthcheck():
    return {"status": "ok", "service": "Smartest Bug Hunter"}


@app.post("/api/scan")
async def scan_target(payload: ScanRequest):
    if not payload.target_url or not payload.target_url.strip():
        return {"status": "error", "message": "A target URL is required."}

    return detect_target(payload.target_url)

