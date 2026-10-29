from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func
from sqlalchemy.orm import Session
from io import BytesIO

from core.database import SessionLocal, engine, Base
from core.models import Finding, ScanResult, User
from core.report import generate_scan_pdf
from core.scanner import detect_target

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-please-super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(
    title="Smartest Bug Hunter Pro",
    description="Advanced OWASP security audit and vulnerability tracking platform.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        user = db.query(User).filter(User.username == username).first()
        return user
    except JWTError:
        return None


@app.on_event("startup")
def ensure_default_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if admin is None:
            admin_user = User(
                username="admin",
                email="admin@localhost",
                hashed_password=hash_password("admin123"),
                is_admin=True,
            )
            db.add(admin_user)
            db.commit()
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_current_user(request, SessionLocal())
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
            status_code=401,
        )

    token = create_access_token(user.username)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=False,
        samesite="lax",
    )
    return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register")
async def register_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "A user with that username or email already exists."},
            status_code=409,
        )

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.username)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=False,
        samesite="lax",
    )
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    return response


def require_login(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    scans = (
        db.query(ScanResult)
        .filter(ScanResult.user_id == user.id)
        .order_by(ScanResult.created_at.desc())
        .all()
    )

    total_scans = len(scans)
    critical_total = sum(1 for scan in scans if scan.highest_severity == "critical")
    total_findings = sum(scan.total_findings for scan in scans)

    owasp_breakdown = (
        db.query(Finding.category, func.count(Finding.id).label("count"))
        .join(ScanResult)
        .filter(ScanResult.user_id == user.id)
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc())
        .all()
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "scans": scans,
            "total_scans": total_scans,
            "critical_total": critical_total,
            "total_findings": total_findings,
            "owasp_breakdown": owasp_breakdown,
        },
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    scan = (
        db.query(ScanResult)
        .filter(ScanResult.id == scan_id, ScanResult.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return templates.TemplateResponse(
        "scan_detail.html",
        {"request": request, "user": user, "scan": scan, "findings": scan.findings},
    )


@app.get("/scan/{scan_id}/pdf")
async def download_pdf(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    scan = (
        db.query(ScanResult)
        .filter(ScanResult.id == scan_id, ScanResult.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pdf_bytes = generate_scan_pdf(scan)
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"'},
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    all_users = db.query(User).order_by(User.created_at.desc()).all()
    all_scans = db.query(ScanResult).order_by(ScanResult.created_at.desc()).all()
    total_users = len(all_users)
    total_scan_count = len(all_scans)

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": user,
            "all_users": all_users,
            "all_scans": all_scans,
            "total_users": total_users,
            "total_scan_count": total_scan_count,
        },
    )


@app.post("/api/scan")
async def api_scan(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_login(request, db)
    payload = await request.json()
    target_url = payload.get("target_url")
    if not target_url:
        raise HTTPException(status_code=400, detail="A target URL is required.")

    result = detect_target(target_url)
    scan = ScanResult(
        user_id=user.id,
        target_url=target_url,
        status=result.get("status", "ok"),
        highest_severity=result.get("summary", {}).get("highest_severity", "info"),
        total_findings=result.get("summary", {}).get("total_findings", 0),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for finding in result.get("findings", []):
        db.add(
            Finding(
                scan_id=scan.id,
                category=finding.get("category", "General"),
                severity=finding.get("severity", "info"),
                title=finding.get("title", "Finding"),
                description=finding.get("description", ""),
                remediation=finding.get("remediation", ""),
                evidence=finding.get("evidence", ""),
            )
        )
    db.commit()

    return {"status": "ok", "scan_id": scan.id, "result": result}


@app.get("/api/scans")
async def api_scans(request: Request, db: Session = Depends(get_db)):
    user = require_login(request, db)
    scans = (
        db.query(ScanResult)
        .filter(ScanResult.user_id == user.id)
        .order_by(ScanResult.created_at.desc())
        .all()
    )
    return [
        {
            "id": scan.id,
            "target": scan.target_url,
            "status": scan.status,
            "highest_severity": scan.highest_severity,
            "total_findings": scan.total_findings,
            "created_at": scan.created_at.isoformat(),
        }
        for scan in scans
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
