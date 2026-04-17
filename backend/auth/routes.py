from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone

from models.models import User, AuditLog
from models.database import get_db
from auth.auth import (hash_password, verify_password, create_access_token,
                       generate_totp_secret, verify_totp, generate_totp_qr,
                       get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES)

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "viewer"

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str | None = None

class TOTPVerifyRequest(BaseModel):
    totp_code: str

async def log_action(db, user_id, action, resource=None, ip=None, detail=None):
    entry = AuditLog(user_id=user_id, action=action, resource=resource, ip_address=ip, detail=detail)
    db.add(entry)
    await db.commit()

@router.post("/register")
async def register(req: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    if req.role not in ("admin", "editor", "viewer"):
        raise HTTPException(400, "Invalid role")
    existing = await db.execute(select(User).where(User.username == req.username))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Username already taken")
    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_action(db, user.id, "REGISTER", ip=request.client.host)
    return {"message": "Registered successfully", "user_id": user.id}

@router.post("/login")
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == req.username))
    user = result.scalar_one_or_none()
    ip = request.client.host

    if not user:
        raise HTTPException(401, "Invalid credentials")

    # Check lockout
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(403, f"Account locked. Try again after {user.locked_until.strftime('%H:%M UTC')}")

    if not verify_password(req.password, user.hashed_password):
        user.failed_logins += 1
        if user.failed_logins >= LOCKOUT_THRESHOLD:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            await db.commit()
            await log_action(db, user.id, "ACCOUNT_LOCKED", ip=ip, detail=f"After {LOCKOUT_THRESHOLD} failed attempts")
            raise HTTPException(403, "Account locked due to too many failed attempts")
        await db.commit()
        raise HTTPException(401, "Invalid credentials")

    # 2FA check
    if user.totp_enabled:
        if not req.totp_code:
            return {"require_2fa": True, "message": "2FA code required"}
        if not verify_totp(user.totp_secret, req.totp_code):
            await log_action(db, user.id, "LOGIN_2FA_FAIL", ip=ip)
            raise HTTPException(401, "Invalid 2FA code")

    user.failed_logins = 0
    user.locked_until = None
    await db.commit()

    token = create_access_token({"sub": user.id, "role": user.role})
    await log_action(db, user.id, "LOGIN_SUCCESS", ip=ip)
    return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username}

@router.post("/setup-2fa")
async def setup_2fa(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    secret = generate_totp_secret()
    current_user.totp_secret = secret
    await db.commit()
    qr = generate_totp_qr(secret, current_user.username)
    return {"secret": secret, "qr_code": qr}

@router.post("/confirm-2fa")
async def confirm_2fa(req: TOTPVerifyRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user.totp_secret:
        raise HTTPException(400, "Run /setup-2fa first")
    if not verify_totp(current_user.totp_secret, req.totp_code):
        raise HTTPException(400, "Invalid code")
    current_user.totp_enabled = True
    await db.commit()
    return {"message": "2FA enabled successfully"}

@router.post("/disable-2fa")
async def disable_2fa(req: TOTPVerifyRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not verify_totp(current_user.totp_secret, req.totp_code):
        raise HTTPException(400, "Invalid code")
    current_user.totp_enabled = False
    current_user.totp_secret = None
    await db.commit()
    return {"message": "2FA disabled"}

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "totp_enabled": current_user.totp_enabled,
        "created_at": current_user.created_at,
    }
