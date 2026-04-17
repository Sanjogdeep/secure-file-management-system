import os, secrets, hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from models.models import User, FileRecord, ShareToken, AuditLog, FileACL
from models.database import get_db
from auth.auth import get_current_user
from threat.scanner import (compute_sha256, validate_filename, run_threat_scan)
from utils.config import encrypt_file, decrypt_file, UPLOAD_DIR

router = APIRouter(prefix="/api/files", tags=["files"])

async def log_action(db, user_id, action, resource=None, ip=None, detail=None):
    entry = AuditLog(user_id=user_id, action=action, resource=resource, ip_address=ip, detail=detail)
    db.add(entry)
    await db.commit()

def can_access(file: FileRecord, user: User, permission: str = "read") -> bool:
    if user.role == "admin":
        return True
    if file.owner_id == user.id:
        return True
    for acl in file.acl:
        if acl.user_id == user.id:
            if permission == "read":
                return True
            if permission == "write" and acl.permission == "write":
                return True
    return False

@router.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "editor"):
        raise HTTPException(403, "Only admin/editor can upload files")

    raw = await file.read()
    safe_name = validate_filename(file.filename or "upload")
    mime = file.content_type or "application/octet-stream"
    ip = request.client.host

    # Threat scan
    await run_threat_scan(raw, safe_name, mime, db, current_user.id, ip)

    # Hash
    sha256 = compute_sha256(raw)

    # Encrypt
    nonce, ciphertext = encrypt_file(raw)

    # Store: nonce (12 bytes) prepended to ciphertext
    file_id = secrets.token_hex(16)
    store_path = os.path.join(UPLOAD_DIR, file_id)
    with open(store_path, "wb") as f:
        f.write(nonce + ciphertext)

    record = FileRecord(
        id=file_id,
        filename=store_path,
        original_name=safe_name,
        mime_type=mime,
        size_bytes=len(raw),
        sha256_hash=sha256,
        owner_id=current_user.id,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    await log_action(db, current_user.id, "FILE_UPLOAD", resource=safe_name, ip=ip,
                     detail=f"size={len(raw)} sha256={sha256[:16]}...")
    return {"id": record.id, "name": safe_name, "size": len(raw), "sha256": sha256}

@router.get("/list")
async def list_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "admin":
        result = await db.execute(
            select(FileRecord).where(FileRecord.is_deleted == False)
        )
    else:
        result = await db.execute(
            select(FileRecord).where(
                FileRecord.owner_id == current_user.id,
                FileRecord.is_deleted == False
            )
        )
    files = result.scalars().all()

    # Also include files shared with the user
    if current_user.role != "admin":
        acl_result = await db.execute(
            select(FileACL).where(FileACL.user_id == current_user.id)
        )
        acls = acl_result.scalars().all()
        shared_ids = {a.file_id for a in acls}
        if shared_ids:
            shared_result = await db.execute(
                select(FileRecord).where(
                    FileRecord.id.in_(shared_ids),
                    FileRecord.is_deleted == False
                )
            )
            shared = shared_result.scalars().all()
            existing_ids = {f.id for f in files}
            for f in shared:
                if f.id not in existing_ids:
                    files.append(f)

    return [
        {
            "id": f.id,
            "name": f.original_name,
            "size": f.size_bytes,
            "mime": f.mime_type,
            "owner": f.owner_id,
            "is_owner": f.owner_id == current_user.id,
            "created_at": f.created_at,
            "updated_at": f.updated_at,
        }
        for f in files
    ]

@router.get("/download/{file_id}")
async def download_file(
    file_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    record = result.scalar_one_or_none()
    if not record or record.is_deleted:
        raise HTTPException(404, "File not found")

    # Eagerly load ACL
    from sqlalchemy.orm import selectinload
    result2 = await db.execute(
        select(FileRecord).where(FileRecord.id == file_id).options(selectinload(FileRecord.acl))
    )
    record = result2.scalar_one_or_none()

    if not can_access(record, current_user, "read"):
        raise HTTPException(403, "Access denied")

    with open(record.filename, "rb") as f:
        blob = f.read()

    nonce, ciphertext = blob[:12], blob[12:]
    try:
        data = decrypt_file(nonce, ciphertext)
    except Exception:
        raise HTTPException(500, "Decryption failed")

    # Verify integrity
    if compute_sha256(data) != record.sha256_hash:
        raise HTTPException(500, "File integrity check failed — possible tampering")

    await log_action(db, current_user.id, "FILE_DOWNLOAD", resource=record.original_name, ip=request.client.host)
    return Response(
        content=data,
        media_type=record.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{record.original_name}"'},
    )

@router.get("/metadata/{file_id}")
async def get_metadata(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(FileRecord).where(FileRecord.id == file_id)
        .options(selectinload(FileRecord.acl))
    )
    record = result.scalar_one_or_none()
    if not record or record.is_deleted:
        raise HTTPException(404, "File not found")
    if not can_access(record, current_user, "read"):
        raise HTTPException(403, "Access denied")

    return {
        "id": record.id,
        "original_name": record.original_name,
        "mime_type": record.mime_type,
        "size_bytes": record.size_bytes,
        "sha256_hash": record.sha256_hash,
        "owner_id": record.owner_id,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "acl": [{"user_id": a.user_id, "permission": a.permission} for a in record.acl],
    }

class ShareRequest(BaseModel):
    expires_hours: int = 24

@router.post("/share/{file_id}")
async def create_share_token(
    file_id: str,
    req: ShareRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    record = result.scalar_one_or_none()
    if not record or record.is_deleted:
        raise HTTPException(404, "File not found")
    if record.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(403, "Only the file owner can share")

    token = secrets.token_urlsafe(32)
    share = ShareToken(
        token=token,
        file_id=file_id,
        created_by=current_user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=req.expires_hours),
    )
    db.add(share)
    await db.commit()
    await log_action(db, current_user.id, "FILE_SHARE", resource=record.original_name, ip=request.client.host)
    return {"share_token": token, "expires_at": share.expires_at}

@router.get("/shared/{token}")
async def download_shared(token: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ShareToken).where(ShareToken.token == token))
    share = result.scalar_one_or_none()
    if not share:
        raise HTTPException(404, "Invalid share token")
    if share.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(410, "Share link has expired")

    result2 = await db.execute(select(FileRecord).where(FileRecord.id == share.file_id))
    record = result2.scalar_one_or_none()
    if not record or record.is_deleted:
        raise HTTPException(404, "File no longer exists")

    with open(record.filename, "rb") as f:
        blob = f.read()
    nonce, ciphertext = blob[:12], blob[12:]
    data = decrypt_file(nonce, ciphertext)

    return Response(
        content=data,
        media_type=record.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{record.original_name}"'},
    )

class GrantACLRequest(BaseModel):
    target_user_id: str
    permission: str = "read"

@router.post("/acl/{file_id}")
async def grant_access(
    file_id: str,
    req: GrantACLRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(404, "File not found")
    if record.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(403, "Only owner/admin can grant access")
    if req.permission not in ("read", "write"):
        raise HTTPException(400, "Permission must be read or write")

    acl = FileACL(file_id=file_id, user_id=req.target_user_id, permission=req.permission)
    db.add(acl)
    await db.commit()
    return {"message": "Access granted"}

@router.delete("/{file_id}")
async def delete_file(
    file_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    record = result.scalar_one_or_none()
    if not record or record.is_deleted:
        raise HTTPException(404, "File not found")
    if record.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(403, "Access denied")
    record.is_deleted = True
    await db.commit()
    await log_action(db, current_user.id, "FILE_DELETE", resource=record.original_name, ip=request.client.host)
    return {"message": "File deleted"}
