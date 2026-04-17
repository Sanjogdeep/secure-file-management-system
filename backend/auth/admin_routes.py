from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update
from models.models import AuditLog, SecurityAlert, User
from models.database import get_db
from auth.auth import get_current_user, require_role

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "ip_address": l.ip_address,
            "detail": l.detail,
            "timestamp": l.timestamp,
        }
        for l in logs
    ]

@router.get("/security-alerts")
async def get_alerts(
    resolved: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    result = await db.execute(
        select(SecurityAlert)
        .where(SecurityAlert.resolved == resolved)
        .order_by(desc(SecurityAlert.timestamp))
        .limit(100)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "user_id": a.user_id,
            "detail": a.detail,
            "resolved": a.resolved,
            "timestamp": a.timestamp,
        }
        for a in alerts
    ]

@router.post("/security-alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(SecurityAlert).where(SecurityAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.resolved = True
    await db.commit()
    return {"message": "Alert resolved"}

@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "totp_enabled": u.totp_enabled,
            "failed_logins": u.failed_logins,
            "locked_until": u.locked_until,
            "created_at": u.created_at,
        }
        for u in users
    ]

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    from sqlalchemy import func
    from models.models import FileRecord

    user_count = (await db.execute(select(func.count(User.id)))).scalar()
    file_count = (await db.execute(select(func.count(FileRecord.id)).where(FileRecord.is_deleted == False))).scalar()
    alert_count = (await db.execute(select(func.count(SecurityAlert.id)).where(SecurityAlert.resolved == False))).scalar()
    log_count = (await db.execute(select(func.count(AuditLog.id)))).scalar()

    return {
        "total_users": user_count,
        "total_files": file_count,
        "open_alerts": alert_count,
        "total_audit_events": log_count,
    }
