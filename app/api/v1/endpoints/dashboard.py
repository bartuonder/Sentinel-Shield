from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from app.api import deps
from app.models.user import User
from app.models.security import SecurityLog, BlacklistedIP
from app.schemas.user import UserResponse
from typing import List, Dict, Any

router = APIRouter()

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(deps.get_current_user)):
    return current_user

@router.get("/stats")
async def get_dashboard_stats(
        current_user: User = Depends(deps.get_current_user),
        db: AsyncSession = Depends(deps.get_db)
):

    total_req_query = select(func.count(SecurityLog.id)).where(SecurityLog.user_id == current_user.id)
    total_req = await db.execute(total_req_query)
    total_count = total_req.scalar() or 0

    blocked_req_query = select(func.count(SecurityLog.id)).where(
        (SecurityLog.user_id == current_user.id) & (SecurityLog.status == "BLOCKED")
    )
    blocked_req = await db.execute(blocked_req_query)
    blocked_count = blocked_req.scalar() or 0

    dist_query = select(SecurityLog.scanner_name, func.count(SecurityLog.id)) \
        .where((SecurityLog.user_id == current_user.id) & (SecurityLog.status == "BLOCKED")) \
        .group_by(SecurityLog.scanner_name)

    dist_result = await db.execute(dist_query)
    attack_distribution = [{"name": row[0], "value": row[1]} for row in dist_result.all()]

    blacklist_query = select(func.count(BlacklistedIP.id))
    blacklist_req = await db.execute(blacklist_query)
    total_banned_ips = blacklist_req.scalar() or 0

    return {
        "total_requests": total_count,
        "blocked_attacks": blocked_count,
        "attack_distribution": attack_distribution,
        "global_banned_ips": total_banned_ips
    }

@router.get("/logs")
async def get_user_logs(
        limit: int = 20,
        current_user: User = Depends(deps.get_current_user),
        db: AsyncSession = Depends(deps.get_db)
):
    query = select(SecurityLog).where(SecurityLog.user_id == current_user.id) \
        .order_by(desc(SecurityLog.timestamp)) \
        .limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()
    return logs