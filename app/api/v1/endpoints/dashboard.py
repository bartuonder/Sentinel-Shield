from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from app.api import deps
from app.models.user import User
from app.models.security import SecurityLog, BlacklistedIP
from app.security.base import ScanStatus
from app.schemas.user import UserResponse
import traceback

router = APIRouter()

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(deps.get_current_user)):
    return current_user


@router.get("/stats")
async def get_dashboard_stats(
        current_user: User = Depends(deps.get_current_user),
        db: AsyncSession = Depends(deps.get_db)
):
    stats = {
        "total_requests": 0,
        "blocked_attacks": 0,
        "attack_distribution": [],
        "global_banned_ips": 0
    }

    try:

        result = await db.execute(select(SecurityLog).where(SecurityLog.user_id == current_user.id))
        all_logs = result.scalars().all()

        total_req = len(all_logs)
        blocked_count = 0
        dist_map = {}

        for log in all_logs:

            status_str = str(log.status).upper()
            scanner = log.scanner_name or 'Bilinmiyor'

            if 'BLOCKED' in status_str:
                blocked_count += 1
                dist_map[scanner] = dist_map.get(scanner, 0) + 1

        stats["total_requests"] = total_req
        stats["blocked_attacks"] = blocked_count
        stats["attack_distribution"] = [{"name": k, "value": v} for k, v in dist_map.items()]

    except Exception as e:
        print(f"Stats Hatası: {e}")
        traceback.print_exc()

    try:
        blacklist_req = await db.execute(
            select(func.count(BlacklistedIP.id)).where(BlacklistedIP.user_id == current_user.id)
        )
        stats["global_banned_ips"] = blacklist_req.scalar() or 0
    except:
        pass

    return stats


@router.get("/logs")
async def get_user_logs(
        limit: int = 50,
        current_user: User = Depends(deps.get_current_user),
        db: AsyncSession = Depends(deps.get_db)
):
    try:
        query = select(SecurityLog).where(SecurityLog.user_id == current_user.id) \
            .order_by(desc(SecurityLog.timestamp)) \
            .limit(limit)

        result = await db.execute(query)
        logs = result.scalars().all()

        clean_logs = []
        for log in logs:

            ip = log.client_ip or '-'

            status_str = str(log.status).upper()

            is_allowed = 'BLOCKED' not in status_str

            clean_logs.append({
                "timestamp": log.timestamp,
                "ip_address": ip,
                "scanner_name": log.scanner_name or 'System',
                "request_text": log.request_text or '',
                "is_allowed": is_allowed,
                "status": "BLOCKED" if not is_allowed else "ALLOWED"
            })
        return clean_logs
    except Exception:
        traceback.print_exc()
        return []


@router.get("/bans")
async def get_banned_ips(
        current_user: User = Depends(deps.get_current_user),
        db: AsyncSession = Depends(deps.get_db)
):
    try:
        query = select(BlacklistedIP).where(BlacklistedIP.user_id == current_user.id) \
            .order_by(desc(BlacklistedIP.banned_at))
        result = await db.execute(query)
        return result.scalars().all()
    except:
        return []