from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from app.api import deps
from app.models.user import User
from app.models.security import SecurityLog, BlacklistedIP
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
        # 1. Logları Çek
        result = await db.execute(select(SecurityLog).where(SecurityLog.user_id == current_user.id))
        all_logs = result.scalars().all()

        total_req = len(all_logs)
        blocked_count = 0
        dist_map = {}

        print(f"--- DEBUG ANALİZ BAŞLADI (Toplam Log: {total_req}) ---")

        for log in all_logs:
            # Veriyi en esnek şekilde alalım
            is_allowed_raw = getattr(log, 'is_allowed', True)
            status_raw = str(getattr(log, 'status', 'ALLOWED')).upper()
            scanner = getattr(log, 'scanner_name', 'Bilinmiyor')

            # KRİTİK DÜZELTME: 'is False' yerine 'not ...' kullanıyoruz.
            # Böylece 0, False, None gibi değerlerin hepsi yakalanır.
            is_blocked_bool = not bool(is_allowed_raw)
            is_blocked_text = status_raw == 'BLOCKED'

            if is_blocked_bool or is_blocked_text:
                blocked_count += 1
                dist_map[scanner] = dist_map.get(scanner, 0) + 1

        print(f"--- DEBUG BİTTİ: Engellenen Sayısı: {blocked_count} ---")

        stats["total_requests"] = total_req
        stats["blocked_attacks"] = blocked_count
        stats["attack_distribution"] = [{"name": k, "value": v} for k, v in dist_map.items()]

    except Exception as e:
        print(f"Stats Log Hatası: {e}")
        traceback.print_exc()

    # 2. Banlanan IP Sayısı
    try:
        blacklist_req = await db.execute(
            select(func.count(BlacklistedIP.id)).where(BlacklistedIP.user_id == current_user.id)
        )
        stats["global_banned_ips"] = blacklist_req.scalar() or 0
    except Exception as e:
        print(f"Stats Ban Hatası: {e}")

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
            ip = getattr(log, 'ip_address', getattr(log, 'ip', getattr(log, 'client_ip', '-')))
            is_allowed_raw = getattr(log, 'is_allowed', True)
            status_raw = getattr(log, 'status', None)

            # Boolean kontrolünü sağlama alalım
            is_allowed_bool = bool(is_allowed_raw)

            # Status metnini belirle
            final_status = "ALLOWED"
            if not is_allowed_bool:
                final_status = "BLOCKED"
            elif status_raw and str(status_raw).upper() == "BLOCKED":
                final_status = "BLOCKED"

            clean_logs.append({
                "timestamp": log.timestamp,
                "ip_address": ip,
                "scanner_name": getattr(log, 'scanner_name', 'System'),
                "request_text": getattr(log, 'request_text', getattr(log, 'text', '')),
                "is_allowed": is_allowed_bool,
                "status": final_status
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
    except Exception:
        return []