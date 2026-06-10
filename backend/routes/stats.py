# backend/routes/stats.py
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict
from backend.routes.auth import get_current_user
from datetime import datetime, timedelta
import json
import logging

def get_fresh_connection():
    """Always get a fresh connection to avoid SSL timeout issues"""
    try:
        conn = ml_db.get_postgres_connection()
        # Test if connection is alive
        conn.cursor().execute("SELECT 1")
        return conn
    except Exception:
        # Force reconnect
        ml_db._postgres_conn = None  # reset cached connection
        return ml_db.get_postgres_connection()

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from backend.db.ml_integration import ml_db

router = APIRouter(prefix="/stats", tags=["stats"])

@router.get("/history")
async def get_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    scan_type: Optional[str] = Query(None, pattern="^(url|email|file|app)$"),
    malicious_only: bool = False,
    current_user: dict = Depends(get_current_user),  # ← ADD
):
    user_id = current_user.get("id") 
    """Get scan history from PostgreSQL"""
    if not isinstance(limit, int):
        limit = getattr(limit, "default", 100)
    if not isinstance(offset, int):
        offset = getattr(offset, "default", 0)
    if not isinstance(scan_type, (str, type(None))):
        scan_type = getattr(scan_type, "default", None)
        
    try:
        conn = ml_db.get_postgres_connection()
        cur = conn.cursor()
        
        query = """
            SELECT sr.id, sr.input_type, sr.input_value, sr.created_at,
                   ap.prediction_label, ap.threat_type, ap.confidence_score, 
                   ap.explanation, ap.model_version, ap.inference_ms
            FROM scan_requests sr
            LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
            WHERE 1=1
        """
        
        count_query = """
            SELECT COUNT(*)
            FROM scan_requests sr
            LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
            WHERE 1=1
        """
        params = []
        
        if scan_type:
            query += " AND sr.input_type = %s"
            count_query += " AND sr.input_type = %s"
            params.append(scan_type)
        
        if malicious_only:
            query += " AND ap.prediction_label = 'malicious'"
            count_query += " AND ap.prediction_label = 'malicious'"
            
        if user_id:
            query += " AND sr.user_id = %s::uuid"
            count_query += " AND sr.user_id = %s::uuid"
            params.append(user_id)
            
        cur.execute(count_query, params)
        total_count = cur.fetchone()[0]
        
        query += " ORDER BY sr.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        
        scans = []
        for row in rows:
            scans.append({
                "id": row[0],
                "input_type": row[1],
                "input_value": row[2] if row[2] else "",
                "timestamp": row[3].isoformat() if row[3] else None,
                "status": row[4],
                "threat_type": row[5],
                "confidence_score": row[6] if row[6] else 0.0,
                "explanation": row[7],
                "model_version": row[8],
                "inference_ms": row[9]
            })
        
        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": scans
        }
    except Exception as e:
        logger.error(f"Error in get_history: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {"total": 0, "scans": [], "error": str(e)}
    
# ── CHANGE 2: Add /history/me route — paste this AFTER the /history function ──

@router.get("/history/me")
async def get_my_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get scan history for the currently authenticated user only"""
    user_id = current_user.get("id")
    try:
        conn = ml_db.get_postgres_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) 
            FROM scan_requests 
            WHERE user_id = %s::uuid
        """, (user_id,))
        total_count = cur.fetchone()[0]

        cur.execute("""
            SELECT sr.id, sr.input_type, sr.input_value, sr.created_at,
                   ap.prediction_label, ap.threat_type, ap.confidence_score
            FROM scan_requests sr
            LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
            WHERE sr.user_id = %s::uuid
            ORDER BY sr.created_at DESC
            LIMIT %s OFFSET %s
        """, (user_id, limit, offset))
        rows = cur.fetchall()
        cur.close()

        records = [{
            "id": str(r[0]),
            "input_type": r[1],
            "input_value": r[2] or "",
            "timestamp": r[3].isoformat() if r[3] else None,
            "status": r[4] or "safe",
            "threat_type": r[5] or "clean",
            "confidence_score": r[6] or 0.0,
        } for r in rows]

        return {"total": total_count, "limit": limit, "offset": offset, "records": records}
    except Exception as e:
        logger.error(f"Error in get_my_history: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {"total": 0, "records": [], "error": str(e)}

def _get_summary_data(hours: int, user_id: Optional[str] = None):
    """Get summary statistics from PostgreSQL and cache layers"""
    if not isinstance(hours, (int, float)):
        hours = getattr(hours, "default", 24)
    try:
        conn = ml_db.get_postgres_connection()
        cur = conn.cursor()
        
        # 1. Total counts — ALL-TIME (no time filter) so Dashboard & History always match
        if user_id:
            cur.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN input_type = 'url' THEN 1 ELSE 0 END) as url_scans,
                    SUM(CASE WHEN input_type = 'email' THEN 1 ELSE 0 END) as email_scans,
                    SUM(CASE WHEN input_type = 'file' THEN 1 ELSE 0 END) as file_scans,
                    SUM(CASE WHEN input_type = 'app' THEN 1 ELSE 0 END) as app_scans,
                    SUM(CASE WHEN ap.prediction_label = 'malicious' THEN 1 ELSE 0 END) as malicious_total,
                    AVG(ap.confidence_score) as avg_confidence,
                    AVG(ap.inference_ms) as avg_time
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
                WHERE sr.user_id = %s::uuid
            """, (user_id,))
        else:
            cur.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN input_type = 'url' THEN 1 ELSE 0 END) as url_scans,
                    SUM(CASE WHEN input_type = 'email' THEN 1 ELSE 0 END) as email_scans,
                    SUM(CASE WHEN input_type = 'file' THEN 1 ELSE 0 END) as file_scans,
                    SUM(CASE WHEN input_type = 'app' THEN 1 ELSE 0 END) as app_scans,
                    SUM(CASE WHEN ap.prediction_label = 'malicious' THEN 1 ELSE 0 END) as malicious_total,
                    AVG(ap.confidence_score) as avg_confidence,
                    AVG(ap.inference_ms) as avg_time
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
            """)
        
        row = cur.fetchone()
        
        total = row[0] or 0
        url_scans = row[1] or 0
        email_scans = row[2] or 0
        file_scans = row[3] or 0
        app_scans = row[4] or 0
        malicious = row[5] or 0
        
        # Calculate local timezone offset in hours
        local_now = datetime.now()
        utc_now = datetime.utcnow()
        offset_hours = int(round((local_now - utc_now).total_seconds() / 3600))
        
        # 2. Hourly activity (scan_activity) over past 24 hours - FIXED
        if user_id:
            cur.execute("""
                SELECT 
                    EXTRACT(HOUR FROM sr.created_at) as hr,
                    COUNT(*) as scans,
                    SUM(CASE WHEN ap.prediction_label = 'malicious' THEN 1 ELSE 0 END) as threats
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
                WHERE sr.created_at >= NOW() - INTERVAL '24 hours'
                AND sr.user_id = %s::uuid
                GROUP BY EXTRACT(HOUR FROM sr.created_at)
            """, (user_id,))
        else:
            cur.execute("""
                SELECT 
                    EXTRACT(HOUR FROM sr.created_at) as hr,
                    COUNT(*) as scans,
                    SUM(CASE WHEN ap.prediction_label = 'malicious' THEN 1 ELSE 0 END) as threats
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
                WHERE sr.created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY EXTRACT(HOUR FROM sr.created_at)
            """)
        activity_rows = cur.fetchall()
        
        # Shift database UTC hours to local hours
        hourly_data = {}
        for r in activity_rows:
            db_utc_hour = int(r[0])
            local_hr = (db_utc_hour + offset_hours) % 24
            hourly_data[local_hr] = {
                "scans": hourly_data.get(local_hr, {}).get("scans", 0) + int(r[1]),
                "threats": hourly_data.get(local_hr, {}).get("threats", 0) + int(r[2])
            }
            
        scan_activity = []
        current_hour = datetime.now().hour
        for i in range(24):
            target_hour = (current_hour - 23 + i) % 24
            hour_str = f"{target_hour:02d}:00"
            bucket = hourly_data.get(target_hour, {"scans": 0, "threats": 0})
            scan_activity.append({
                "hour": hour_str,
                "scans": bucket["scans"],
                "threats": bucket["threats"]
            })
            
        # 3. Threat Distribution - FIXED
        if user_id:
            cur.execute("""
                SELECT 
                    ap.threat_type,
                    sr.input_type,
                    COUNT(*) as count
                FROM ai_predictions ap
                LEFT JOIN scan_requests sr ON sr.id = ap.request_id
                WHERE sr.user_id = %s::uuid
                GROUP BY ap.threat_type, sr.input_type
            """, (user_id,))
        else:
            cur.execute("""
                SELECT 
                    ap.threat_type,
                    sr.input_type,
                    COUNT(*) as count
                FROM ai_predictions ap
                LEFT JOIN scan_requests sr ON sr.id = ap.request_id
                GROUP BY ap.threat_type, sr.input_type
            """)
        threat_rows = cur.fetchall()
        total_predictions = sum(r[2] for r in threat_rows)
        
        distribution_counts = {
            "Phishing": 0,
            "Malware": 0,
            "Spam": 0,
            "Clean": 0
        }
        for r in threat_rows:
            raw_type = (r[0] or "clean").lower()
            input_type = (r[1] or "").lower()
            count = r[2]
            
            if raw_type == "clean":
                disp_name = "Clean"
            elif raw_type in ("phishing", "spam_phishing"):
                disp_name = "Phishing"
            elif raw_type in ("trojan", "malware", "unsafe_app"):
                disp_name = "Malware"
            elif raw_type == "spam":
                disp_name = "Spam"
            elif raw_type == "suspicious":
                if input_type == "url":
                    disp_name = "Phishing"
                elif input_type == "email":
                    disp_name = "Spam"
                else:
                    disp_name = "Malware"
            elif raw_type == "low_risk":
                if input_type == "email":
                    disp_name = "Spam"
                else:
                    disp_name = "Malware"
            else:
                if input_type == "url":
                    disp_name = "Phishing"
                elif input_type == "email":
                    disp_name = "Spam"
                elif input_type in ("file", "app", "apk"):
                    disp_name = "Malware"
                else:
                    disp_name = "Clean"
            
            distribution_counts[disp_name] += count
            
        threat_distribution = [
            {"name": "Phishing", "value": round((distribution_counts["Phishing"] / total_predictions) * 100, 1) if total_predictions > 0 else 0.0},
            {"name": "Malware", "value": round((distribution_counts["Malware"] / total_predictions) * 100, 1) if total_predictions > 0 else 0.0},
            {"name": "Spam", "value": round((distribution_counts["Spam"] / total_predictions) * 100, 1) if total_predictions > 0 else 0.0},
            {"name": "Clean", "value": round((distribution_counts["Clean"] / total_predictions) * 100, 1) if total_predictions > 0 else 0.0}
        ]
            
        # 4. Recent Scans (latest 5) - FIXED
        if user_id:
            cur.execute("""
                SELECT sr.id, sr.input_type, sr.created_at,
                       ap.prediction_label, ap.threat_type, ap.confidence_score
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
                WHERE sr.user_id = %s::uuid
                ORDER BY sr.created_at DESC
                LIMIT 5
            """, (user_id,))
        else:
            cur.execute("""
                SELECT sr.id, sr.input_type, sr.created_at,
                       ap.prediction_label, ap.threat_type, ap.confidence_score
                FROM scan_requests sr
                LEFT JOIN ai_predictions ap ON sr.id = ap.request_id
                ORDER BY sr.created_at DESC
                LIMIT 5
            """)
        recent_rows = cur.fetchall()
        recent_scans = []
        for r in recent_rows:
            ts = r[2].strftime("%Y-%m-%d %H:%M:%S") if r[2] else ""
            recent_scans.append({
                "id": str(r[0]),
                "timestamp": ts,
                "type": r[1],
                "status": r[3] or "safe",
                "threat_type": r[4] or "clean",
                "confidence_score": r[5] if r[5] is not None else 0.0
            })
            
            
        # 5. Cache stats from ml_db
        cache_stats = {
            "l1": {"hits": 0, "misses": 0, "hit_rate": 0},
            "l2": {"hits": 0, "misses": 0, "hit_rate": 0},
            "l3": {"hits": 0, "misses": 0, "hit_rate": 0}
        }
        cache_hit_rate = 0.0
        total_hits = 0
        try:
            cur.close()  # close the previous cursor
            cur2 = conn.cursor()  # open a fresh one for cache stats
            if user_id:
                # Calculate individual cache stats based on explanations
                cur2.execute("""
                    SELECT ap.explanation, COUNT(*) FROM ai_predictions ap
                    JOIN scan_requests sr ON sr.id = ap.request_id
                    WHERE sr.user_id = %s::uuid AND ap.explanation LIKE 'Cached result from previous scan%%'
                    GROUP BY ap.explanation
                """, (user_id,))
                user_cache_rows = cur2.fetchall()
                l1_hits = l2_hits = l3_hits = legacy_hits = 0
                for exp, cnt in user_cache_rows:
                    if "(L1)" in exp: l1_hits += cnt
                    elif "(L2)" in exp: l2_hits += cnt
                    elif "(L3)" in exp: l3_hits += cnt
                    else: legacy_hits += cnt
                
                # Add legacy unversioned hits to L1
                l1_hits += legacy_hits
                
                user_total = total
                total_hits = l1_hits + l2_hits + l3_hits
                
                # Approximate misses based on sequential L1 -> L2 -> L3 logic
                l1_total = user_total
                l2_total = user_total - l1_hits
                l3_total = user_total - l1_hits - l2_hits
                
                cache_stats = {
                    "l1": {
                        "hits": l1_hits,
                        "misses": l1_total - l1_hits if l1_total > l1_hits else 0,
                        "hit_rate": round(l1_hits / l1_total, 2) if l1_total > 0 else 0.0
                    },
                    "l2": {
                        "hits": l2_hits,
                        "misses": l2_total - l2_hits if l2_total > l2_hits else 0,
                        "hit_rate": round(l2_hits / l2_total, 2) if l2_total > 0 else 0.0
                    },
                    "l3": {
                        "hits": l3_hits,
                        "misses": l3_total - l3_hits if l3_total > l3_hits else 0,
                        "hit_rate": round(l3_hits / l3_total, 2) if l3_total > 0 else 0.0
                    }
                }
                cache_hit_rate = round(total_hits / user_total, 2) if user_total > 0 else 0.0
                logger.info(f"User {user_id} cache stats: l1_hits={l1_hits}, l2_hits={l2_hits}, l3_hits={l3_hits}, total={user_total}")
            else:
                # Global stats
                cache_stats = ml_db.get_cache_stats()
                l1 = cache_stats.get("l1", {"hits": 0, "misses": 0, "hit_rate": 0})
                l2 = cache_stats.get("l2", {"hits": 0, "misses": 0, "hit_rate": 0})
                l3 = cache_stats.get("l3", {"hits": 0, "misses": 0, "hit_rate": 0})
                
                total_hits = l1.get("hits", 0) + l2.get("hits", 0) + l3.get("hits", 0)
                total_cache_reqs = l1.get("hits", 0) + l1.get("misses", 0)
                cache_hit_rate = total_hits / total_cache_reqs if total_cache_reqs > 0 else 0.0
            cur2.close()

        except Exception as ce:
            logger.warning(f"Failed to calculate cache summary stats: {ce}", exc_info=True)
        
        return {
            "period_hours": hours,
            "total_scans": total,
            "by_type": {
                "url": url_scans,
                "email": email_scans,
                "file": file_scans,
                "app": app_scans
            },
            "threats_detected": malicious,
            "safe_requests": total - malicious,
            "malicious_total": malicious,
            "avg_confidence": round((row[6] or 0) * 100, 2),
            "avg_time_ms": round(row[7] or 0, 2),
            "cache_hit_rate": cache_hit_rate,
            "personal_cache_hits": total_hits,
            "personal_cache_hit_rate": round(cache_hit_rate * 100, 1),
            "cache": cache_stats,
            "scan_activity": scan_activity,
            "threat_distribution": threat_distribution,
            "recent_scans": recent_scans,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in get_summary: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {
            "period_hours": hours,
            "total_scans": 0,
            "by_type": {"url": 0, "email": 0, "file": 0, "app": 0},
            "threats_detected": 0,
            "safe_requests": 0,
            "avg_confidence": 0,
            "cache_hit_rate": 0.0,
            "cache": {
                "l1": {"hits": 0, "misses": 0, "hit_rate": 0},
                "l2": {"hits": 0, "misses": 0, "hit_rate": 0},
                "l3": {"hits": 0, "misses": 0, "hit_rate": 0}
            },
            "scan_activity": [],
            "threat_distribution": [],
            "recent_scans": [],
            "timestamp": datetime.now().isoformat()
        }

@router.get("/summary")
async def get_summary(hours: int = Query(24, ge=1, le=8760)):
    """Get global summary statistics"""
    return _get_summary_data(hours, user_id=None)

@router.get("/summary/me")
async def get_summary_me(
    hours: int = Query(24, ge=1, le=8760),
    current_user: dict = Depends(get_current_user)
):
    """Get user-scoped summary statistics"""
    user_id = current_user.get("id")
    return _get_summary_data(hours, user_id=user_id)

@router.get("/cache/status")
async def get_cache_status():
    """Get REAL cache status — computed from DB scan history (admin use)"""
    try:
        conn = ml_db.get_postgres_connection()
        cur = conn.cursor()

        # Total scans
        cur.execute("SELECT COUNT(*) FROM scan_requests")
        total = cur.fetchone()[0] or 0

        # Count cache hits per layer from explanation field
        cur.execute("""
            SELECT explanation, COUNT(*)
            FROM ai_predictions
            WHERE explanation LIKE 'Cached result from previous scan%%'
            GROUP BY explanation
        """)
        rows = cur.fetchall()
        cur.close()

        l1_hits = l2_hits = l3_hits = legacy_hits = 0
        for exp, cnt in rows:
            if "(L1)" in exp:    l1_hits += cnt
            elif "(L2)" in exp:  l2_hits += cnt
            elif "(L3)" in exp:  l3_hits += cnt
            else:                legacy_hits += cnt

        l1_hits += legacy_hits  # unversioned legacy hits → L1

        l2_total = max(0, total - l1_hits)
        l3_total = max(0, total - l1_hits - l2_hits)

        return {
            "l1": {
                "hit_rate": round(l1_hits / total, 2) if total > 0 else 0.0,
                "hits": l1_hits,
                "misses": max(0, total - l1_hits),
            },
            "l2": {
                "hit_rate": round(l2_hits / l2_total, 2) if l2_total > 0 else 0.0,
                "hits": l2_hits,
                "misses": max(0, l2_total - l2_hits),
                "keys": l2_hits,
            },
            "l3": {
                "hit_rate": round(l3_hits / l3_total, 2) if l3_total > 0 else 0.0,
                "hits": l3_hits,
                "misses": max(0, l3_total - l3_hits),
                "documents": l3_hits,
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Cache status error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {
            "l1": {"hit_rate": 0, "hits": 0, "misses": 0},
            "l2": {"hit_rate": 0, "hits": 0, "misses": 0},
            "l3": {"hit_rate": 0, "hits": 0, "misses": 0},
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@router.get("/cache/status/me")
async def get_cache_status_me(
    current_user: dict = Depends(get_current_user)
):
    """Get per-user cache stats computed from scan history"""
    user_id = current_user.get("id")
    try:
        conn = ml_db.get_postgres_connection()
        cur = conn.cursor()

        # Get total scans for this user
        cur.execute("""
            SELECT COUNT(*) FROM scan_requests WHERE user_id = %s::uuid
        """, (user_id,))
        user_total = cur.fetchone()[0] or 0

        # Count cache hits per layer from ai_predictions explanation field
        cur.execute("""
            SELECT ap.explanation, COUNT(*) FROM ai_predictions ap
            JOIN scan_requests sr ON sr.id = ap.request_id
            WHERE sr.user_id = %s::uuid AND ap.explanation LIKE 'Cached result from previous scan%%'
            GROUP BY ap.explanation
        """, (user_id,))
        rows = cur.fetchall()
        cur.close()

        l1_hits = l2_hits = l3_hits = legacy_hits = 0
        for exp, cnt in rows:
            if "(L1)" in exp: l1_hits += cnt
            elif "(L2)" in exp: l2_hits += cnt
            elif "(L3)" in exp: l3_hits += cnt
            else: legacy_hits += cnt

        l1_hits += legacy_hits  # legacy unversioned hits count as L1

        # Approximate misses based on cascading L1 -> L2 -> L3 logic
        l2_total = max(0, user_total - l1_hits)
        l3_total = max(0, user_total - l1_hits - l2_hits)

        return {
            "l1": {
                "hit_rate": round(l1_hits / user_total, 2) if user_total > 0 else 0.0,
                "hits": l1_hits,
                "misses": max(0, user_total - l1_hits)
            },
            "l2": {
                "hit_rate": round(l2_hits / l2_total, 2) if l2_total > 0 else 0.0,
                "hits": l2_hits,
                "misses": max(0, l2_total - l2_hits)
            },
            "l3": {
                "hit_rate": round(l3_hits / l3_total, 2) if l3_total > 0 else 0.0,
                "hits": l3_hits,
                "misses": max(0, l3_total - l3_hits)
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"User cache status error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {
            "l1": {"hit_rate": 0, "hits": 0, "misses": 0},
            "l2": {"hit_rate": 0, "hits": 0, "misses": 0},
            "l3": {"hit_rate": 0, "hits": 0, "misses": 0},
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }