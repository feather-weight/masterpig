from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import asyncio, time, inspect

from dotenv import load_dotenv

from .scanner import Scanner, THRESHOLDS
from .db import get_db

app = FastAPI()

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
STATIC_DIR = WEB_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

scanner: Scanner | None = None
scan_task: asyncio.Task | None = None

load_dotenv()

@app.get("/health", response_class=PlainTextResponse)
async def health():
    return "ok"

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return index_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>App is running</h1>", status_code=200)

@app.post("/start_scan")
async def start_scan(xpub: str, max_gap: int = 20, concurrency: int = 16, follow_depth: int = 2):
    global scanner, scan_task
    if scan_task and not scan_task.done():
        return {"status": "already_running"}
    scanner = Scanner(max_gap=max_gap, concurrency=concurrency, follow_depth=follow_depth)
    scan_task = asyncio.create_task(scanner.scan_xpub(xpub))
    return {"status": "started"}

@app.post("/stop_scan")
async def stop_scan():
    global scanner, scan_task
    if scanner:
        scanner.stop()
    if scan_task:
        try:
            await scan_task
        except Exception:
            pass
    return {"status": "stopped"}

@app.get("/stats")
async def stats():
    return scanner.stats if scanner else {}

@app.get("/debug")
async def debug():
    info = {"has_scanner": scanner is not None}
    if scanner:
        info["task_done"] = scan_task.done() if scan_task else True
    return info

@app.get("/metrics")
async def metrics():
    now = int(time.time())
    result = {"thresholds": {}, "buckets": {}, "recent_usage": {}, "balances": {}}

    # Get DB (works even if get_db() is sync)
    db = None
    try:
        _get = get_db
        db = await _get() if inspect.iscoroutinefunction(_get) else _get()
    except Exception:
        db = None

    # No DB? Return in-memory snapshot
    if db is None:
        if scanner:
            now_ts = int(time.time())
            result["thresholds"] = {f"gt_{t}": int(scanner.stats.get(f"tx_gt_{t}", 0)) for t in THRESHOLDS}

            def count_window(seconds: int) -> int:
                return len([ts for ts in scanner.address_times if ts >= now_ts - seconds])

            windows = {
                "minute": 60,
                "hour": 3600,
                "day": 86400,
                "week": 604800,
                "month": 2592000,
                "year": 31536000,
            }

            base_active = {
                "active_addresses": int(scanner.stats.get("active_addresses", 0)),
                "with_balance": int(scanner.stats.get("with_balance", 0)),
            }
            for name, secs in windows.items():
                result["buckets"][name] = {
                    "addresses_scanned": count_window(secs),
                    **base_active,
                }
        return JSONResponse(result)

    # With DB (PyMongo sync)
    try:
        pipeline = [{
            "$group": {
                "_id": None,
                **{f"gt_{t}": {"$sum": {"$cond": [{"$gt": ["$tx_count", t]}, 1, 0]}} for t in THRESHOLDS},
                "with_balance": {"$sum": {"$cond": [{"$gt": ["$balance", 0]}, 1, 0]}},
                "active": {"$sum": {"$cond": [{"$gt": ["$tx_count", 0]}, 1, 0]}},
                "total": {"$sum": 1}
            }
        }]
        agg = list(db.addresses.aggregate(pipeline))
        if agg:
            row = agg[0]
            result["thresholds"] = {k: int(v) for k, v in row.items() if k.startswith("gt_")}
            result["balances"]["overall"] = int(row.get("with_balance", 0))
            result["recent_usage"]["overall_active"] = int(row.get("active", 0))
            result["recent_usage"]["total_addresses"] = int(row.get("total", 0))

        def ts_minus(days=0, hours=0, minutes=0):
            return now - (days*86400 + hours*3600 + minutes*60)

        windows = {
            "past_hour": ts_minus(hours=1),
            "past_day": ts_minus(days=1),
            "past_week": ts_minus(days=7),
            "past_month": ts_minus(days=30),
            "past_year": ts_minus(days=365),
        }
        recent = {}
        for name, ts in windows.items():
            cur = db.addresses.count_documents({"last_seen": {"$gte": ts}, "tx_count": {"$gt": 0}})
            with_bal = db.addresses.count_documents({"balance": {"$gt": 0}, "last_seen": {"$gte": ts}})
            recent[name] = {"active": int(cur), "with_balance": int(with_bal)}
        result["recent_usage"] = recent

    except Exception as e:
        result["error"] = f"db_query_failed:{type(e).__name__}"

    return JSONResponse(result)
