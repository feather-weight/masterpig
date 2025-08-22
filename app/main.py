from fastapi import FastAPI, Form
from fastapi.responses import (
    PlainTextResponse,
    HTMLResponse,
    JSONResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Dict, Any
import asyncio, time, inspect, json
import aiohttp

from dotenv import load_dotenv

from .scanner import Scanner, THRESHOLDS, _ctx_from_xpub
from .keygen import derive_extended_keys, first_xpub, generate_random_hex
from .db import get_db
from .providers import (
    fetch_transactions,
    infura_get_eth_info,
    blockchair_address_info,
    ProviderError,
)

app = FastAPI()

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
STATIC_DIR = WEB_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

scanner: Scanner | None = None
scan_task: asyncio.Task | None = None

load_dotenv()


async def gather_key_info(hex_key: str, chain: str) -> Dict[str, Any]:
    """Return detailed information for ``hex_key`` including provider data."""

    keys = derive_extended_keys(hex_key)
    result: Dict[str, Any] = {
        "hex": hex_key,
        "private_key": f"0x{int(hex_key, 16):x}",
        "keys": {
            "xprv": keys.get("xprv"),
            "xpub": keys.get("xpub"),
            "yprv": keys.get("yprv"),
            "ypub": keys.get("ypub"),
            "zprv": keys.get("zprv"),
            "zpub": keys.get("zpub"),
            "seed": "N/A",
        },
        "Blockchair Data": None,
        "Tatum Data": None,
        "Infura Data": None,
        "electrum": {},
    }

    async with aiohttp.ClientSession() as session:
        if chain == "btc":
            electrum: Dict[str, Any] = {}
            if keys.get("xpub"):
                ctx = _ctx_from_xpub(keys["xpub"], "btc")
                addr = ctx.AddressIndex(0).PublicAddress()
                try:
                    txs = await fetch_transactions(session, addr)
                except ProviderError:
                    txs = []
                electrum["p2pkh"] = {
                    "address": addr,
                    "balance": 0,
                    "tx_count": len(txs),
                    "history": [
                        {
                            "height": tx.get("block_height") or tx.get("blockNumber") or 0,
                            "tx_hash": tx.get("txid") or tx.get("hash") or tx.get("tx_hash"),
                        }
                        for tx in txs[:2]
                    ],
                }
                try:
                    result["Blockchair Data"] = await blockchair_address_info(session, addr)
                except Exception:
                    result["Blockchair Data"] = {}
                result["Tatum Data"] = txs
            if keys.get("zpub"):
                ctx = _ctx_from_xpub(keys["zpub"], "btc")
                addr = ctx.AddressIndex(0).PublicAddress()
                try:
                    txs2 = await fetch_transactions(session, addr)
                except ProviderError:
                    txs2 = []
                electrum["p2wpkh"] = {
                    "address": addr,
                    "balance": 0,
                    "tx_count": len(txs2),
                    "history": [
                        {
                            "height": tx.get("block_height") or tx.get("blockNumber") or 0,
                            "tx_hash": tx.get("txid") or tx.get("hash") or tx.get("tx_hash"),
                        }
                        for tx in txs2[:2]
                    ],
                }
                if result["Tatum Data"] in (None, []):
                    result["Tatum Data"] = txs2
                if result["Blockchair Data"] in (None, {}):
                    try:
                        result["Blockchair Data"] = await blockchair_address_info(session, addr)
                    except Exception:
                        result["Blockchair Data"] = {}
            result["Infura Data"] = "N/A"
            result["electrum"] = electrum
        elif chain == "eth":
            if keys.get("xpub"):
                ctx = _ctx_from_xpub(keys["xpub"], "eth")
                addr = ctx.AddressIndex(0).PublicAddress()
                try:
                    info = await infura_get_eth_info(session, addr)
                except ProviderError:
                    info = {"balance": 0, "tx_count": 0}
                result["Infura Data"] = info
                result["electrum"] = {
                    "eth": {
                        "address": addr,
                        "balance": info.get("balance", 0),
                        "tx_count": info.get("tx_count", 0),
                        "history": [],
                    }
                }
            result["Blockchair Data"] = "N/A"
            result["Tatum Data"] = "N/A"

    return result

@app.get("/health", response_class=PlainTextResponse)
async def health():
    return "ok"

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return index_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>App is running</h1>", status_code=200)


@app.get("/range_stream")
async def range_stream(start: str, end: str, chain: str = "btc"):
    """Stream generated keys within ``start``-``end`` range as SSE."""

    try:
        s = int(start, 16)
        e = int(end, 16)
    except ValueError:
        return PlainTextResponse("invalid_range", status_code=400)
    if s > e:
        return PlainTextResponse("invalid_range", status_code=400)

    async def event_gen():
        for val in range(s, e + 1):
            hex_key = f"{val:064x}"
            data = await gather_key_info(hex_key, chain)
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(0)

    return StreamingResponse(event_gen(), media_type="text/event-stream")

@app.post("/start_scan")
async def start_scan(
    mode: str | None = Form(None),
    start: str | None = Form(None),
    end: str | None = Form(None),
    input: str | None = Form(None),
    xpub: str | None = Form(None),
    hex_key: str | None = Form(None),
    max_gap: int = 20,
    concurrency: int = 16,
    follow_depth: int = 2,
    chain: str = "btc",
):
    global scanner, scan_task
    if scan_task and not scan_task.done():
        return {"status": "already_running"}

    if not (xpub or hex_key) and mode:
        m = mode.lower()
        if m == "random":
            hex_key = generate_random_hex()
        elif m == "range":
            if start is None or end is None:
                return {"status": "no_query"}
            try:
                s = int(start, 16)
                e = int(end, 16)
            except ValueError:
                return {"status": "invalid_range"}
            if s > e:
                return {"status": "invalid_range"}
            hex_key = f"{s:064x}"
        elif m == "specific":
            if not input:
                return {"status": "no_query"}
            val = input.strip()
            try:
                int(val, 16)
                is_hex = len(val) <= 64
            except ValueError:
                is_hex = False
            if is_hex:
                hex_key = val
            else:
                xpub = val
        else:
            return {"status": "no_query"}

    info: Dict[str, Any] = {}
    if hex_key and not xpub:
        info = await gather_key_info(hex_key, chain)
        xpub = info["keys"].get("xpub") if chain == "eth" else first_xpub(info["keys"])
        if not xpub:
            return {"status": "invalid_key", **info}

    if not xpub:
        return {"status": "no_xpub", **info}

    scanner = Scanner(max_gap=max_gap, concurrency=concurrency, follow_depth=follow_depth, chain=chain)
    scanner.stats.update({"private_key": info.get("private_key", "")})
    if info:
        try:
            db_get = get_db
            db = await db_get() if inspect.iscoroutinefunction(db_get) else db_get()
            if db is not None:
                await asyncio.to_thread(
                    db.keys.insert_one,
                    {"started_at": int(time.time()), "chain": chain, **info},
                )
        except Exception:
            pass

    scan_task = asyncio.create_task(scanner.scan_xpub(xpub))
    return {"status": "started", **info}

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
