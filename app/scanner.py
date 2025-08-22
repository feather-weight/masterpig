"""Asynchronous recursive blockchain scanner.

The scanner derives addresses from an extended public key (xpub/ypub/zpub)
and fetches their transaction history via the provider layer. Any output
addresses encountered are queued for a recursive scan up to a configurable
depth. Results are optionally stored in MongoDB in batches which keeps the
number of write operations low.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Deque, Dict, Iterable, List, Set, Tuple

import aiohttp
from bip_utils import (
    Bip44,
    Bip49,
    Bip84,
    Bip44Coins,
    Bip44Changes,
)

from .providers import fetch_transactions, ProviderError
from .db import get_db

THRESHOLDS = [1, 2, 5, 10, 50]


def _ctx_from_xpub(xpub: str):
    """Return a bip-utils context for deriving addresses from ``xpub``."""

    if xpub.startswith("ypub"):
        return Bip49.FromExtendedKey(xpub, Bip44Coins.BITCOIN).Change(Bip44Changes.CHAIN_EXT)
    if xpub.startswith("zpub"):
        return Bip84.FromExtendedKey(xpub, Bip44Coins.BITCOIN).Change(Bip44Changes.CHAIN_EXT)
    if xpub.startswith("tpub"):
        return Bip44.FromExtendedKey(xpub, Bip44Coins.BITCOIN_TESTNET).Change(Bip44Changes.CHAIN_EXT)
    # Default to BIP44 xpub
    return Bip44.FromExtendedKey(xpub, Bip44Coins.BITCOIN).Change(Bip44Changes.CHAIN_EXT)


class Scanner:
    def __init__(self, max_gap: int = 20, concurrency: int = 16, follow_depth: int = 2):
        self.max_gap = max_gap
        self.concurrency = concurrency
        self.follow_depth = follow_depth
        self._stop = False

        self.stats: Dict[str, int] = {
            "addresses_scanned": 0,
            "active_addresses": 0,
            "with_balance": 0,
        }
        for t in THRESHOLDS:
            self.stats[f"tx_gt_{t}"] = 0

        self._seen: Set[str] = set()
        self._queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        self._batch: List[Dict] = []
        self._address_times: Deque[int] = deque(maxlen=10_000)

        self.db = get_db()

    # ------------------------------------------------------------------
    async def _flush_batch(self):
        if not self.db or not self._batch:
            return
        batch = self._batch
        self._batch = []
        await asyncio.to_thread(self.db.addresses.insert_many, batch, ordered=False)

    async def _store(self, info: Dict):
        self._batch.append(info)
        if len(self._batch) >= 50:
            await self._flush_batch()

    # ------------------------------------------------------------------
    async def _handle_address(self, session: aiohttp.ClientSession, address: str, depth: int) -> int:
        """Fetch transactions for ``address`` and update stats.

        Returns the number of transactions found.
        """

        try:
            txs = await fetch_transactions(session, address)
        except ProviderError:
            return 0

        self.stats["addresses_scanned"] += 1
        self._address_times.append(int(time.time()))

        tx_count = len(txs)
        if tx_count > 0:
            self.stats["active_addresses"] += 1
            for t in THRESHOLDS:
                if tx_count > t:
                    self.stats[f"tx_gt_{t}"] += 1

        # Balance and next addresses
        balance = 0
        next_addrs: Set[str] = set()
        for tx in txs:
            for out in tx.get("outputs", []):
                addr = out.get("address")
                val = int(out.get("value", 0))
                balance += val if addr == address else 0
                if addr and addr not in self._seen:
                    next_addrs.add(addr)

        if balance > 0:
            self.stats["with_balance"] += 1

        if self.db is not None:
            await self._store(
                {
                    "address": address,
                    "tx_count": tx_count,
                    "balance": balance,
                    "last_seen": int(time.time()),
                }
            )

        if depth < self.follow_depth:
            for addr in next_addrs:
                if addr not in self._seen:
                    self._seen.add(addr)
                    await self._queue.put((addr, depth + 1))

        return tx_count

    # ------------------------------------------------------------------
    async def _worker(self, session: aiohttp.ClientSession):
        while not self._stop:
            try:
                addr, depth = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if self._stop:
                    break
                continue
            try:
                await self._handle_address(session, addr, depth)
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    async def scan_xpub(self, xpub: str):
        ctx = _ctx_from_xpub(xpub)
        async with aiohttp.ClientSession() as session:
            workers = [asyncio.create_task(self._worker(session)) for _ in range(self.concurrency)]

            index = 0
            gap = 0
            while not self._stop and gap < self.max_gap:
                address = ctx.AddressIndex(index).PublicAddress()
                index += 1

                txs = await self._handle_address(session, address, 0)
                if txs:
                    gap = 0
                else:
                    gap += 1

            await self._queue.join()
            self._stop = True
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            await self._flush_batch()
        return True

    def stop(self):
        self._stop = True

    # Expose address timestamps for stats when no DB is configured
    @property
    def address_times(self) -> List[int]:
        return list(self._address_times)


__all__ = ["Scanner", "THRESHOLDS"]

