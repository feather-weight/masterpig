"""Blockchain data providers used by the scanner.

Currently only the Tatum API is implemented for full transaction
history lookups, but the module is structured so additional providers
can be added easily (e.g. Infura, Blockchair).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import aiohttp

TATUM_API = "https://api.tatum.io/v3"


class ProviderError(Exception):
    """Raised when an upstream provider returns an unexpected result."""


async def tatum_get_transactions(session: aiohttp.ClientSession, address: str) -> List[Dict[str, Any]]:
    """Return the list of transactions for ``address`` using Tatum.

    The function wraps the ``GET /bitcoin/transaction/address`` endpoint and
    normalises the result to a simple list of transactions. Only the first
    page of results is retrieved to keep the call lightweight; callers are
    free to implement pagination if required.
    """

    api_key = os.getenv("TATUM_API_KEY")
    headers = {"x-api-key": api_key} if api_key else {}
    url = f"{TATUM_API}/bitcoin/transaction/address/{address}"
    params = {"pageSize": 50}

    async with session.get(url, headers=headers, params=params, timeout=30) as resp:
        if resp.status != 200:
            raise ProviderError(f"tatum_status_{resp.status}")
        data = await resp.json()

    # Tatum returns {"txs": [...]} for this endpoint
    if isinstance(data, dict) and "txs" in data:
        return data.get("txs", [])
    if isinstance(data, list):
        return data
    raise ProviderError("tatum_invalid_response")


async def fetch_transactions(session: aiohttp.ClientSession, address: str) -> List[Dict[str, Any]]:
    """Fetch transactions for ``address`` using the configured providers.

    At the moment this simply proxies to :func:`tatum_get_transactions`, but
    the wrapper makes it trivial to add fallback/alternative providers such as
    Infura in the future.
    """

    return await tatum_get_transactions(session, address)


__all__ = ["fetch_transactions", "ProviderError"]

