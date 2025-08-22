"""Blockchain data providers used by the scanner.

Currently the Tatum API is implemented for full transaction history
lookups, but the module is structured so additional providers can be added
(e.g. Infura, Electrum) if required.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import aiohttp

TATUM_API = "https://api.tatum.io/v3"


class ProviderError(Exception):
    """Raised when an upstream provider returns an unexpected result."""


async def tatum_get_transactions(session: aiohttp.ClientSession, address: str) -> List[Dict[str, Any]]:
    """Return the full list of transactions for ``address`` using Tatum.

    The function wraps the ``GET /bitcoin/transaction/address`` endpoint and
    normalises the result to a simple list of transactions. All pages are
    retrieved by iterating over the ``page`` parameter until no results are
    returned.
    """

    api_key = os.getenv("TATUM_API_KEY")
    headers = {"x-api-key": api_key} if api_key else {}
    url = f"{TATUM_API}/bitcoin/transaction/address/{address}"

    transactions: List[Dict[str, Any]] = []
    page = 1
    page_size = 50

    while True:
        params = {"pageSize": page_size, "page": page}
        async with session.get(url, headers=headers, params=params, timeout=30) as resp:
            if resp.status != 200:
                raise ProviderError(f"tatum_status_{resp.status}")
            data = await resp.json()

        if isinstance(data, dict) and "txs" in data:
            txs = data.get("txs", [])
        elif isinstance(data, list):
            txs = data
        else:
            raise ProviderError("tatum_invalid_response")

        if not txs:
            break

        transactions.extend(txs)
        page += 1

    return transactions


async def fetch_transactions(session: aiohttp.ClientSession, address: str) -> List[Dict[str, Any]]:
    """Fetch transactions for ``address`` using the configured providers.

    At the moment this proxies to :func:`tatum_get_transactions`, but the
    wrapper makes it easy to add fallback providers such as Infura or
    Electrum in the future.
    """

    return await tatum_get_transactions(session, address)


__all__ = ["fetch_transactions", "ProviderError"]

