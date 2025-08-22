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


def _infura_url() -> str:
    """Return the Infura endpoint for Ethereum mainnet.

    The function reads ``INFURA_PROJECT_ID`` from the environment and
    constructs the JSON-RPC URL. A missing project ID results in an empty
    string which the caller should treat as a configuration error.
    """

    project_id = os.getenv("INFURA_PROJECT_ID")
    return f"https://mainnet.infura.io/v3/{project_id}" if project_id else ""


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
    """Fetch Bitcoin transactions for ``address`` using Tatum."""

    return await tatum_get_transactions(session, address)


async def infura_get_eth_info(session: aiohttp.ClientSession, address: str) -> Dict[str, int]:
    """Return basic information for an Ethereum ``address`` using Infura.

    Infura does not expose a dedicated "transactions for address" endpoint
    like Tatum. Instead we query the balance and transaction count via JSON-
    RPC which can be used for lightweight scans.
    """

    url = _infura_url()
    if not url:
        raise ProviderError("infura_project_id_missing")

    payloads = [
        {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1},
        {"jsonrpc": "2.0", "method": "eth_getTransactionCount", "params": [address, "latest"], "id": 2},
    ]

    results: Dict[str, int] = {"balance": 0, "tx_count": 0}
    for payload in payloads:
        async with session.post(url, json=payload, timeout=30) as resp:
            if resp.status != 200:
                raise ProviderError(f"infura_status_{resp.status}")
            data = await resp.json()

        if "error" in data:
            raise ProviderError("infura_error")

        value = data.get("result", "0x0")
        if payload["method"] == "eth_getBalance":
            results["balance"] = int(value, 16)
        else:
            results["tx_count"] = int(value, 16)

    return results


__all__ = ["fetch_transactions", "infura_get_eth_info", "ProviderError"]

