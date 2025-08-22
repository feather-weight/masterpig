"""Interactive CLI for deriving extended keys from hexadecimal values.

This script mimics the original ``worksdonotchange2`` behaviour by
allowing the user to choose between scanning a specific hexadecimal key,
a range of keys, or a set of random keys. For each key the script
produces tprv/uprv/xprv/yprv/zprv extended private keys and their
corresponding public counterparts (tpub/upub/xpub/ypub/zpub).

The module does not perform any blockchain lookups directly; it is meant
as a helper utility to generate the keys that can then be fed into the
scanner or other components.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Dict

from bip_utils import (
    Bip32KeyNetVersions,
    Bip32Slip10Secp256k1,
    Secp256k1,
)

# ---------------------------------------------------------------------------
# Network versions for different extended key prefixes
_KEY_VERSIONS: Dict[str, Bip32KeyNetVersions] = {
    # mainnet (pub, priv)
    "x": Bip32KeyNetVersions(b"\x04\x88\xB2\x1E", b"\x04\x88\xAD\xE4"),
    "y": Bip32KeyNetVersions(b"\x04\x9D\x7C\xB2", b"\x04\x9D\x78\x78"),
    "z": Bip32KeyNetVersions(b"\x04\xB2\x47\x46", b"\x04\xB2\x43\x0C"),
    # testnet (pub, priv)
    "t": Bip32KeyNetVersions(b"\x04\x35\x87\xCF", b"\x04\x35\x83\x94"),
    "u": Bip32KeyNetVersions(b"\x04\x4A\x52\x62", b"\x04\x4A\x4E\x28"),
}

# ---------------------------------------------------------------------------
_ORDER = Secp256k1.Order()


def _is_valid_key(key_bytes: bytes) -> bool:
    """Return ``True`` if ``key_bytes`` represents a valid Secp256k1 key."""

    val = int.from_bytes(key_bytes, "big")
    return 0 < val < _ORDER


def generate_random_hex() -> str:
    """Return a random hexadecimal key within the Secp256k1 range."""

    val = secrets.randbelow(_ORDER - 1) + 1
    return f"{val:064x}"


def derive_extended_keys(hex_key: str) -> Dict[str, str]:
    """Derive extended private/public keys from a hexadecimal string.

    ``hex_key`` may be shorter than 64 characters; it will be left padded
    with zeros. Any invalid input results in an empty dict which allows the
    caller to gracefully handle errors without raising exceptions.
    """

    try:
        hex_key = hex_key.strip().lower().rjust(64, "0")[-64:]
        key_bytes = bytes.fromhex(hex_key)
    except ValueError:
        # ``bytes.fromhex`` raises ``ValueError`` for invalid hex strings.
        return {}

    if not _is_valid_key(key_bytes):
        return {}

    results: Dict[str, str] = {}
    for prefix, net_ver in _KEY_VERSIONS.items():
        try:
            ctx = Bip32Slip10Secp256k1.FromPrivateKey(key_bytes, key_net_ver=net_ver)
        except Exception:  # pragma: no cover - invalid key edge case
            return {}
        results[f"{prefix}prv"] = ctx.PrivateKey().ToExtended()
        results[f"{prefix}pub"] = ctx.PublicKey().ToExtended()
    return results


def first_xpub(keys: Dict[str, str]) -> str | None:
    """Return the first available extended public key from ``keys``.

    The function checks for the common prefixes (xpub, ypub, zpub, tpub, upub)
    and returns the first match. ``None`` is returned if none are found.
    """

    for k in ("xpub", "ypub", "zpub", "tpub", "upub"):
        if keys.get(k):
            return keys[k]
    return None

# ---------------------------------------------------------------------------

async def main() -> None:
    print("Select scan type: [specific] / [range] / [random]")
    mode = input("Mode: ").strip().lower()

    hex_values = []
    if mode == "specific":
        hv = input("Enter 64-char hexadecimal value: ").strip()
        hex_values = [hv]
    elif mode == "range":
        start = max(int(input("Start hex: "), 16), 1)
        end = min(int(input("End   hex: "), 16), _ORDER - 1)
        if start > end:
            print("Invalid range; exiting")
            return
        for val in range(start, end + 1):
            hex_values.append(f"{val:064x}")
    elif mode == "random":
        count = int(input("How many random keys? "))
        for _ in range(count):
            hex_values.append(generate_random_hex())
    else:
        print("Unknown mode; exiting")
        return

    print("Select blockchains to scan (comma separated, e.g. btc,eth) or 'all':")
    chains_input = input("Chains: ").strip().lower()
    chains = [c.strip() for c in chains_input.split(",") if c.strip()] if chains_input != "all" else ["all"]

    for hv in hex_values:
        keys = derive_extended_keys(hv)
        print(f"Hex: {hv}")
        for k, v in keys.items():
            print(f"  {k}: {v}")
        print()

        if "all" in chains or "btc" in chains:
            xpub = first_xpub(keys)
            if xpub:
                from .scanner import Scanner

                print("  Initiating BTC scan for", xpub)
                scanner = Scanner(chain="btc")
                try:
                    await scanner.scan_xpub(xpub)
                except Exception as exc:  # pragma: no cover - best effort
                    print("  scan failed:", exc)

        if "all" in chains or "eth" in chains:
            xpub = keys.get("xpub")
            if xpub:
                from .scanner import Scanner

                print("  Initiating ETH scan for", xpub)
                scanner = Scanner(chain="eth")
                try:
                    await scanner.scan_xpub(xpub)
                except Exception as exc:  # pragma: no cover - best effort
                    print("  scan failed:", exc)


if __name__ == "__main__":
    asyncio.run(main())
