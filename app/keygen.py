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

from bip_utils import Bip32KeyNetVersions, Bip32Slip10Secp256k1

# ---------------------------------------------------------------------------
# Network versions for different extended key prefixes
_KEY_VERSIONS: Dict[str, Bip32KeyNetVersions] = {
    # mainnet
    "x": Bip32KeyNetVersions(b"\x04\x88\xAD\xE4", b"\x04\x88\xB2\x1E"),
    "y": Bip32KeyNetVersions(b"\x04\x9D\x78\x78", b"\x04\x9D\x7C\xB2"),
    "z": Bip32KeyNetVersions(b"\x04\xB2\x43\x0C", b"\x04\xB2\x47\x46"),
    # testnet
    "t": Bip32KeyNetVersions(b"\x04\x35\x83\x94", b"\x04\x35\x87\xCF"),
    "u": Bip32KeyNetVersions(b"\x04\x4A\x4E\x28", b"\x04\x4A\x52\x62"),
}

# ---------------------------------------------------------------------------

def derive_extended_keys(hex_key: str) -> Dict[str, str]:
    """Derive extended private/public keys from a 64-character hex string."""

    key_bytes = bytes.fromhex(hex_key)
    results: Dict[str, str] = {}
    for prefix, net_ver in _KEY_VERSIONS.items():
        ctx = Bip32Slip10Secp256k1.FromPrivateKey(key_bytes, key_net_ver=net_ver)
        results[f"{prefix}prv"] = ctx.PrivateKey().ToExtended()
        results[f"{prefix}pub"] = ctx.PublicKey().ToExtended()
    return results

# ---------------------------------------------------------------------------

async def main() -> None:
    print("Select scan type: [specific] / [range] / [random]")
    mode = input("Mode: ").strip().lower()

    hex_values = []
    if mode == "specific":
        hv = input("Enter 64-char hexadecimal value: ").strip()
        hex_values = [hv]
    elif mode == "range":
        start = int(input("Start hex: "), 16)
        end = int(input("End   hex: "), 16)
        for val in range(start, end + 1):
            hex_values.append(f"{val:064x}")
    elif mode == "random":
        count = int(input("How many random keys? "))
        for _ in range(count):
            hex_values.append(secrets.token_hex(32))
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
            xpub = keys.get("xpub") or keys.get("tpub")
            if xpub:
                from .scanner import Scanner

                print("  Initiating BTC scan for", xpub)
                scanner = Scanner()
                try:
                    await scanner.scan_xpub(xpub)
                except Exception as exc:  # pragma: no cover - best effort
                    print("  scan failed:", exc)


if __name__ == "__main__":
    asyncio.run(main())
