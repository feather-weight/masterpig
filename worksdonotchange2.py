import struct
import asyncio
import base58
import json
import ssl
import hashlib
import secrets  # for random key generation
from hashlib import sha256
from bip_utils import Bip32Secp256k1
import aiohttp
from pymongo import MongoClient

#########################
# MongoDB Configuration #
#########################

MONGO_CLIENT = MongoClient("ENV_MONGO_URI")  # Use environment variable for security
DB = MONGO_CLIENT["extended_keys_db"]
COLLECTION = DB["keys_new"]

######################
# Vezgo Credentials  #
######################

VEZGO_CLIENT_ID = "env_vezgo_client_id"  # Use environment variable for security
VEZGO_CLIENT_SECRET = "env_vezgo_client_secret"  # Use environment variable for security
VEZGO_LOGIN_NAME = "env_vezgo_login_name"  # Use environment variable for security
VEZGO_AUTH_URL = "ENV_VEZGO_AUTH_URL"  # Use environment variable for security
VEZGO_BALANCE_URL = "ENV_VEZGO_BALANCE_URL"  # Use environment variable for security

vezgo_access_token = None  # Global token holder

##################
# Extended Key   #
##################

PREFIXES = {
    "xprv": "0488ADE4",
    "xpub": "0488B21E",
    "yprv": "049D7878",
    "ypub": "049D7CB2",
    "zprv": "04B2430C",
    "zpub": "04B24746",
    "tprv": "04358394",
    "tpub": "043587CF",
}

#################################
# Bech32 / Bech32m Helper Functions
#################################

CHARSET = "ENV_CHARSET"  # Use environment variable for security

def bech32_polymod(values):
    chk = 1
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec="bech32"):
    values = bech32_hrp_expand(hrp) + data
    const = 1 if spec == "bech32" else 0x2bc830a3  # For Bech32m (Taproot) use BIP-350 constant.
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec="bech32"):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

######################
# Address Derivation #
######################

def hash160(data: bytes) -> bytes:
    """Return RIPEMD160(SHA256(data))."""
    return hashlib.new('ripemd160', sha256(data).digest()).digest()

def get_p2pkh_address_and_script(pubkey_bytes: bytes, network_ver=b'\x00'):
    pubkey_hash = hash160(pubkey_bytes)
    versioned_payload = network_ver + pubkey_hash
    checksum = sha256(sha256(versioned_payload).digest()).digest()[:4]
    address = base58.b58encode(versioned_payload + checksum).decode()
    # P2PKH locking script: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    return address, script

def get_p2wpkh_address_and_script(pubkey_bytes: bytes, hrp="bc"):
    pubkey_hash = hash160(pubkey_bytes)
    data = [0] + convertbits(list(pubkey_hash), 8, 5, pad=True)
    address = bech32_encode(hrp, data, spec="bech32")
    # P2WPKH locking script: 0x00 followed by 0x14 <pubkey_hash>
    script = b'\x00\x14' + pubkey_hash
    return address, script

def get_p2sh_p2wpkh_address_and_script(pubkey_bytes: bytes):
    pubkey_hash = hash160(pubkey_bytes)
    redeem_script = b'\x00\x14' + pubkey_hash
    redeem_hash = hash160(redeem_script)
    versioned_payload = b'\x05' + redeem_hash  # For mainnet P2SH
    checksum = sha256(sha256(versioned_payload).digest()).digest()[:4]
    address = base58.b58encode(versioned_payload + checksum).decode()
    # P2SH locking script: OP_HASH160 <redeem_hash> OP_EQUAL
    script = b'\xa9\x14' + redeem_hash + b'\x87'
    return address, script

def get_p2tr_address_and_script(pubkey_bytes: bytes, hrp="bc"):
    """
    Taproot (P2TR) address:
     - Use the x-only public key (drop the first byte of the compressed pubkey).
     - Uses witness version 1 and Bech32m encoding.
     - Locking script: OP_1 followed by a push of the 32-byte x-only pubkey.
    """
    x_only_pubkey = pubkey_bytes[1:]
    data = [1] + convertbits(list(x_only_pubkey), 8, 5, pad=True)
    address = bech32_encode(hrp, data, spec="bech32m")
    script = b'\x51\x20' + x_only_pubkey
    return address, script

#####################################
# Helper for Reversed Script Hash
#####################################

def compute_reversed_scripthash(script: bytes) -> str:
    scripthash = sha256(script).digest()
    scripthash_hex = scripthash.hex()
    reversed_scripthash = ''.join([scripthash_hex[i:i+2] for i in range(0, len(scripthash_hex), 2)][::-1])
    return reversed_scripthash

#####################################
# Electrum Server Query Functions   #
#####################################

async def fetch_electrum_method(method: str, reversed_scripthash: str, label: str):
    try:
        reader, writer = await asyncio.open_connection(
            'electrum.blockstream.info', 50002, ssl=ssl.create_default_context()
        )
        request = {"id": 0, "method": method, "params": [reversed_scripthash]}
        request_str = json.dumps(request) + "\n"
        writer.write(request_str.encode())
        await writer.drain()
        response_line = await reader.readline()
        writer.close()
        await writer.wait_closed()
        response = json.loads(response_line.decode())
        return response.get("result", None)
    except Exception as e:
        print(f"❌ Electrum query error for {label} using {method}: {e}")
        return None

async def fetch_electrum_data_for_script(script: bytes, label: str):
    reversed_sh = compute_reversed_scripthash(script)
    balance_task = asyncio.create_task(fetch_electrum_method("blockchain.scripthash.get_balance", reversed_sh, label))
    history_task = asyncio.create_task(fetch_electrum_method("blockchain.scripthash.get_history", reversed_sh, label))
    balance_result, history_result = await asyncio.gather(balance_task, history_task)
    balance = 0
    tx_count = 0
    if isinstance(balance_result, dict):
        balance = balance_result.get("confirmed", 0)
    if isinstance(history_result, list):
        tx_count = len(history_result)
    print(f"💰 Electrum {label}: balance={balance}, tx_count={tx_count}")
    return {"balance": balance, "tx_count": tx_count, "history": history_result}

#####################################
# Vezgo API Helper Functions          #
#####################################

async def authenticate_vezgo(session):
    global vezgo_access_token
    headers = {"loginName": VEZGO_LOGIN_NAME, "Content-Type": "application/json"}
    data = {"clientId": VEZGO_CLIENT_ID, "secret": VEZGO_CLIENT_SECRET}
    async with session.post(VEZGO_AUTH_URL, headers=headers, json=data) as response:
        if response.status == 200:
            auth_response = await response.json()
            vezgo_access_token = auth_response.get("token")
            print("✅ Authenticated with Vezgo!")
        else:
            text = await response.text()
            print(f"❌ Vezgo Authentication Failed: {text}")

async def fetch_vezgo_balance(session, xpub):
    global vezgo_access_token
    if not vezgo_access_token:
        print("⚠️ Missing Vezgo token, authenticating...")
        await authenticate_vezgo(session)
    headers = {"Authorization": f"Bearer {vezgo_access_token}"}
    async with session.get(VEZGO_BALANCE_URL, headers=headers) as response:
        if response.status == 200:
            accounts = await response.json()
            for account in accounts:
                if account.get("address") == xpub:
                    balance = account.get("balance")
                    print(f"💰 Vezgo Balance for {xpub}: {balance}")
                    return balance
        else:
            text = await response.text()
            print(f"❌ Failed to fetch Vezgo balance for {xpub}: {text}")
    return None

#############################################
# Key Generation, Processing and Storage    #
#############################################

def serialize_extended_key(prefix, depth, parent_fingerprint, child_number, chain_code, key_data):
    header = bytes.fromhex(PREFIXES[prefix])
    components = (
        header +
        struct.pack("B", depth) +
        parent_fingerprint +
        struct.pack(">I", child_number) +
        chain_code +
        key_data
    )
    checksum = sha256(sha256(components).digest()).digest()[:4]
    return base58.b58encode(components + checksum)

def generate_root_keys(private_key_int, verbose=False):
    private_key_bytes = private_key_int.to_bytes(32, 'big')
    bip32_ctx = Bip32Secp256k1.FromPrivateKey(private_key_bytes)
    parent_fingerprint = b"\x00\x00\x00\x00"
    child_number = 0
    chain_code = bip32_ctx.ChainCode().ToBytes()
    private_key_with_prefix = b"\x00" + bip32_ctx.PrivateKey().Raw().ToBytes()
    xprv = serialize_extended_key("xprv", 0, parent_fingerprint, child_number, chain_code, private_key_with_prefix)
    public_key_bytes = bip32_ctx.PublicKey().RawCompressed().ToBytes()
    xpub = serialize_extended_key("xpub", 0, parent_fingerprint, child_number, chain_code, public_key_bytes)
    if verbose:
        print(f"🔑 Private Key: {hex(private_key_int)}")
        print(f"📜 XPUB: {xpub.decode()}")
        print(f"📜 XPRV: {xprv.decode()}")
    return {"xprv": xprv.decode(), "xpub": xpub.decode()}

def store_data_to_mongodb(data):
    try:
        COLLECTION.insert_one(data)
        print("✅ Data inserted into MongoDB")
    except Exception as e:
        print(f"❌ MongoDB Insert Error: {e}")

#####################################
# ANSI Color Helper Functions
#####################################

def format_balance(balance):
    # Zero balance: bold red; positive balance: bold bright yellow.
    if balance == 0:
        return f"\033[1;31m{balance}\033[0m"
    else:
        return f"\033[1;33m{balance}\033[0m"

def format_tx_count(tx_count):
    # Zero transactions: dim grey; nonzero: bold bright green.
    if tx_count == 0:
        return f"\033[90m{tx_count}\033[0m"
    else:
        return f"\033[1;32m{tx_count}\033[0m"

#####################################
# Deep Wallet Scan Functionality
#####################################

async def scan_derivation_range(xpub, deriv_func, deriv_name, start_index=0, end_index=5000, sem=None):
    results = []
    child_root = Bip32Secp256k1.FromExtendedKey(xpub)
    tasks = []

    async def process_index(i):
        async with sem:
            child = child_root.DerivePath(f"0/{i}")
            pubkey_bytes = child.PublicKey().RawCompressed().ToBytes()
            addr, script = deriv_func(pubkey_bytes)
            data = await fetch_electrum_data_for_script(script, f"{deriv_name} idx {i}")
            if data["tx_count"] > 0:
                rev_sh = compute_reversed_scripthash(script)
                history = await fetch_electrum_method("blockchain.scripthash.get_history", rev_sh, f"{deriv_name} idx {i}")
                return {
                    "index": i,
                    "address": addr,
                    "balance": data["balance"],
                    "tx_count": data["tx_count"],
                    "transactions": history if history is not None else []
                }
            else:
                return None

    for i in range(start_index, end_index + 1):
        tasks.append(asyncio.create_task(process_index(i)))
    scan_results = await asyncio.gather(*tasks)
    for r in scan_results:
        if r:
            results.append(r)
    return results

#####################################
# Processing Functions for a Key
#####################################

async def process_key(private_key_int, session, sem, verbose=False):
    async with sem:
        try:
            print(f"\n🔑 Processing Private Key: {hex(private_key_int)}")
            root_keys = generate_root_keys(private_key_int, verbose=verbose)
            xpub = root_keys["xpub"]
            # Vezgo query
            vezgo_task = asyncio.create_task(fetch_vezgo_balance(session, xpub))
            # Derive public key bytes for primary derivation (index 0)
            pubkey_bytes = Bip32Secp256k1.FromExtendedKey(xpub).PublicKey().RawCompressed().ToBytes()
            # Derive addresses (default index 0)
            p2pkh_addr, p2pkh_script = get_p2pkh_address_and_script(pubkey_bytes)
            p2wpkh_addr, p2wpkh_script = get_p2wpkh_address_and_script(pubkey_bytes)
            p2sh_addr, p2sh_script = get_p2sh_p2wpkh_address_and_script(pubkey_bytes)
            taproot_addr, taproot_script = get_p2tr_address_and_script(pubkey_bytes)
            # Query Electrum concurrently for each derivation type
            electrum_p2pkh = asyncio.create_task(fetch_electrum_data_for_script(p2pkh_script, f"P2PKH: {p2pkh_addr}"))
            electrum_p2wpkh = asyncio.create_task(fetch_electrum_data_for_script(p2wpkh_script, f"P2WPKH: {p2wpkh_addr}"))
            electrum_p2sh = asyncio.create_task(fetch_electrum_data_for_script(p2sh_script, f"P2SH-P2WPKH: {p2sh_addr}"))
            electrum_p2tr = asyncio.create_task(fetch_electrum_data_for_script(taproot_script, f"Taproot: {taproot_addr}"))
            vezgo_balance, e_p2pkh, e_p2wpkh, e_p2sh, e_p2tr = await asyncio.gather(
                vezgo_task, electrum_p2pkh, electrum_p2wpkh, electrum_p2sh, electrum_p2tr
            )
            data_to_store = {
                "private_key": hex(private_key_int),
                "keys": root_keys,
                "vezgo_balance": vezgo_balance,
                "electrum": {
                    "p2pkh": {"address": p2pkh_addr, "balance": e_p2pkh["balance"], "tx_count": e_p2pkh["tx_count"], "history": e_p2pkh["history"]},
                    "p2wpkh": {"address": p2wpkh_addr, "balance": e_p2wpkh["balance"], "tx_count": e_p2wpkh["tx_count"], "history": e_p2wpkh["history"]},
                    "p2sh": {"address": p2sh_addr, "balance": e_p2sh["balance"], "tx_count": e_p2sh["tx_count"], "history": e_p2sh["history"]},
                    "p2tr": {"address": taproot_addr, "balance": e_p2tr["balance"], "tx_count": e_p2tr["tx_count"], "history": e_p2tr["history"]}
                }
            }
            store_data_to_mongodb(data_to_store)
            return data_to_store
        except Exception as e:
            print(f"❌ Error processing {hex(private_key_int)}: {e}")
            return None

#####################################
# Specific Mode Processing Function
#####################################

async def process_specific_key(input_value, session, sem, verbose=False):
    async with sem:
        try:
            if input_value.startswith("xpub"):
                xpub = input_value
                root_keys = {"xpub": xpub, "xprv": "N/A"}
                pubkey_bytes = Bip32Secp256k1.FromExtendedKey(xpub).PublicKey().RawCompressed().ToBytes()
            else:
                hex_str = input_value[2:] if input_value.startswith("0x") else input_value
                if len(hex_str) != 64:
                    raise ValueError("Private key must be 32 bytes in hex (64 characters).")
                key_int = int(hex_str, 16)
                root_keys = generate_root_keys(key_int, verbose=verbose)
                xpub = root_keys["xpub"]
                pubkey_bytes = Bip32Secp256k1.FromExtendedKey(xpub).PublicKey().RawCompressed().ToBytes()
            # Vezgo query.
            vezgo_task = asyncio.create_task(fetch_vezgo_balance(session, xpub))
            # Primary derivation (index 0)
            p2pkh_addr, p2pkh_script = get_p2pkh_address_and_script(pubkey_bytes)
            p2wpkh_addr, p2wpkh_script = get_p2wpkh_address_and_script(pubkey_bytes)
            p2sh_addr, p2sh_script = get_p2sh_p2wpkh_address_and_script(pubkey_bytes)
            taproot_addr, taproot_script = get_p2tr_address_and_script(pubkey_bytes)
            electrum_p2pkh = asyncio.create_task(fetch_electrum_data_for_script(p2pkh_script, f"P2PKH: {p2pkh_addr}"))
            electrum_p2wpkh = asyncio.create_task(fetch_electrum_data_for_script(p2wpkh_script, f"P2WPKH: {p2wpkh_addr}"))
            electrum_p2sh = asyncio.create_task(fetch_electrum_data_for_script(p2sh_script, f"P2SH-P2WPKH: {p2sh_addr}"))
            electrum_p2tr = asyncio.create_task(fetch_electrum_data_for_script(taproot_script, f"Taproot: {taproot_addr}"))
            vezgo_balance, e_p2pkh, e_p2wpkh, e_p2sh, e_p2tr = await asyncio.gather(
                vezgo_task, electrum_p2pkh, electrum_p2wpkh, electrum_p2sh, electrum_p2tr
            )
            result = {
                "input": input_value,
                "keys": root_keys,
                "vezgo_balance": vezgo_balance,
                "electrum": {
                    "p2pkh": {"address": p2pkh_addr, "balance": e_p2pkh["balance"], "tx_count": e_p2pkh["tx_count"], "history": e_p2pkh["history"]},
                    "p2wpkh": {"address": p2wpkh_addr, "balance": e_p2wpkh["balance"], "tx_count": e_p2wpkh["tx_count"], "history": e_p2wpkh["history"]},
                    "p2sh": {"address": p2sh_addr, "balance": e_p2sh["balance"], "tx_count": e_p2sh["tx_count"], "history": e_p2sh["history"]},
                    "p2tr": {"address": taproot_addr, "balance": e_p2tr["balance"], "tx_count": e_p2tr["tx_count"], "history": e_p2tr["history"]}
                }
            }
            store_data_to_mongodb(result)

            # --- Deep scan if any primary derivation shows transactions ---
            deep_scan = {}
            sem_deep = asyncio.Semaphore(10)
            # For each derivation type, if there is any transaction, scan child indexes 0..5000.
            if result["electrum"]["p2pkh"]["tx_count"] > 0:
                deep_scan["p2pkh"] = await scan_derivation_range(xpub, get_p2pkh_address_and_script, "P2PKH", 0, 5000, sem_deep)
            if result["electrum"]["p2wpkh"]["tx_count"] > 0:
                deep_scan["p2wpkh"] = await scan_derivation_range(xpub, get_p2wpkh_address_and_script, "P2WPKH", 0, 5000, sem_deep)
            if result["electrum"]["p2sh"]["tx_count"] > 0:
                deep_scan["p2sh"] = await scan_derivation_range(xpub, get_p2sh_p2wpkh_address_and_script, "P2SH", 0, 5000, sem_deep)
            if result["electrum"]["p2tr"]["tx_count"] > 0:
                deep_scan["p2tr"] = await scan_derivation_range(xpub, get_p2tr_address_and_script, "P2TR", 0, 5000, sem_deep)
            result["deep_scan"] = deep_scan
            return result
        except Exception as e:
            print(f"❌ Error processing input {input_value}: {e}")
            return None

#####################################
# Mode Functions: Range, Random, Specific
#####################################

async def iterate_range_mode(start_int, end_int, verbose=False):
    sem = asyncio.Semaphore(10)
    async with aiohttp.ClientSession() as session:
        await authenticate_vezgo(session)
        tasks = []
        for private_key_int in range(start_int, end_int + 1):
            tasks.append(process_key(private_key_int, session, sem, verbose=verbose))
        results = await asyncio.gather(*tasks)
        return results

async def producer(queue: asyncio.Queue):
    while True:
        random_key = secrets.randbelow(2**256)
        await queue.put(random_key)

async def worker(queue: asyncio.Queue, session, sem, verbose=False):
    while True:
        key = await queue.get()
        try:
            await process_key(key, session, sem, verbose=verbose)
        except Exception as e:
            print(f"Error in worker: {e}")
        queue.task_done()

async def iterate_random_mode(verbose=False):
    sem = asyncio.Semaphore(10)
    queue = asyncio.Queue(maxsize=100)
    async with aiohttp.ClientSession() as session:
        await authenticate_vezgo(session)
        workers = [asyncio.create_task(worker(queue, session, sem, verbose)) for _ in range(10)]
        prod = asyncio.create_task(producer(queue))
        print("🚀 Running in Random Mode. Press Ctrl+C to stop.")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            for w in workers:
                w.cancel()
            prod.cancel()
            await asyncio.gather(*workers, prod, return_exceptions=True)

async def iterate_specific_mode(input_value, verbose=False):
    sem = asyncio.Semaphore(10)
    async with aiohttp.ClientSession() as session:
        await authenticate_vezgo(session)
        result = await process_specific_key(input_value, session, sem, verbose=verbose)
        return result

#####################################
# Main Entry Point
#####################################

def main():
    mode = input("Select mode ('range' for iteration range, 'random' for random continuous, 'specific' for a specific key/xpub): ").strip().lower()
    try:
        if mode == "range":
            start_str = input("Enter start integer (in decimal or hex, e.g. 0x100): ").strip()
            end_str = input("Enter end integer: ").strip()
            start_int = int(start_str, 0)
            end_int = int(end_str, 0)
            asyncio.run(iterate_range_mode(start_int, end_int, verbose=True))
        elif mode == "random":
            try:
                asyncio.run(iterate_random_mode(verbose=True))
            except KeyboardInterrupt:
                print("🔴 Random mode stopped by user.")
        elif mode == "specific":
            specific_input = input("Enter a specific private key (64 hex characters, optionally prefixed with '0x') or xpub (starting with 'xpub'): ").strip()
            result = asyncio.run(iterate_specific_mode(specific_input, verbose=True))
            if result:
                print("\n📊 Specific Key Primary Results:")
                electrum = result.get("electrum", {})
                for derivation, data in electrum.items():
                    addr = data.get("address", "N/A")
                    balance = data.get("balance", 0)
                    tx_count = data.get("tx_count", 0)
                    print(f"{derivation.upper()} Address: {addr}")
                    print(f"  Balance: {format_balance(balance)}")
                    print(f"  Transactions: {format_tx_count(tx_count)}")
                # If deep_scan data exists, print it as prettified JSON.
                deep_scan = result.get("deep_scan", {})
                if deep_scan:
                    print("\n🕵️ Deep Scan Results (only addresses with transactions):")
                    print(json.dumps(deep_scan, indent=4))
        else:
            print("Invalid mode selected. Please choose 'range', 'random', or 'specific'.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
