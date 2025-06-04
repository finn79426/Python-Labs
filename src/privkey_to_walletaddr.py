import argparse
import hashlib
from hashlib import sha256

import base58
import ecdsa
from eth_utils import keccak
from eth_utils.address import to_checksum_address

# ---------------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Convert private key to wallet address")
parser.add_argument("private_key_hex", help="Private key in hex format")
args = parser.parse_args()

# ---------------------------------------------------------------------------------

PRIVATE_KEY_HEX = args.private_key_hex

# ---------------------------------------------------------------------------------

# Remove '0x' prefix if it exists
if PRIVATE_KEY_HEX.startswith("0x"):
    PRIVATE_KEY_HEX = PRIVATE_KEY_HEX[2:]

# Check if the length of the hex string is valid
assert len(PRIVATE_KEY_HEX) == 64, (
    "Invalid private key length. Must be 64 hexadecimal characters."
)

# ---------------------------------------------------------------------------------


def ripemd160(x: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(x)
    return h.digest()


def bech32_polymod(values):
    GENERATORS = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data, spec="bech32"):
    values = bech32_hrp_expand(hrp) + data
    const = 1 if spec == "bech32" else 0x2BC830A3
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec="bech32"):
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            return None
        acc = (acc << frombits) | b
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


# ---------------------------------------------------------------------------------


def priv_to_pub_secp256k1(private_key_hex: str, compressed: bool) -> bytes:
    assert not private_key_hex.startswith("0x")
    assert len(private_key_hex) == 64
    priv_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    else:
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---------------------------------------------------------------------------------


def priv_to_p2pkh(private_key_hex: str) -> str:
    pubkey = priv_to_pub_secp256k1(private_key_hex, compressed=True)
    pubkey_hash = ripemd160(sha256(pubkey).digest())
    prefix = b"\x00"
    payload = prefix + pubkey_hash
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address


def priv_to_p2sh_p2pkh(private_key_hex: str) -> str:
    pubkey = priv_to_pub_secp256k1(private_key_hex, compressed=True)
    pubkey_hash = ripemd160(sha256(pubkey).digest())
    redeem_script = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
    redeem_script_hash = ripemd160(sha256(redeem_script).digest())
    prefix = b"\x05"
    payload = prefix + redeem_script_hash
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address


def priv_to_p2wpkh(private_key_hex: str) -> str:
    pubkey = priv_to_pub_secp256k1(private_key_hex, compressed=True)
    pubkey_hash = ripemd160(sha256(pubkey).digest())
    # witness version 0 + program
    version = 0
    data = [version] + convertbits(pubkey_hash, 8, 5)
    return bech32_encode("bc", data, spec="bech32")


def priv_to_p2wsh(private_key_hex: str) -> str:
    pubkey = priv_to_pub_secp256k1(private_key_hex, compressed=True)
    witness_script = b"\x21" + pubkey + b"\xac"
    script_hash = sha256(witness_script).digest()
    version = 0
    data = [version] + convertbits(script_hash, 8, 5)
    return bech32_encode("bc", data, spec="bech32")


def priv_to_p2tr(private_key_hex: str) -> str:
    pubkey = priv_to_pub_secp256k1(private_key_hex, compressed=True)
    x_only_pubkey = pubkey[1:]
    version = 1
    data = [version] + convertbits(x_only_pubkey, 8, 5)
    return bech32_encode("bc", data, spec="bech32m")


def priv_to_ethereum(private_key_hex: str) -> str:
    public_key_bytes = priv_to_pub_secp256k1(private_key_hex, compressed=False)[1:]
    address_bytes = keccak(public_key_bytes)[-20:]
    eth_address = "0x" + address_bytes.hex()
    eth_address_checksum = to_checksum_address(eth_address)
    return eth_address_checksum


def priv_to_tron(private_key_hex: str) -> str:
    public_key_bytes = priv_to_pub_secp256k1(private_key_hex, compressed=False)[1:]
    address_bytes = keccak(public_key_bytes)[-20:]
    tron_hex = "41" + address_bytes.hex()
    tron_bytes = bytes.fromhex(tron_hex)
    tron_checksum = sha256(sha256(tron_bytes).digest()).digest()[:4]
    tron_address_checksum = base58.b58encode(tron_bytes + tron_checksum).decode()
    return tron_address_checksum


# ---------------------------------------------------------------------------------


print("🔑 Private Key:", PRIVATE_KEY_HEX)
print("Bitcoin Legacy (P2PKH):", priv_to_p2pkh(PRIVATE_KEY_HEX))
print("Bitcoin Nested Segwit (P2SH-P2WPKH):", priv_to_p2sh_p2pkh(PRIVATE_KEY_HEX))
print("Bitcoin Native Segwit (P2WPKH):", priv_to_p2wpkh(PRIVATE_KEY_HEX))
print("Bitcoin Native Segwit (P2WSH):", priv_to_p2wsh(PRIVATE_KEY_HEX))
print("Bitcoin Native Segwit v1 (P2TR):", priv_to_p2tr(PRIVATE_KEY_HEX))
print("Ethereum Address:", priv_to_ethereum(PRIVATE_KEY_HEX))
print("Tron Address:", priv_to_tron(PRIVATE_KEY_HEX))
