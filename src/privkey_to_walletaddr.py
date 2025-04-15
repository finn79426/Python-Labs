import argparse
from hashlib import sha256

import base58
from eth_keys import keys
from eth_utils import keccak
from eth_utils.address import to_checksum_address

# uv run src/privkey_to_walletaddr.py b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291

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
assert (
    len(PRIVATE_KEY_HEX) == 64
), "Invalid private key length. Must be 64 hex characters."

# Convert the hex string to bytes
private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)

# Generate the private key and public key
private_key = keys.PrivateKey(private_key_bytes)
public_key = private_key.public_key

# Generate the Ethereum address
pubkey_bytes = public_key.to_bytes()
address_bytes = keccak(pubkey_bytes)[-20:]

# Add '0x' prefix to the address
eth_address = "0x" + address_bytes.hex()

# Convert to checksum address
eth_address_checksum = to_checksum_address(eth_address)

# Convert to Tron address
tron_hex = "41" + address_bytes.hex()
tron_bytes = bytes.fromhex(tron_hex)
tron_checksum = sha256(sha256(tron_bytes).digest()).digest()[:4]
tron_address_checksum = base58.b58encode(tron_bytes + tron_checksum).decode()

# ---------------------------------------------------------------------------------

print("Private Key:", PRIVATE_KEY_HEX)
print("Ethereum Address:", eth_address_checksum)
print("Tron Address:", tron_address_checksum)
