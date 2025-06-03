import argparse
import base64
import hashlib
import hmac
import os
import time

# ---------------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Get 2FA OTP code")
parser.add_argument(
    "two_fa_secret",
    help="2FA Secret Key",
    nargs="?",
    default=os.getenv("TWO_FA_SECRET"),
)
args = parser.parse_args()

# ---------------------------------------------------------------------------------

TWO_FA_SECRET_KEY: str = args.two_fa_secret

# ---------------------------------------------------------------------------------

assert TWO_FA_SECRET_KEY is not None, "2FA Secret key is required."

assert len(TWO_FA_SECRET_KEY) in {16, 26, 32}, "Invalid 2FA Secret key length."

# ---------------------------------------------------------------------------------

# Decode the Base32 secret key
key = base64.b32decode(TWO_FA_SECRET_KEY.upper())

# Get the current time step
timestep = int(time.time() // 30)

# Pack time step into bytes
msg = timestep.to_bytes(8, "big")

# Create HMAC-SHA1 from key and message
hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()

# Dynamic truncation to get a 4-byte string
offset = hmac_hash[-1] & 0x0F
code = (
    (hmac_hash[offset] & 0x7F) << 24
    | (hmac_hash[offset + 1] & 0xFF) << 16
    | (hmac_hash[offset + 2] & 0xFF) << 8
    | (hmac_hash[offset + 3] & 0xFF)
)

# Modulo to get the OTP value
otp = str(code % (10**6)).zfill(6)

# ---------------------------------------------------------------------------------

print("2FA Secret Key:", TWO_FA_SECRET_KEY)
print("2FA OTP Code:", otp)
