"""Second, independent computations written directly from the specifications.

Only raw block-cipher primitives (AES-ECB, DES-ECB) are used here, so these do not
share CMAC/CBC code paths with the library under test.
"""
from Crypto.Cipher import AES, DES

# Publicly documented GlobalPlatform default test key 40 41 ... 4F (synthetic, never a real card key)
GP_TEST_KEY = bytes(range(0x40, 0x50))
HOST_CHALLENGE = bytes(range(0x00, 0x08))   # synthetic
CARD_CHALLENGE = bytes(range(0x08, 0x10))   # synthetic


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pad80(data, block):
    data += b"\x80"
    return data + bytes(-len(data) % block)


# ---- NIST SP 800-38B CMAC, built from AES-ECB -------------------------------------------
def _dbl(block):
    n = int.from_bytes(block, "big") << 1
    if n >> 128:
        n = (n ^ 0x87) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")


def ref_cmac(key, msg):
    ecb = AES.new(key, AES.MODE_ECB)
    k1 = _dbl(ecb.encrypt(bytes(16)))
    k2 = _dbl(k1)
    if msg and len(msg) % 16 == 0:
        blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        blocks[-1] = xor(blocks[-1], k1)
    else:
        padded = pad80(msg, 16)
        blocks = [padded[i:i + 16] for i in range(0, len(padded), 16)]
        blocks[-1] = xor(blocks[-1], k2)
    x = bytes(16)
    for b in blocks:
        x = ecb.encrypt(xor(x, b))
    return x


# ---- GP Amendment D SCP03 KDF (SP 800-108 counter mode) ---------------------------------
def ref_kdf(key, constant, context, bits):
    label = b"\x00" * 11
    out = b""
    for i in range(1, (bits + 127) // 128 + 1):
        out += ref_cmac(key, label + bytes([constant]) + b"\x00" + bytes([bits >> 8, bits & 0xFF]) + bytes([i]) + context)
    return out[:bits // 8]


def ref_aes_cbc(key, iv, data, decrypt=False):
    ecb = AES.new(key, AES.MODE_ECB)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if decrypt:
            out += xor(ecb.decrypt(blk), prev)
            prev = blk
        else:
            prev = ecb.encrypt(xor(blk, prev))
            out += prev
    return out


# ---- 3DES primitives for SCP02 ------------------------------------------------------------
def tdes_ecb(key, block):
    k1, k2 = DES.new(key[:8], DES.MODE_ECB), DES.new(key[8:16], DES.MODE_ECB)
    return k1.encrypt(k2.decrypt(k1.encrypt(block)))


def ref_tdes_cbc(key, iv, data):
    out, prev = b"", iv
    for i in range(0, len(data), 8):
        prev = tdes_ecb(key, xor(data[i:i + 8], prev))
        out += prev
    return out


def ref_retail_mac(key, data, icv):
    k1 = DES.new(key[:8], DES.MODE_ECB)
    padded = pad80(data, 8)
    h = icv
    for i in range(0, len(padded) - 8, 8):
        h = k1.encrypt(xor(h, padded[i:i + 8]))
    return tdes_ecb(key, xor(h, padded[-8:]))
