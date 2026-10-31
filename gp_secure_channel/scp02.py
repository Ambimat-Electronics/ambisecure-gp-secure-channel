"""GlobalPlatform SCP02, host side (GP Card Spec v2.2 Appendix E), 3DES only.

Targets the common i=0x15 / i=0x55 options: three secure channel keys, explicit
initiation, zero starting ICV, C-MAC on the modified APDU. The two options differ
only in how the card generates its challenge, which the host never recomputes.

ICV encryption (i bit b5): GPPro and pySim both encrypt the chained ICV for these
options (ICV = DES-ECB(first 8 bytes of C-MAC session key, previous MAC)), so it is
on by default. Pass icv_encrypt=False for cards whose i parameter clears b5.

Not implemented: R-MAC, ICV = MAC over AID (b4), implicit initiation, key
diversification, and any AES variant (SCP02 is defined for 3DES only).
Key material is never printed or logged by this module.
"""
import hmac

from Crypto.Cipher import DES, DES3

from .apdu import external_authenticate, split_command

DERIVE_C_MAC = b"\x01\x01"
DERIVE_S_ENC = b"\x01\x82"
DERIVE_DEK = b"\x01\x81"

C_MAC = 0x01
C_DECRYPTION = 0x02


def pad80(data: bytes) -> bytes:
    """ISO/IEC 9797-1 padding method 2, 8-byte blocks."""
    data += b"\x80"
    return data + bytes(-len(data) % 8)


def derive_session_key(static_key: bytes, constant: bytes, sequence_counter: bytes) -> bytes:
    """3DES-CBC, zero IV, over constant(2) | sequence counter(2) | 12 x 00."""
    return DES3.new(static_key, DES3.MODE_CBC, iv=bytes(8)).encrypt(constant + sequence_counter + bytes(12))


def full_3des_mac(key: bytes, data: bytes) -> bytes:
    """Full triple-DES CBC-MAC, zero IV, method 2 padding (used for the cryptograms)."""
    return DES3.new(key, DES3.MODE_CBC, iv=bytes(8)).encrypt(pad80(data))[-8:]


def retail_mac(key: bytes, data: bytes, icv: bytes) -> bytes:
    """ISO/IEC 9797-1 MAC algorithm 3: single-DES CBC with K1, final block D(K2) then E(K1)."""
    k1, k2 = key[:8], key[8:16]
    h = DES.new(k1, DES.MODE_CBC, iv=icv).encrypt(pad80(data))[-8:]
    return DES.new(k1, DES.MODE_ECB).encrypt(DES.new(k2, DES.MODE_ECB).decrypt(h))


class Session:
    """One SCP02 secure channel session (host side), C-MAC and optional C-ENC."""

    def __init__(self, k_enc: bytes, k_mac: bytes, k_dek: bytes, sequence_counter: bytes,
                 card_challenge: bytes, host_challenge: bytes, security_level: int = C_MAC,
                 icv_encrypt: bool = True):
        if any(len(k) != 16 for k in (k_enc, k_mac, k_dek)):
            raise ValueError("SCP02 static keys must be 16-byte two-key 3DES keys")
        if len(sequence_counter) != 2 or len(card_challenge) != 6 or len(host_challenge) != 8:
            raise ValueError("sequence counter 2, card challenge 6, host challenge 8 bytes")
        if security_level not in (C_MAC, C_MAC | C_DECRYPTION):
            raise ValueError(f"unsupported security level 0x{security_level:02X} (R-MAC not implemented)")
        self.s_enc = derive_session_key(k_enc, DERIVE_S_ENC, sequence_counter)
        self.s_mac = derive_session_key(k_mac, DERIVE_C_MAC, sequence_counter)
        self.s_dek = derive_session_key(k_dek, DERIVE_DEK, sequence_counter)
        self.card_cryptogram = full_3des_mac(self.s_enc, host_challenge + sequence_counter + card_challenge)
        self.host_cryptogram = full_3des_mac(self.s_enc, sequence_counter + card_challenge + host_challenge)
        self.security_level = security_level
        self.icv_encrypt = icv_encrypt
        self.last_mac = None

    def __repr__(self):  # never expose key material
        return f"<scp02.Session security_level=0x{self.security_level:02X}>"

    def verify_card_cryptogram(self, received: bytes) -> None:
        if not hmac.compare_digest(self.card_cryptogram, received):
            raise ValueError("card cryptogram mismatch: wrong keys or not this card")

    def external_authenticate(self) -> bytes:
        return self._wrap(external_authenticate(self.security_level, self.host_cryptogram), encrypt=False)

    def wrap(self, apdu: bytes) -> bytes:
        return self._wrap(apdu, encrypt=bool(self.security_level & C_DECRYPTION))

    def _wrap(self, apdu: bytes, encrypt: bool) -> bytes:
        header, data, le = split_command(apdu)
        header = bytes([header[0] | 0x04]) + header[1:]
        body = DES3.new(self.s_enc, DES3.MODE_CBC, iv=bytes(8)).encrypt(pad80(data)) if encrypt and data else data
        if len(body) + 8 > 255:                         # checked before any state changes
            raise ValueError("wrapped command exceeds short APDU length")
        if self.last_mac is None:
            icv = bytes(8)
        elif self.icv_encrypt:
            icv = DES.new(self.s_mac[:8], DES.MODE_ECB).encrypt(self.last_mac)
        else:
            icv = self.last_mac
        # C-MAC over the modified header and the *plaintext* data
        mac = retail_mac(self.s_mac, header + bytes([len(data) + 8]) + data, icv)
        self.last_mac = mac
        return header + bytes([len(body) + 8]) + body + mac + le
