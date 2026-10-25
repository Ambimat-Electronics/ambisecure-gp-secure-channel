"""GlobalPlatform SCP03, host side (GP Card Spec v2.3.1 Amendment D).

Scope: AES-128 keys, S8 mode (8-byte challenges, cryptograms and MACs).
Key material is never printed or logged by this module.
"""
import hmac

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from .apdu import external_authenticate, split_command

# Derivation constants (Amendment D, section 4.1.5)
CARD_CRYPTOGRAM = 0x00
HOST_CRYPTOGRAM = 0x01
DERIVE_S_ENC = 0x04
DERIVE_S_MAC = 0x06
DERIVE_S_RMAC = 0x07

# Security level bits (P1 of EXTERNAL AUTHENTICATE)
C_MAC = 0x01
C_DECRYPTION = 0x02
R_MAC = 0x10
R_ENCRYPTION = 0x20


def cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC, NIST SP 800-38B."""
    return CMAC.new(key, data, ciphermod=AES).digest()


def kdf(key: bytes, constant: int, context: bytes, bits: int) -> bytes:
    """NIST SP 800-108 KDF in counter mode, PRF = AES-CMAC.

    Input block: label (11 x 00) | constant | 00 | L (2 bytes, bits, big-endian) | i (1 byte) | context
    """
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += cmac(key, bytes(11) + bytes([constant, 0x00]) + bits.to_bytes(2, "big") + bytes([i]) + context)
        i += 1
    return out[:bits // 8]


def pad80(data: bytes, block: int = 16) -> bytes:
    """ISO/IEC 9797-1 padding method 2."""
    data += b"\x80"
    return data + bytes(-len(data) % block)


def unpad80(data: bytes) -> bytes:
    stripped = data.rstrip(b"\x00")
    if not stripped.endswith(b"\x80"):
        raise ValueError("invalid ISO/IEC 9797-1 method 2 padding")
    return stripped[:-1]


def _check_level(level: int) -> None:
    if level & ~(C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION):
        raise ValueError(f"unsupported security level 0x{level:02X}")
    if (level & C_DECRYPTION and not level & C_MAC) or (level & R_ENCRYPTION and not level & R_MAC):
        raise ValueError(f"invalid security level 0x{level:02X}: encryption requires the matching MAC")


class Session:
    """One SCP03 secure channel session (host side).

    Typical flow:
        s = Session(k_enc, k_mac, host_challenge, card_challenge, security_level=C_MAC | C_DECRYPTION)
        s.verify_card_cryptogram(card_cryptogram_from_init_update)
        card.send(s.external_authenticate())
        resp = s.unwrap(card.send(s.wrap(apdu)))
    """

    def __init__(self, k_enc: bytes, k_mac: bytes, host_challenge: bytes, card_challenge: bytes,
                 security_level: int = C_MAC):
        if len(k_enc) != 16 or len(k_mac) != 16:
            raise ValueError("this implementation supports AES-128 keys only")
        if len(host_challenge) != 8 or len(card_challenge) != 8:
            raise ValueError("S8 mode: challenges must be 8 bytes")
        _check_level(security_level)
        context = host_challenge + card_challenge
        self.s_enc = kdf(k_enc, DERIVE_S_ENC, context, 128)
        self.s_mac = kdf(k_mac, DERIVE_S_MAC, context, 128)
        self.s_rmac = kdf(k_mac, DERIVE_S_RMAC, context, 128)
        self.card_cryptogram = kdf(self.s_mac, CARD_CRYPTOGRAM, context, 64)
        self.host_cryptogram = kdf(self.s_mac, HOST_CRYPTOGRAM, context, 64)
        self.security_level = security_level
        self.mac_chaining_value = bytes(16)
        self.encryption_counter = 0

    def __repr__(self):  # never expose key material
        return f"<scp03.Session security_level=0x{self.security_level:02X}>"

    def verify_card_cryptogram(self, received: bytes) -> None:
        if not hmac.compare_digest(self.card_cryptogram, received):
            raise ValueError("card cryptogram mismatch: wrong keys or not this card")

    def external_authenticate(self) -> bytes:
        """EXTERNAL AUTHENTICATE with C-MAC (always MAC-only, MAC chaining value starts at zero)."""
        return self._mac(external_authenticate(self.security_level, self.host_cryptogram))

    def _counter_block(self) -> bytes:
        return self.encryption_counter.to_bytes(16, "big")

    def _mac(self, apdu: bytes) -> bytes:
        header, data, le = split_command(apdu)
        header = bytes([header[0] | 0x04]) + header[1:]
        lc = len(data) + 8
        if lc > 255:
            raise ValueError("wrapped command exceeds short APDU length")
        full = cmac(self.s_mac, self.mac_chaining_value + header + bytes([lc]) + data)
        self.mac_chaining_value = full                 # 16-byte chaining value
        return header + bytes([lc]) + data + full[:8] + le

    def wrap(self, apdu: bytes) -> bytes:
        """Apply C-DECRYPTION (if enabled) then C-MAC to a plain short command APDU."""
        if not self.security_level & C_MAC:
            return apdu
        header, data, le = split_command(apdu)
        if self.security_level & C_DECRYPTION:
            self.encryption_counter += 1               # incremented for every command, data or not
            if data:
                # ICV = AES-ECB(S-ENC, counter), NOT the raw counter
                icv = AES.new(self.s_enc, AES.MODE_ECB).encrypt(self._counter_block())
                data = AES.new(self.s_enc, AES.MODE_CBC, iv=icv).encrypt(pad80(data))
                if len(data) > 255:
                    raise ValueError("encrypted data exceeds short APDU length")
        body = bytes([len(data)]) + data if data else b""
        return self._mac(header + body + le)

    def unwrap(self, response: bytes) -> bytes:
        """Verify R-MAC and remove R-ENCRYPTION (if enabled). Returns data | SW1 SW2."""
        if len(response) < 2:
            raise ValueError("response shorter than status word")
        if not self.security_level & R_MAC:
            return response
        sw = response[-2:]
        if len(response) == 2 and not (sw == b"\x90\x00" or sw[0] in (0x62, 0x63)):
            return response                            # error status words carry no R-MAC
        if len(response) < 10:
            raise ValueError("response too short to carry an R-MAC")
        data, mac = response[:-10], response[-10:-2]
        expected = cmac(self.s_rmac, self.mac_chaining_value + data + sw)[:8]
        if not hmac.compare_digest(expected, mac):
            raise ValueError("R-MAC verification failed")
        if self.security_level & R_ENCRYPTION and data:
            # ICV = AES-ECB(S-ENC, counter with its most significant byte set to 0x80)
            icv = AES.new(self.s_enc, AES.MODE_ECB).encrypt(b"\x80" + self._counter_block()[1:])
            data = unpad80(AES.new(self.s_enc, AES.MODE_CBC, iv=icv).decrypt(data))
        return data + sw
