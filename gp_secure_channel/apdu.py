"""Short-APDU helpers for opening a GlobalPlatform secure channel.

Builders return plain command APDUs (CLA 0x80). A secure-channel session wraps
them, which sets the secure-messaging bit (CLA 0x84) and appends the MAC.
Response parsers take the response *data* without SW1 SW2.
"""
from dataclasses import dataclass
from typing import Optional

INITIALIZE_UPDATE = 0x50
EXTERNAL_AUTHENTICATE = 0x82


def initialize_update(host_challenge: bytes, key_version: int = 0x00) -> bytes:
    """80 50 <KVN> 00 08 <host challenge> 00. Key version 0 = first available key set."""
    if len(host_challenge) != 8:
        raise ValueError("host challenge must be 8 bytes (S8 mode)")
    return bytes([0x80, INITIALIZE_UPDATE, key_version, 0x00, 0x08]) + host_challenge + b"\x00"


def external_authenticate(security_level: int, host_cryptogram: bytes) -> bytes:
    """Plain 80 82 <security level> 00 08 <host cryptogram>; the session adds C-MAC (-> 84 .. 10 ..)."""
    if len(host_cryptogram) != 8:
        raise ValueError("host cryptogram must be 8 bytes")
    return bytes([0x80, EXTERNAL_AUTHENTICATE, security_level, 0x00, 0x08]) + host_cryptogram


def split_command(apdu: bytes):
    """Split a short command APDU (ISO/IEC 7816-4 cases 1-4) into (header, data, le)."""
    if len(apdu) < 4:
        raise ValueError("APDU shorter than 4-byte header")
    header, body = apdu[:4], apdu[4:]
    if len(body) <= 1:                      # case 1 or case 2
        return header, b"", body
    lc = body[0]
    if lc == 0 or len(body) not in (1 + lc, 2 + lc):
        raise ValueError("unsupported APDU (extended length or Lc mismatch)")
    return header, body[1:1 + lc], body[1 + lc:]


@dataclass(frozen=True)
class Scp03InitUpdate:
    key_diversification_data: bytes
    key_version: int
    scp_id: int
    i_param: int
    card_challenge: bytes
    card_cryptogram: bytes
    sequence_counter: Optional[bytes]


def _check_key_version(returned: int, requested: Optional[int]) -> None:
    # P1 = 00 lets the card pick its first available key set; any other P1 names the set
    # the session must use (Amendment D v1.1.2, 7.1.1.3; same P1 coding for SCP02).
    if requested and returned != requested:
        raise ValueError(f"card answered with key version 0x{returned:02X}, requested 0x{requested:02X}")


def parse_initialize_update_scp03(data: bytes, expected_key_version: Optional[int] = None) -> Scp03InitUpdate:
    """KDD(10) | KVN(1) | 03 | i(1) | card challenge(8) | card cryptogram(8) [| sequence counter(3)].

    S8 mode only: 29 bytes, or 32 when the card uses a pseudo-random challenge.
    Pass the key version sent in INITIALIZE UPDATE P1 as expected_key_version to
    reject a response from a different key set (00 or None: no check).
    """
    if len(data) not in (29, 32):
        raise ValueError(f"SCP03 S8 INITIALIZE UPDATE response must be 29 or 32 bytes, got {len(data)}")
    if data[11] != 0x03:
        raise ValueError(f"not an SCP03 response (SCP id 0x{data[11]:02X})")
    _check_key_version(data[10], expected_key_version)
    return Scp03InitUpdate(data[:10], data[10], data[11], data[12], data[13:21], data[21:29],
                           data[29:32] if len(data) == 32 else None)


@dataclass(frozen=True)
class Scp02InitUpdate:
    key_diversification_data: bytes
    key_version: int
    scp_id: int
    sequence_counter: bytes
    card_challenge: bytes
    card_cryptogram: bytes


def parse_initialize_update_scp02(data: bytes, expected_key_version: Optional[int] = None) -> Scp02InitUpdate:
    """KDD(10) | KVN(1) | 02 | sequence counter(2) | card challenge(6) | card cryptogram(8)."""
    if len(data) != 28:
        raise ValueError(f"SCP02 INITIALIZE UPDATE response must be 28 bytes, got {len(data)}")
    if data[11] != 0x02:
        raise ValueError(f"not an SCP02 response (SCP id 0x{data[11]:02X})")
    _check_key_version(data[10], expected_key_version)
    return Scp02InitUpdate(data[:10], data[10], data[11], data[12:14], data[14:20], data[20:28])
