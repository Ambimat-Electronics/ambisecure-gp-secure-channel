"""Open an SCP03 channel to a test card over PC/SC and send one wrapped GET STATUS.

Requires `pip install pyscard`. Keys come from the environment as hex (never put
keys in source code or on the command line):

    GP_SCP03_ENC, GP_SCP03_MAC   static AES-128 keys; default: public GP test key 40..4F
    GP_SCP03_KVN                 optional key version the card must answer with (hex)

Sends only SELECT, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE and GET STATUS (read-only).
If the card cryptogram does not match, it stops before EXTERNAL AUTHENTICATE, so a
wrong key never costs an authentication attempt on the card.
"""
import os

from smartcard.System import readers

from gp_secure_channel import apdu, scp03

GP_TEST_KEY = "404142434445464748494A4B4C4D4E4F"
ISD_AID = bytes.fromhex("A000000151000000")   # GlobalPlatform ISD AID; many cards use A000000003000000


def transmit(conn, command: bytes) -> bytes:
    data, sw1, sw2 = conn.transmit(list(command))
    return bytes(data) + bytes([sw1, sw2])


def main():
    k_enc = bytes.fromhex(os.environ.get("GP_SCP03_ENC", GP_TEST_KEY))
    k_mac = bytes.fromhex(os.environ.get("GP_SCP03_MAC", GP_TEST_KEY))
    kvn = int(os.environ["GP_SCP03_KVN"], 16) if "GP_SCP03_KVN" in os.environ else None

    conn = readers()[0].createConnection()
    conn.connect()
    resp = transmit(conn, bytes([0x00, 0xA4, 0x04, 0x00, len(ISD_AID)]) + ISD_AID + b"\x00")
    if resp[-2:] != b"\x90\x00":
        raise SystemExit(f"SELECT ISD failed: SW {resp[-2:].hex().upper()}")

    host_challenge = os.urandom(8)
    resp = transmit(conn, apdu.initialize_update(host_challenge))          # P1 00: first available key set
    if resp[-2:] != b"\x90\x00":
        raise SystemExit(f"INITIALIZE UPDATE failed: SW {resp[-2:].hex().upper()}")
    iu = apdu.parse_initialize_update_scp03(resp[:-2], expected_key_version=kvn)
    print(f"KVN {iu.key_version:02X}, i {iu.i_param:02X}")

    level = scp03.C_MAC | scp03.C_DECRYPTION | scp03.R_MAC | scp03.R_ENCRYPTION   # 33; needs i bits 0x60
    s = scp03.Session(k_enc, k_mac, host_challenge, iu.card_challenge, level)
    s.verify_card_cryptogram(iu.card_cryptogram)                         # raises before anything is sent
    resp = transmit(conn, s.external_authenticate())
    if resp[-2:] != b"\x90\x00":
        raise SystemExit(f"EXTERNAL AUTHENTICATE rejected: SW {resp[-2:].hex().upper()}")

    # GET STATUS, Issuer Security Domain, TLV format; R-MAC verified and R-ENCRYPTION removed by unwrap()
    print("ISD status:", s.unwrap(transmit(conn, s.wrap(bytes.fromhex("80F28002024F0000")))).hex().upper())


if __name__ == "__main__":
    main()
