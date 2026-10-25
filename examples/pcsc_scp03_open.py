"""Open an SCP03 channel to a test card over PC/SC and send one wrapped GET DATA.

Requires `pip install pyscard`. Uses the public GlobalPlatform test key 40..4F, so it only
works on a development card that still has that default key. NOT RUN on hardware in this draft.
Never put production keys in source code.
"""
import os

from smartcard.System import readers

from gp_secure_channel import apdu, scp03

GP_TEST_KEY = bytes(range(0x40, 0x50))
ISD_AID = bytes.fromhex("A000000151000000")   # GlobalPlatform ISD AID; many cards use A000000003000000


def transmit(conn, command: bytes) -> bytes:
    data, sw1, sw2 = conn.transmit(list(command))
    return bytes(data) + bytes([sw1, sw2])


def main():
    conn = readers()[0].createConnection()
    conn.connect()
    assert transmit(conn, bytes([0x00, 0xA4, 0x04, 0x00, len(ISD_AID)]) + ISD_AID + b"\x00")[-2:] == b"\x90\x00"

    host_challenge = os.urandom(8)
    resp = transmit(conn, apdu.initialize_update(host_challenge))
    if resp[-2:] != b"\x90\x00":
        raise SystemExit(f"INITIALIZE UPDATE failed: SW {resp[-2:].hex().upper()}")
    iu = apdu.parse_initialize_update_scp03(resp[:-2])

    s = scp03.Session(GP_TEST_KEY, GP_TEST_KEY, host_challenge, iu.card_challenge, scp03.C_MAC | scp03.R_MAC)
    s.verify_card_cryptogram(iu.card_cryptogram)
    if transmit(conn, s.external_authenticate())[-2:] != b"\x90\x00":
        raise SystemExit("EXTERNAL AUTHENTICATE rejected")

    # GET DATA, tag 0066 (Card Data); R-MAC is verified by unwrap()
    print("Card Data:", s.unwrap(transmit(conn, s.wrap(bytes.fromhex("80CA006600")))).hex().upper())


if __name__ == "__main__":
    main()
