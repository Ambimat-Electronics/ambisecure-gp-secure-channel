import pytest
from Crypto.Cipher import DES

from gp_secure_channel import scp02
from spec_reference import GP_TEST_KEY, HOST_CHALLENGE, pad80, ref_retail_mac, ref_tdes_cbc

K = GP_TEST_KEY
SEQ = bytes.fromhex("0001")              # synthetic sequence counter
CARD_CHALLENGE6 = bytes(range(0x08, 0x0E))

KAT = {
    "s_enc": "25c9794a1205ff244f5fa0378d2f8d59",
    "s_mac": "9bed98891580c3b245fe9ec58bfa8d2a",
    "s_dek": "0e51fdf196141f227a57bd154012fd39",
    "card_cryptogram": "9d8da672f05c4e45",
    "host_cryptogram": "e87e4c9e45c47f79",
}


def session(level=scp02.C_MAC, icv_encrypt=True):
    return scp02.Session(K, K, K, SEQ, CARD_CHALLENGE6, HOST_CHALLENGE, level, icv_encrypt)


@pytest.mark.parametrize("name", sorted(KAT))
def test_known_answers(name):
    assert getattr(session(), name).hex() == KAT[name]


def test_session_keys_and_cryptograms_match_spec_reference():
    s = session()
    for const, key in ((b"\x01\x82", s.s_enc), (b"\x01\x01", s.s_mac), (b"\x01\x81", s.s_dek)):
        assert key == ref_tdes_cbc(K, bytes(8), const + SEQ + bytes(12))
    assert s.card_cryptogram == ref_tdes_cbc(s.s_enc, bytes(8), pad80(HOST_CHALLENGE + SEQ + CARD_CHALLENGE6, 8))[-8:]
    assert s.host_cryptogram == ref_tdes_cbc(s.s_enc, bytes(8), pad80(SEQ + CARD_CHALLENGE6 + HOST_CHALLENGE, 8))[-8:]


def test_card_cryptogram_check():
    with pytest.raises(ValueError):
        session().verify_card_cryptogram(bytes(8))


@pytest.mark.parametrize("icv_encrypt", [True, False])
def test_external_authenticate_then_chained_retail_mac(icv_encrypt):
    s = session(icv_encrypt=icv_encrypt)
    ea = s.external_authenticate()
    hdr = bytes.fromhex("8482010010")
    mac1 = ref_retail_mac(s.s_mac, hdr + s.host_cryptogram, bytes(8))
    assert ea == hdr + s.host_cryptogram + mac1
    icv = DES.new(s.s_mac[:8], DES.MODE_ECB).encrypt(mac1) if icv_encrypt else mac1
    mac2 = ref_retail_mac(s.s_mac, bytes.fromhex("84CA006608"), icv)
    assert s.wrap(bytes.fromhex("80CA006600")) == bytes.fromhex("84CA006608") + mac2 + b"\x00"


def test_c_enc_zero_iv_and_mac_over_plaintext():
    s = session(scp02.C_MAC | scp02.C_DECRYPTION)
    ea = s.external_authenticate()
    assert len(ea) == 21                                   # EXTERNAL AUTHENTICATE is never encrypted
    plain = bytes.fromhex("4F00")
    wrapped = s.wrap(bytes.fromhex("80F28002024F0000"))
    icv = DES.new(s.s_mac[:8], DES.MODE_ECB).encrypt(ea[-8:])
    mac = ref_retail_mac(s.s_mac, bytes.fromhex("84F280020A") + plain, icv)
    enc = ref_tdes_cbc(s.s_enc, bytes(8), pad80(plain, 8))
    assert wrapped == bytes.fromhex("84F2800210") + enc + mac + b"\x00"


def test_rejects_unsupported_levels():
    with pytest.raises(ValueError):
        session(0x10)                                       # R-MAC not implemented


@pytest.mark.parametrize("level, size", [(scp02.C_MAC, 248), (scp02.C_MAC | scp02.C_DECRYPTION, 240)])
def test_oversize_command_fails_cleanly_without_touching_the_mac_chain(level, size):
    s = session(level)
    s.external_authenticate()
    before = s.last_mac
    with pytest.raises(ValueError, match="exceeds short APDU length"):
        s.wrap(bytes([0x80, 0xE2, 0x00, 0x00, size]) + bytes(size))
    assert s.last_mac == before


def test_largest_mac_only_command_still_fits():
    s = session()
    s.external_authenticate()
    assert len(s.wrap(bytes([0x80, 0xE2, 0x00, 0x00, 247]) + bytes(247))) == 5 + 255
