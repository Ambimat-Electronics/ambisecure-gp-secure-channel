import pytest
from Crypto.Cipher import AES

from gp_secure_channel import scp03
from spec_reference import (CARD_CHALLENGE, GP_TEST_KEY, HOST_CHALLENGE, pad80, ref_aes_cbc, ref_cmac,
                            ref_kdf)

K = GP_TEST_KEY
CTX = HOST_CHALLENGE + CARD_CHALLENGE

# Known-answer values: GP test key 40..4F, host challenge 00..07, card challenge 08..0F.
KAT = {
    "s_enc": "eb845bbc703969a9b312a5f8e4834aa2",
    "s_mac": "94d9141c5e50a39ef3939b9a4616c910",
    "s_rmac": "f034ed3222d3466ee1531f3fa3561def",
    "card_cryptogram": "114f6bc5052c5228",
    "host_cryptogram": "fafa93c2ede62463",
}


def session(level=scp03.C_MAC):
    return scp03.Session(K, K, HOST_CHALLENGE, CARD_CHALLENGE, level)


def test_reference_cmac_matches_library_cmac():
    for n in (0, 1, 15, 16, 17, 32, 33):
        msg = bytes(range(n))
        assert scp03.cmac(K, msg) == ref_cmac(K, msg)


def test_kdf_block_layout():
    # The only CMAC input for a 128-bit output: 11 x 00 | const | 00 | 0080 | 01 | context
    block = bytes(11) + b"\x04\x00\x00\x80\x01" + CTX
    assert scp03.kdf(K, 0x04, CTX, 128) == ref_cmac(K, block)


def test_kdf_multi_block_output_matches_reference():
    assert scp03.kdf(K, 0x04, CTX, 256) == ref_kdf(K, 0x04, CTX, 256)


@pytest.mark.parametrize("name", sorted(KAT))
def test_known_answers(name):
    assert getattr(session(), name).hex() == KAT[name]


def test_session_keys_and_cryptograms_match_spec_reference():
    s = session()
    assert s.s_enc == ref_kdf(K, 0x04, CTX, 128)
    assert s.s_mac == ref_kdf(K, 0x06, CTX, 128)
    assert s.s_rmac == ref_kdf(K, 0x07, CTX, 128)
    assert s.card_cryptogram == ref_kdf(s.s_mac, 0x00, CTX, 64)
    assert s.host_cryptogram == ref_kdf(s.s_mac, 0x01, CTX, 64)


def test_card_cryptogram_check():
    s = session()
    s.verify_card_cryptogram(bytes.fromhex(KAT["card_cryptogram"]))
    with pytest.raises(ValueError):
        s.verify_card_cryptogram(bytes(8))


def test_external_authenticate_and_mac_chaining():
    s = session()
    ea = s.external_authenticate()
    hdr = bytes.fromhex("8482010010")
    mac1 = ref_cmac(s.s_mac, bytes(16) + hdr + s.host_cryptogram)
    assert ea == hdr + s.host_cryptogram + mac1[:8]
    assert s.mac_chaining_value == mac1                      # full 16 bytes chain, 8 are sent
    wrapped = s.wrap(bytes.fromhex("80CA006600"))
    mac2 = ref_cmac(s.s_mac, mac1 + bytes.fromhex("84CA006608"))
    assert wrapped == bytes.fromhex("84CA006608") + mac2[:8] + b"\x00"


def test_c_decryption_icv_is_encrypted_counter_not_raw_counter():
    """Proves the SCP-01 fix: ICV = AES-ECB(S-ENC, counter)."""
    s = session(scp03.C_MAC | scp03.C_DECRYPTION)
    s.external_authenticate()
    plain = bytes.fromhex("4F00")
    wrapped = s.wrap(bytes.fromhex("80F28002024F0000"))
    ciphertext = wrapped[5:5 + 16]
    counter = (1).to_bytes(16, "big")
    icv = AES.new(s.s_enc, AES.MODE_ECB).encrypt(counter)
    raw_counter_output = ref_aes_cbc(s.s_enc, counter, pad80(plain, 16))
    assert ciphertext != raw_counter_output                  # the defective construction
    assert ciphertext == ref_aes_cbc(s.s_enc, icv, pad80(plain, 16))
    assert ref_aes_cbc(s.s_enc, icv, ciphertext, decrypt=True) == pad80(plain, 16)
    assert wrapped[4] == 16 + 8


def test_counter_increments_on_commands_without_data():
    s = session(scp03.C_MAC | scp03.C_DECRYPTION)
    s.external_authenticate()
    assert s.encryption_counter == 0
    s.wrap(bytes.fromhex("80F22002"))
    s.wrap(bytes.fromhex("80CA006600"))
    assert s.encryption_counter == 2


def test_r_mac_verify_and_reject():
    s = session(scp03.C_MAC | scp03.R_MAC)
    s.external_authenticate()
    s.wrap(bytes.fromhex("80CA006600"))
    data, sw = bytes.fromhex("6603A1B2C3"), b"\x90\x00"
    rmac = ref_cmac(s.s_rmac, s.mac_chaining_value + data + sw)[:8]
    assert s.unwrap(data + rmac + sw) == data + sw
    with pytest.raises(ValueError):
        s.unwrap(data + bytes(8) + sw)
    assert s.unwrap(b"\x6A\x82") == b"\x6A\x82"                # error SW carries no R-MAC
    with pytest.raises(ValueError):
        s.unwrap(b"\x90\x00")                                 # success must carry an R-MAC


def test_r_encryption_icv_uses_counter_with_0x80_msb():
    s = session(scp03.C_MAC | scp03.C_DECRYPTION | scp03.R_MAC | scp03.R_ENCRYPTION)
    s.external_authenticate()
    s.wrap(bytes.fromhex("80CA006600"))
    plain, sw = bytes.fromhex("00112233445566778899"), b"\x90\x00"
    icv = AES.new(s.s_enc, AES.MODE_ECB).encrypt(b"\x80" + (1).to_bytes(16, "big")[1:])
    enc = ref_aes_cbc(s.s_enc, icv, pad80(plain, 16))
    rmac = ref_cmac(s.s_rmac, s.mac_chaining_value + enc + sw)[:8]
    assert s.unwrap(enc + rmac + sw) == plain + sw


def test_rejects_invalid_parameters():
    with pytest.raises(ValueError):
        scp03.Session(K + K, K, HOST_CHALLENGE, CARD_CHALLENGE)   # AES-256 not supported here
    with pytest.raises(ValueError):
        session(scp03.C_DECRYPTION)                                  # C-DEC without C-MAC
    with pytest.raises(ValueError):
        session(scp03.C_MAC | scp03.R_ENCRYPTION)                    # R-ENC without R-MAC


def test_repr_does_not_leak_keys():
    s = session()
    assert s.s_enc.hex() not in repr(s) and s.s_mac.hex() not in repr(s)


# --- v0.1.1: security levels (Amendment D v1.1.2, Table 7-6) -----------------------------

@pytest.mark.parametrize("level", scp03.SECURITY_LEVELS)
def test_every_defined_security_level_is_accepted(level):
    s = session(level)
    assert s.external_authenticate()[2] == level


@pytest.mark.parametrize("level", [v for v in range(256) if v not in scp03.SECURITY_LEVELS])
def test_every_undefined_security_level_is_rejected(level):
    with pytest.raises(ValueError, match="invalid security level"):
        session(level)


def test_level_31_is_rejected():
    """0x31 (R-ENC without C-DEC) used to be accepted with a counter that never moved."""
    with pytest.raises(ValueError):
        session(scp03.C_MAC | scp03.R_MAC | scp03.R_ENCRYPTION)


@pytest.mark.parametrize("level", scp03.SECURITY_LEVELS)
def test_encryption_counter_moves_only_with_c_decryption(level):
    s = session(level)
    s.external_authenticate()
    s.wrap(bytes.fromhex("80F22002"))
    s.wrap(bytes.fromhex("80F28002024F0000"))
    assert s.encryption_counter == (2 if level & scp03.C_DECRYPTION else 0)


def test_no_secure_messaging_level_passes_apdus_through():
    s = session(0x00)
    s.external_authenticate()
    assert s.wrap(bytes.fromhex("80CA006600")) == bytes.fromhex("80CA006600")
    assert s.unwrap(b"\x66\x00\x90\x00") == b"\x66\x00\x90\x00"


# --- v0.1.1: failed operations leave the session unchanged --------------------------------

def state(s):
    return (s.mac_chaining_value, s.encryption_counter)


@pytest.mark.parametrize("level", [scp03.C_MAC, 0x33])
def test_failed_wrap_leaves_state_unchanged(level):
    s, fresh = session(level), session(level)
    s.external_authenticate()
    fresh.external_authenticate()
    before = state(s)
    too_long = bytes.fromhex("80E20000F8") + bytes(248)          # 248 + 8 > 255 once wrapped
    with pytest.raises(ValueError, match="exceeds short APDU length"):
        s.wrap(too_long)
    assert state(s) == before
    ok = bytes.fromhex("80F28002024F0000")
    assert s.wrap(ok) == fresh.wrap(ok)                          # as if the failure never happened


def test_failed_r_mac_leaves_state_unchanged_and_session_usable():
    s = session(scp03.C_MAC | scp03.R_MAC)
    s.external_authenticate()
    s.wrap(bytes.fromhex("80CA006600"))
    data, sw = bytes.fromhex("6603A1B2C3"), b"\x90\x00"
    before = state(s)
    with pytest.raises(ValueError, match="R-MAC verification failed"):
        s.unwrap(data + bytes(8) + sw)
    assert state(s) == before
    rmac = ref_cmac(s.s_rmac, s.mac_chaining_value + data + sw)[:8]
    assert s.unwrap(data + rmac + sw) == data + sw


@pytest.mark.parametrize("response", ["90", "", "6603A19000"])
def test_malformed_response_leaves_state_unchanged(response):
    s = session(scp03.C_MAC | scp03.R_MAC)
    s.external_authenticate()
    before = state(s)
    with pytest.raises(ValueError):
        s.unwrap(bytes.fromhex(response))
    assert state(s) == before


def test_failed_r_decryption_leaves_state_unchanged():
    s = session(0x33)
    s.external_authenticate()
    s.wrap(bytes.fromhex("80CA006600"))
    garbage, sw = bytes(16), b"\x90\x00"                          # authentic R-MAC, invalid padding inside
    rmac = ref_cmac(s.s_rmac, s.mac_chaining_value + garbage + sw)[:8]
    before = state(s)
    with pytest.raises(ValueError, match="padding"):
        s.unwrap(garbage + rmac + sw)
    assert state(s) == before
