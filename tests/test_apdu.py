import pytest

from gp_secure_channel import apdu

HC = bytes(range(8))


def test_initialize_update():
    assert apdu.initialize_update(HC, 0x30) == bytes.fromhex("8050300008") + HC + b"\x00"
    with pytest.raises(ValueError):
        apdu.initialize_update(HC[:7])


def test_external_authenticate_plain():
    assert apdu.external_authenticate(0x33, bytes(8)) == bytes.fromhex("8082330008") + bytes(8)


@pytest.mark.parametrize("raw, expect", [
    ("80F22002", ("80F22002", "", "")),
    ("80CA006600", ("80CA0066", "", "00")),
    ("80F2200202AABB", ("80F22002", "AABB", "")),
    ("80F2200202AABB00", ("80F22002", "AABB", "00")),
])
def test_split_command(raw, expect):
    assert tuple(x.hex().upper() for x in apdu.split_command(bytes.fromhex(raw))) == expect


@pytest.mark.parametrize("raw", ["80F220", "80F2200203AABB", "80F2200000AABB"])
def test_split_command_rejects_malformed(raw):
    with pytest.raises(ValueError):
        apdu.split_command(bytes.fromhex(raw))


def test_parse_scp03_s8():
    data = bytes(10) + b"\x30\x03\x70" + bytes(range(8)) + bytes(range(8, 16))
    r = apdu.parse_initialize_update_scp03(data)
    assert (r.key_version, r.scp_id, r.i_param, r.sequence_counter) == (0x30, 3, 0x70, None)
    assert r.card_challenge == bytes(range(8)) and r.card_cryptogram == bytes(range(8, 16))
    assert apdu.parse_initialize_update_scp03(data + b"\x00\x00\x02").sequence_counter == b"\x00\x00\x02"
    with pytest.raises(ValueError):
        apdu.parse_initialize_update_scp03(data[:28])
    with pytest.raises(ValueError):
        apdu.parse_initialize_update_scp03(data[:11] + b"\x02" + data[12:])


def test_parse_scp02():
    data = bytes(10) + b"\x20\x02\x00\x01" + bytes(range(6)) + bytes(range(8))
    r = apdu.parse_initialize_update_scp02(data)
    assert (r.key_version, r.scp_id, r.sequence_counter) == (0x20, 2, b"\x00\x01")
    assert r.card_challenge == bytes(range(6)) and r.card_cryptogram == bytes(range(8))
    with pytest.raises(ValueError):
        apdu.parse_initialize_update_scp02(data + b"\x00")
