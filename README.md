# ambisecure-gp-secure-channel

A small reference implementation of the host side of the GlobalPlatform secure
channel protocols SCP03 (AES) and SCP02 (3DES). It is written to be read: each
cryptographic step is a few lines that map directly onto the specification, and
the test suite recomputes every value a second way from raw block-cipher
primitives.

Use it to understand the protocols, to check another implementation against
known answers, or as a starting point for test tooling.

## Not for production key handling

- **Not for production keys.** There is no HSM or secure key storage, keys sit
  in Python memory as plain `bytes`, and nothing here has been side-channel
  reviewed.
- **No HSM integration.**
- **One card, one configuration.** Hardware verification covers SCP03 AES-128,
  S8 mode, on one test card (see *Hardware verification*). Everything else rests
  on software tests and published test vectors (see *Verification*).

## SCP02 and SCP03 in one paragraph

GlobalPlatform defines several secure channel protocols. **SCP02** is the older,
**3DES-based** channel: session keys come from the static keys and the card's
sequence counter, and commands carry a retail MAC. **SCP03** is the
**AES-based** channel from Amendment D: session keys come from an AES-CMAC KDF
(NIST SP 800-108) over both challenges, and commands carry an AES-CMAC with a
16-byte chaining value. "SCP03 with 3DES" is not a GlobalPlatform configuration;
3DES deployments are SCP02.

## What it implements

| Module | Scope |
|---|---|
| `gp_secure_channel/scp03.py` | SCP03, AES-128 keys, S8 mode. SP 800-108 counter-mode KDF with AES-CMAC. Session keys S-ENC (`04`), S-MAC (`06`), S-RMAC (`07`). Card (`00`) and host (`01`) cryptograms, 64-bit. C-MAC with a 16-byte MAC chaining value, truncated to 8 bytes. R-MAC verification in constant time (`hmac.compare_digest`). C-DECRYPTION with ICV = AES-ECB(S-ENC, counter). R-ENCRYPTION removal with ICV = AES-ECB(S-ENC, counter with MSB `80`). |
| `gp_secure_channel/scp02.py` | SCP02, 3DES (two-key) only, for the common i=`15`/`55` options. Session keys by 3DES-CBC with zero IV over constant ‖ sequence counter ‖ 12×`00`: S-ENC `0182`, C-MAC `0101`, DEK `0181`. Card and host cryptograms as full 3DES CBC-MAC with ISO 9797-1 method 2 padding. C-MAC is a retail MAC (ISO 9797-1 algorithm 3) over the modified APDU with a chained ICV. ICV encryption is on by default. C-ENC uses 3DES-CBC with zero IV. |
| `gp_secure_channel/apdu.py` | INITIALIZE UPDATE and EXTERNAL AUTHENTICATE builders, short-APDU splitting, and INITIALIZE UPDATE response parsers (SCP03 S8: 29 or 32 bytes; SCP02: 28 bytes). Optional `expected_key_version` check. |

Current release: **0.1.1** (see [CHANGELOG](CHANGELOG.md)). `gp_secure_channel.__version__`
is the single version source; `pyproject.toml` reads it.

### SCP03 security levels

`scp03.Session` accepts exactly the six EXTERNAL AUTHENTICATE P1 values that
Amendment D v1.1.2 defines (section 7.1.2.3, Table 7-6) and raises `ValueError` for
every other value, before any APDU is built:

| P1 | Protection |
|---|---|
| `00` | none (no secure messaging expected) |
| `01` | C-MAC |
| `03` | C-DECRYPTION + C-MAC |
| `11` | C-MAC + R-MAC |
| `13` | C-DECRYPTION + C-MAC + R-MAC |
| `33` | C-DECRYPTION + R-ENCRYPTION + C-MAC + R-MAC |

`10`, `30` and `31` are rejected. Version 0.1.0 accepted them; with `31` the
response decryption used an encryption counter that never advanced.
The card's i parameter says what it supports: bit `20` = R-MAC, bit `40` =
R-ENCRYPTION (Amendment D Table 5-1), so `11`/`13` need i & `20` and `33` needs i & `60`.

### Session state on errors

A failed `wrap()` (for example a command too long once wrapped) leaves the MAC
chaining value and the encryption counter unchanged, because no command was
produced. `unwrap()` never changes state, so a failed R-MAC check or response
decryption leaves the session as it was. Whether to continue after an error is
the caller's decision; after a card-side MAC failure the card ends the session
(Amendment D section 5.5) and a new INITIALIZE UPDATE is needed.

### Key version

INITIALIZE UPDATE P1 `00` lets the card pick its first available key set; any other
value names the set (Amendment D 7.1.1.3). Pass the key version you expect as
`expected_key_version` and the parser rejects a response from a different set. The
check is opt-in: with no value, or `00`, the parser accepts any key version, and the
pySim SCP02 vector below sends P1 `20` and reports key version `70`.

The only runtime dependency is `pycryptodome`. There is no PC/SC dependency;
`examples/pcsc_scp03_open.py` optionally uses `pyscard`.

### Not implemented (by design)

- SCP03 with AES-192/256 keys and S16 mode (S16 responses fail the 29/32-byte length check).
- SCP03 pseudo-random card-challenge recomputation.
- DEK-based key wrapping (PUT KEY) for both protocols.
- SCP02 R-MAC, implicit initiation, ICV = MAC over AID (i bit b4), and any
  "SCP02 with AES" variant. SCP02 is defined for 3DES only.
- Key diversification of any kind. Diversification schemes are issuer-specific.
- Extended-length APDUs.

### SCP02 ICV encryption

The i parameter values `15` and `55` both set bit b5 (ICV encryption for the
C-MAC session). They differ only in b7, the card-challenge generation method,
which the host never recomputes. From the second wrapped command onward, the ICV is
DES-ECB(first 8 bytes of the C-MAC session key, previous C-MAC). Pass
`icv_encrypt=False` for cards whose i value clears b5.

## Quick start

```python
import os
from gp_secure_channel import apdu, scp03

key = bytes(range(0x40, 0x50))          # public GP test key 40..4F; never a real card key
host_challenge = os.urandom(8)
cmd = apdu.initialize_update(host_challenge)
# ... send cmd, receive response data (without SW1 SW2) as `rdata` ...
iu = apdu.parse_initialize_update_scp03(rdata, expected_key_version=0x30)   # or None
s = scp03.Session(key, key, host_challenge, iu.card_challenge, scp03.C_MAC | scp03.C_DECRYPTION)
s.verify_card_cryptogram(iu.card_cryptogram)
ext_auth = s.external_authenticate()     # send this next
wrapped = s.wrap(bytes.fromhex("80F28002024F0000"))
```

## Verification

```sh
pip install pycryptodome pytest
pytest                      # 315 tests, under a second
```

- All test data is synthetic. The only key is the publicly documented
  GlobalPlatform test key `40 41 42 … 4F`. Challenges and sequence counters are
  fixed counting patterns.
- Every SCP03 and SCP02 value is checked three ways: against pinned known-answer
  values, against the library, and against a second computation in
  `tests/spec_reference.py`. That second computation is built from raw AES-ECB and
  DES-ECB and does not reuse the library's CMAC or CBC code.
- Negative tests: every undefined SCP03 security level (250 values), wrong card
  cryptogram, wrong R-MAC, invalid response padding, malformed APDUs and
  responses, key-version mismatch, and session state after each failure.
- One test proves the C-DECRYPTION ICV construction. The ciphertext differs from
  the raw-counter-IV result and decrypts with ICV = AES-ECB(S-ENC, counter).

### Cross-check against osmocom pySim (optional, not in CI)

pySim's unit tests publish SCP02 and SCP03 vectors. pySim is GPL-2.0-or-later, so
this Apache-2.0 repository contains none of its code or data. You clone pySim
yourself; the script reads its test file with Python's `ast` module (pySim is
never imported or executed) and recomputes every value with this package:

```sh
git clone https://gitea.osmocom.org/sim-card/pysim.git
git -C pysim checkout 0c4d170e773798c390abe996aa089791192e28ce
python tools/crosscheck_pysim.py pysim      # prints one PASS/FAIL line per value
```

Result at the pinned commit: **34/34 values match** (SCP02 3DES with ICV
encryption: INITIALIZE UPDATE, card cryptogram, EXTERNAL AUTHENTICATE, four C-MAC
cases; SCP03 AES-128 at levels 11, 03 and 33: INITIALIZE UPDATE, card cryptogram,
EXTERNAL AUTHENTICATE, wrapped and unwrapped GET EID including R-MAC and
R-ENCRYPTION, four C-MAC cases each). Exit status 0 = all match, 1 = mismatch,
2 = file not readable. It stays out of CI because it needs a network clone of a
separately licensed project.

### Browser cross-check

The [AmbiSecure SCP03 helper](https://ambisecure.ambimat.com/resources/tools/scp03-helper/)
computes the session keys and cryptograms in the browser. It is a separate
JavaScript implementation (Web Crypto AES plus its own RFC 4493 CMAC) and shares
no code with this package; both follow the same specification. With the GP test
key `40..4F`, host challenge `00..07` and card challenge `08..0F` it returns the
five values in `KAT` in `tests/test_scp03.py`. It covers key derivation and
cryptograms only, not wrapping, R-MAC or encryption. The
[SCP03 walkthrough](https://ambisecure.ambimat.com/resources/tools/scp03-walkthrough/)
explains each step.

## Hardware verification

Run on 2026-10-31 with `examples/pcsc_scp03_open.py` and an equivalent script
that also recorded a transcript. Details and the sanitised transcript:
[docs/hardware-verification-2026-10-31.md](docs/hardware-verification-2026-10-31.md).

| Item | Value |
|---|---|
| Host | macOS 27.0.1, built-in PC/SC (CryptoTokenKit), CCID driver 1.5.1, `pyscard` 2.3.2 |
| Reader | Gemalto USB SmartCard Reader (USB `08E6:3437`), T=1 |
| Card | NXP-fabricated Java Card test card, GlobalPlatform 2.3, SCP03 i=`70`, one AES-128 key set (KVN `FF`) |
| Keys | test keys supplied by the card owner; not recorded anywhere in this repository |
| Result | SELECT ISD → INITIALIZE UPDATE → card cryptogram verified → EXTERNAL AUTHENTICATE level `33` → wrapped GET STATUS: all `9000`; R-MAC verified and R-ENCRYPTION removed; three sessions, same result |
| Not covered | SCP02 on hardware, levels other than `33`, AES-192/256, other cards and readers |

Only SELECT, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE and GET STATUS were sent; no
command that changes keys, content or lifecycle. Negative checks (wrong key, wrong
key version, level `31`) were made on the host against the real card response, so
no failed authentication reached the card.

## Troubleshooting

| Symptom | Raised by | Likely cause |
|---|---|---|
| `card cryptogram mismatch: wrong keys or not this card` | `Session.verify_card_cryptogram` | Wrong static ENC/MAC keys, a diversified card key, or a card or key set other than the one you expect. Stop here: do not send EXTERNAL AUTHENTICATE with keys the card did not confirm, as cards may count failed authentications. |
| `card answered with key version 0xNN, requested 0xMM` | `parse_initialize_update_*` | The card used a different key set. Read the Key Information Template (GET DATA `00E0`) to see which key versions exist; a key file's own "version" field may not be the on-card KVN (the verified card reports `FF`). |
| `not an SCP03 response (SCP id 0x02)` | `parse_initialize_update_scp03` | The key set is SCP02; use `parse_initialize_update_scp02` and `scp02.Session`. |
| `SCP03 S8 INITIALIZE UPDATE response must be 29 or 32 bytes` | `parse_initialize_update_scp03` | S16 mode or a non-GP response; S16 is not implemented. |
| `invalid security level 0xNN` | `scp03.Session` | P1 is not one of `00 01 03 11 13 33`. |
| `R-MAC verification failed` | `Session.unwrap` | Wrong S-RMAC (keys), a response that does not belong to the last wrapped command, or a security level without R-MAC on the card side. Session state is unchanged. |
| `response too short to carry an R-MAC` | `Session.unwrap` | A `9000`/`62xx`/`63xx` response without the 8-byte R-MAC while R-MAC is on. |
| `invalid ISO/IEC 9797-1 method 2 padding` | `Session.unwrap` | R-ENCRYPTION removal with the wrong key or counter. |
| `wrapped command exceeds short APDU length` | `wrap` | Data too long once MAC (and padding) is added; split the command. Session state is unchanged. |
| `unsupported APDU (extended length or Lc mismatch)` | `split_command` | Malformed command or extended-length APDU. |

Card status words on the verified card: every command returned `9000`. Status words
for card-side failures (for example `6982`, `6A88`) have not yet been observed with
this package on hardware, so they are not listed here.

## Specification references

- GlobalPlatform Card Specification v2.3, Amendment D: Secure Channel Protocol '03', v1.1.2
  (GPC_SPE_014, March 2019, public release): security levels 7.1.2.3 / Table 7-6,
  i parameter Table 5-1, INITIALIZE UPDATE 7.1.1, security level rules 5.5
- GlobalPlatform Card Specification v2.2, Appendix E: Secure Channel Protocol '02'
- NIST SP 800-108: Recommendation for Key Derivation Using Pseudorandom Functions
- NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
- ISO/IEC 9797-1: Message Authentication Codes, Part 1 (padding method 2, MAC algorithm 3)

## About

Maintained by AmbiSecure, the security business unit of Ambimat Electronics
(Ahmedabad, India). Ambimat has deployed GlobalPlatform secure-channel
provisioning using SCP02/3DES and SCP03/AES with customer systems, including
NXP P71D600 and Infineon secure elements. This repository contains none of that
customer work: no keys, key-diversification schemes, chip-specific commands or
customer configuration.

- [AmbiSecure secure-element integration](https://ambisecure.ambimat.com/solutions/secure-element-integration/)
- [AmbiSecure SCP03 engineering case study](https://ambisecure.ambimat.com/case-studies/scp03-secure-element-provisioning/)
- [SCP03 technical overview](https://ambisecure.ambimat.com/technologies/scp03/)
- [SCP03 helper (browser cross-check)](https://ambisecure.ambimat.com/resources/tools/scp03-helper/)

## Security

Please report suspected vulnerabilities privately to support@ambimat.com rather
than in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
