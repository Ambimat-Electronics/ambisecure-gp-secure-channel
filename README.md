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
- **Software-verified only.** The results in this repository come from software
  tests and published test vectors (see *Verification*). The PC/SC example has
  not been run against a card as part of this release.

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
| `gp_secure_channel/apdu.py` | INITIALIZE UPDATE and EXTERNAL AUTHENTICATE builders, short-APDU splitting, and INITIALIZE UPDATE response parsers (SCP03 S8: 29 or 32 bytes; SCP02: 28 bytes). |

The only runtime dependency is `pycryptodome`. There is no PC/SC dependency;
`examples/pcsc_scp03_open.py` optionally uses `pyscard`.

### Not implemented (by design)

- SCP03 with AES-192/256 keys and S16 mode.
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
iu = apdu.parse_initialize_update_scp03(rdata)
s = scp03.Session(key, key, host_challenge, iu.card_challenge, scp03.C_MAC | scp03.C_DECRYPTION)
s.verify_card_cryptogram(iu.card_cryptogram)
ext_auth = s.external_authenticate()     # send this next
wrapped = s.wrap(bytes.fromhex("80F28002024F0000"))
```

## Verification

```sh
pip install pycryptodome pytest
pytest
```

- All test data is synthetic. The only key is the publicly documented
  GlobalPlatform test key `40 41 42 … 4F`. Challenges and sequence counters are
  fixed counting patterns.
- Every SCP03 and SCP02 value is checked three ways: against pinned known-answer
  values, against the library, and against a second computation in
  `tests/spec_reference.py`. That second computation is built from raw AES-ECB and
  DES-ECB and does not reuse the library's CMAC or CBC code.
- Off-repository cross-check: the package reproduces the 30 published
  GlobalPlatform values in osmocom pySim's unit tests (SCP02 3DES with ICV
  encryption; SCP03 AES-128 at security levels 11, 03 and 33, including R-MAC
  and R-ENCRYPTION). pySim is GPL-licensed, so its vectors are not copied here.
- One test proves the C-DECRYPTION ICV construction. The ciphertext differs from
  the raw-counter-IV result and decrypts with ICV = AES-ECB(S-ENC, counter).

## Specification references

- GlobalPlatform Card Specification v2.3.1, Amendment D: Secure Channel Protocol '03'
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

## Security

Please report suspected vulnerabilities privately to support@ambimat.com rather
than in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
