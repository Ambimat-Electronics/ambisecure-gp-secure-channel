# Hardware verification, 2026-10-31

One SCP03 session per run, three runs, same result: runs 1 and 2 (13:22Z, 13:23Z)
with a transcript-recording script that follows the example; run 3 (13:27Z) with
`examples/pcsc_scp03_open.py` unchanged, which printed `KVN FF, i 70` and the same ISD
status as below. The transcript below is run 2. Values that are derived from the static keys (card and
host cryptograms, MACs, encrypted data), the key diversification data and the card
challenge are redacted. No key value appears anywhere in this repository.

| Item | Value |
|---|---|
| Host | macOS 27.0.1, PC/SC via CryptoTokenKit, CCID driver `fr.apdu.ccid.smartcardccid` 1.5.1 |
| Python | 3.14.7, pycryptodome, pyscard 2.3.2 |
| Reader | Gemalto USB SmartCard Reader, USB `08E6:3437`, protocol T=1 |
| ATR | `3BD518FF8191FE1FC3AE190482CEFF` |
| Card | NXP-fabricated Java Card test card (CPLC IC fabricator `4790`); Card Recognition Data: GlobalPlatform 2.3, SCP `03` i=`70` |
| Key Information Template (GET DATA `00E0`, before authentication) | key IDs `01`, `02`, `03`; KVN `FF`; type `88` (AES); 16 bytes each |
| Keys | test keys supplied by the card owner (`KEY_VALUES_RECORDED = NO`) |
| INITIALIZE UPDATE answer | KVN `FF`, SCP `03`, i `70` (pseudo-random challenge, R-MAC and R-ENCRYPTION supported), sequence counter present |

## Transcript (run 2)

| Step | Command | Response data | SW | ms |
|---|---|---|---|---|
| SELECT ISD | `00A4040008A00000015100000000` | `6F108408A000000151000000A5049F6501FF` | `9000` | 46.7 |
| INITIALIZE UPDATE (P1 00, host challenge 8B) | `805000000823D45F268F9CC25300` | `<REDACTED_KDD:10B> FF0370 <CARD_CHALLENGE:8B> <REDACTED_CARD_CRYPTOGRAM:8B> 000005` | `9000` | 49.2 |
| EXTERNAL AUTHENTICATE, level 33 | `8482330010 <REDACTED_HOST_CRYPTOGRAM:8B> <REDACTED_CMAC:8B>` | `(none)` | `9000` | 18.7 |
| GET STATUS ISD (wrapped) | `84F2800218 <ENCRYPTED:16B> <REDACTED_CMAC:8B> 00` | `<ENCRYPTED:48B> <REDACTED_RMAC:8B>` | `9000` | 30.9 |

GET STATUS plaintext after R-MAC verification and R-ENCRYPTION removal by `Session.unwrap()`:

```text
E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08A0000001510000009000
E3 26                       GP registry entry
  4F 08 A000000151000000    ISD AID
  9F70 01 01                life cycle 01 (in the ISD context: OP_READY)
  C5 03 9EFE80              privileges
  C4 07 A0000001515350      executable load file
  CC 08 A000000151000000    associated security domain
9000
```

## Checks

- Card cryptogram verified on the host before EXTERNAL AUTHENTICATE was sent.
- EXTERNAL AUTHENTICATE at level `33` accepted (`9000`).
- GET STATUS sent with C-DECRYPTION and C-MAC; the response R-MAC verified and its
  R-ENCRYPTION removed.
- Host-side negatives against the real INITIALIZE UPDATE answer, without sending
  anything further to the card: a key with one bit flipped fails the card
  cryptogram check; `expected_key_version=0x01` is rejected (card answered `FF`);
  level `31` is rejected before any APDU. Failed authentications sent to the card: 0.
- Commands sent: SELECT, GET DATA (INS `CA`: CPLC `9F7F`, Card Data `0066`, Key
  Information `00E0`, and `80CA00FE02DF2800`, a proprietary card-identification tag),
  INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, GET STATUS. None changes keys, content or life-cycle state; each
  INITIALIZE UPDATE advances the card's SCP03 sequence counter, as the protocol requires.
