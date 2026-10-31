# Changelog

## 0.1.1 (2026-10-31)

- SCP03: security levels are checked against the six values Amendment D v1.1.2 defines
  (`00 01 03 11 13 33`, Table 7-6). `10`, `30` and `31` were accepted before; with `31`
  responses were decrypted with an encryption counter that never advanced.
- SCP03 `wrap()` no longer advances the encryption counter when it raises; SCP02 no longer
  updates its MAC chain when a command is too long, and an oversize MAC-only command now
  raises the module's own error instead of a `bytes()` range error.
- `parse_initialize_update_scp03/02(data, expected_key_version=None)`: optional check that
  the card answered with the requested key set.
- `__version__` is the single version source (was `0.1.0.dev0` against package `0.1.0`);
  explicit `[build-system]`.
- `tools/crosscheck_pysim.py`: optional, reproducible cross-check against pySim's published
  vectors without copying them (34/34 at the pinned commit).
- `examples/pcsc_scp03_open.py` reads keys from the environment, opens level `33` and sends a
  read-only GET STATUS; run on hardware (see `docs/hardware-verification-2026-10-31.md`).
- README: security levels, session state on errors, key version, troubleshooting,
  hardware verification, browser cross-check.

## 0.1.0 (2026-10-25)

- Initial public release (untagged).
