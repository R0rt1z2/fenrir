# CMF Phone 1 / Tetris notes

These notes document the firmware-specific CMF Phone 1 data behind the
`Tetris240910` profile.  The goal is to make this port fail closed when the
input LK image does not match the audited firmware, rather than applying broad
`MatchMode.ALL` patches to a different build.

## Tested firmware

- Device: CMF Phone 1 (`Tetris`, MT6878)
- Firmware: `Tetris_U2.6-240910-1735`
- LK input SHA256:
  `849fdabc71e39b007e8000f26c5744965b3e24bc076886d0eb0aefea2d87858b`
- LK base from the image: `0xFFFF000050700000`

## Patch profile

`Tetris240910` applies five exact-offset patches:

| Stage | Partition | Offset | Purpose |
| --- | --- | ---: | --- |
| `bl2_ext_lk_policy_table_no_vfy` | `bl2_ext` | `0xAB460` | Clear `VFY_EN` only for the `lk`/`lk_a`/`lk_b` policy table entry. |
| `final_unlock_orange_to_green` | `lk` | `0x565C4` | Use `GREEN` instead of `ORANGE` at the final unlocked-device boot-state setter. |
| `rot_device_lock_smc_locked` | `lk` | `0xA4870` | Pass `DEVICE_STATE_LOCKED`/`1` to the RootOfTrust SMC payload. |
| `main_lk_unlocked_literal_to_locked` | `lk` | `0xC0B45` | Replace the main LK `unlocked` AVB/cmdline literal with `locked`. |
| `aee_unlocked_literal_to_locked` | `aee` | `0x9B61F` | Replace the AEE `unlocked` AVB/cmdline literal with `locked`. |

The profile also checks:

- exact input image SHA256;
- exact partition name for every patch;
- expected match count;
- selected match offset;
- equal pattern/replacement length.

## Validation summary

The `Tetris240910` patch set was tested on a CMF Phone 1 running the firmware
listed above:

- booted Android after flashing the patched LK to the active slot;
- Android boot props reported `green`, `flash.locked=1`, and
  `vbmeta.device_state=locked`;
- Android Key Attestation reported `deviceLocked=True` and
  `verifiedBootState=Verified`;
- Play Integrity reached Strong after the OS/vendor patchlevel source was
  refreshed separately in the Android/KeyMint stack.

The last point is intentionally not modeled as an LK-only guarantee.  On this
firmware, LK-side RootOfTrust patching supplied the locked/verified state and
boot patchlevel path, while OS/vendor patchlevels were taken from the
Trustonic KeyMint configuration path.  Treat patchlevel spoofing as a separate
firmware/user-space integration problem.

## Related 240606 finding

On firmware `2406061805`, global Tetris-style patches were risky.  A safer
analysis path used firmware-specific offsets and avoided global `MatchMode.ALL`
patching:

- live LK SHA256:
  `d3af07fb6da0c1946748186756853bc44dc806e6a2cb6f0cb60c8389056915de`
- `bl2_ext` policy table patch offset: `0xAC320`
- final `ORANGE` to `GREEN` LK offset: `0x56524`
- RootOfTrust device-lock SMC offset: `0xA48EC`

Those offsets are included here as research notes only.  They are not exposed
as a default profile in this PR because the tested and current profile is
`Tetris240910`.

## Safety note

Do not apply this profile to other Tetris firmware builds.  Offsets and match
counts are expected to drift between OTA releases.  If any gate fails, stop and
port the profile again from a fresh LK dump and boot log evidence.
