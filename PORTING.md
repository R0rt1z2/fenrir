# Device Porting Guide for Fenrir

This guide explains how to port **Fenrir** to new MediaTek (MTK) Android devices.

---

## Prerequisites

1. **Target Compatibility**:
   - The device **MUST** be powered by a MediaTek (MTK) chipset.
   - The device boot chain must skip `bl2_ext` verification when unlocked (`seccfg` unlocked state).
   - You can verify this in an `expdb` crash dump or UART log:
     ```text
     [PART] img_auth_required = 0
     [PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
     [PART] part: lk_a img: bl2_ext cert vfy(0 ms)
     ```

2. **Required Tools**:
   - Python 3.8+ with `liblk`, `capstone`, `pyasn1` installed (`pip install -r requirements.txt`)
   - Disassembler: **Ghidra**, **IDA Pro**, or **Binary Ninja** (ARM64 / AArch64 Little Endian)
   - Stock fastboot ROM containing `lk.img` / `bootloader.bin`

---

## Step 1: Extract the Bootloader Binary

1. Extract the `lk.img` or `bootloader.bin` from the official Fastboot ROM for your device.
2. Place the file into `bin/<codename>.bin`.
3. Unpack the inner sub-partitions (`lk`, `bl2_ext`, `aee`) using `lkpatcher`:
   ```bash
   cd bin
   python3 -m lkpatcher <codename>.bin -d lk
   ```
   This extracts `<codename>_lk.raw` and related partition binaries.

---

## Step 2: Reverse Engineering and Locating Patches

Open the extracted `lk` raw binary in your disassembler as **AArch64 (64-bit Little Endian)**.

Default base address: `0xFFFF000050F00000` (or check `header.memory_address`).

### 1. `sec_get_vfy_policy` (Bypass Partition Verification)
* **Goal**: Force verification policy to return `0` (`SUCCESS`).
* **Search**: String `"sec_get_vfy_policy"`.
* **Standard Patch**:
  * **Original Opcode**: Function entry (e.g. `00 01 00 b4 fd 7b bf a9`)
  * **Replacement**: `00 00 80 52 c0 03 5f d6` (`MOV W0, #0; RET`)

### 2. `force_green_state` (Spoof Verified Boot to GREEN)
* **Goal**: Force `set_boot_state` to store `0` (`BOOT_STATE_GREEN`).
* **Search**: Strings `"androidboot.verifiedbootstate=green"`, `"green"`, `"orange"`.
* **Pattern**: Find the function ending with:
  ```arm64
  adrp x8, #page
  str  w0, [x8, #offset]
  ret
  ```
* **Patch**: Change `w0` into zero register `wzr` (`1F`):
  * E.g. `str w0, [x8, #offset]` $\rightarrow$ `str wzr, [x8, #offset]`

### 3. `spoof_lock_state` (Report Locked State)
* **Goal**: Force bootloader lock status query to report `LKS_LOCK` (`1`).
* **Search**: Strings `"get_lock_state"`, `"LKS_LOCK"`, `"lock_state"`.
* **Replacement**:
  ```arm64
  mov w8, #1      ; 88 00 80 52
  str w8, [x0]     ; 08 00 00 b9
  mov w0, #0      ; 00 00 80 52
  ret             ; c0 03 5f d6
  ```

### 4. `spoof_get_sboot_state` (Report Secure Boot Enabled)
* **Goal**: Force `sec_cfg_get_sboot_state` to report `ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP`.
* **Search**: Strings `"sboot"`, `"sec_get_sboot_state"`.
* **Replacement**: Set output pointer `[x0]` to `1` (or `0x48`) and return `0`.

### 5. `bypass_security_control` / `bypass_lock_control`
* **Goal**: Allow fastboot flash and erase commands even when lock state is spoofed.
* **Search**: Strings `"Flashing is not allowed in Lock State"`, `"security deny"`, `"erase:"`.
* **Patch**: Replace conditional branch (`CBNZ` / `B.NE`) with `NOP` (`1f 20 03 d5`) or direct branch (`B`).

### 6. `dont_relock_seccfg`
* **Goal**: Prevent Little Kernel from attempting to relock `seccfg`.
* **Replacement**: Return `0` immediately (`00 00 80 52 c0 03 5f d6 ...`).

---

## Step 3: Register Device in `injector/devices.py`

Add your device profile to `DEVICES` in `injector/devices.py`:

```python
Device(
    '<codename>',
    '<Device Full Name>',
    {
        'sec_get_vfy_policy': PatchStage(
            'sec_get_vfy_policy',
            pattern='<original_hex>',
            replacement='00 00 80 52 c0 03 5f d6',
            match_mode=MatchMode.ALL,
            description="Don't enforce secure boot policy",
        ),
        'force_green_state': PatchStage(
            'force_green_state',
            pattern='<original_hex>',
            replacement='<patched_hex>',
            match_mode=MatchMode.ALL,
            description='Force boot state to always be set to green',
        ),
        'bypass_security_control': PatchStage(
            'bypass_security_control',
            pattern='<original_hex>',
            replacement='<patched_hex>',
            match_mode=MatchMode.ALL,
            description='Skip security check - always execute commands',
        ),
        'spoof_sboot_state': PatchStage(
            'spoof_get_sboot_state',
            pattern='<original_hex>',
            replacement='<patched_hex>',
            match_mode=MatchMode.ALL,
            description='Force sboot state to always be enabled',
        ),
        'spoof_lock_state': PatchStage(
            'spoof_lock_state',
            pattern='<original_hex>',
            replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
            match_mode=MatchMode.ALL,
            description='Force lock state to always be LKS_LOCK',
        ),
        'dont_relock_seccfg': PatchStage(
            'dont_relock_seccfg',
            pattern='<original_hex>',
            replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Prevent LK from relocking seccfg',
        ),
    },
    cert_bypass=CertBypass.OVERRIDE  # or CertBypass.WRAP
),
```

---

## Step 4: Build and Test

1. **Verify defined stages**:
   ```bash
   python3 injector/inject.py <codename> --list-stages
   ```

2. **Patch Bootloader**:
   ```bash
   python3 injector/inject.py <codename> bin/<codename>.bin -o <codename>-fenrir.img
   ```

3. **Flash to Target Device (Fastboot Mode)**:
   ```bash
   fastboot flash lk_a <codename>-fenrir.img
   fastboot reboot
   ```
