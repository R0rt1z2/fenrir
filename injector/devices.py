from device import Device
from stage import PayloadStage, PatchStage
from patch_utils import MatchMode


DEVICES = [
    Device(
        'Pacman',
        'Nothing Phone 2a',
        {
            # Ideally, we'd make room in the 'lk' partition for the payload, but for the sake
            # of this demonstration, we take advantage of the fact that the BSP for this phone     
            # includes a lot of eMMC-related code that isn’t actually used, since this device 
            # uses UFS instead.                                                               
            #                                                                                 
            # Technically, these stages are not required by the exploit. They simply show    
            # that we can execute arbitrary code within the LK image, which is way cooler    
            # than just applying patches.                                                    
            #                                                                                 
            # The first address is the virtual base address where the stage payload is       
            # injected. The second address is the address of the `bl` call that we override  
            # to jump to the payload instead (called pivot by me, which is probably wrong).
            #'stage1': PayloadStage(
            #    'stage1',
            #    0xFFFF000050F6F0A8,  # emmc_init()
            #    0xFFFF000050F05DA4,  # platform_init()
            #    description='Pre-platform initialization stage',
            #),
            #'stage2': PayloadStage(
            #    'stage2',
            #    0xFFFF000050F6AE98, # msdc_tune_cmdrsp()
            #    0xFFFF000050F0E088, # bl notify_enter_fastboot()
            #    description='Pre-fastboot initialization stage',
            #),
            #'stage3': PayloadStage(
            #    'stage3',
            #    0xFFFF000050F6C168, # msdc_config_bus()
            #    0xFFFF000050F0E0A4, # bl dprintf("%s:%d: Notify boot linux.\n")
            #    description='Linux initialization stage',
            #),

            # This is what makes it possible for this exploit to work. Long
            # story short, an LK image has various partitions inside it,
            # which each have a specific purpose and get loaded at a specific
            # address. The order matters, and each partition verifies the next
            # one before loading it.
            #
            # From my analysis, the boot chain of this device is as follows:
            # 1. BootROM (SoC)
            # 2. Preloader
            # 3. bl2_ext (LK)
            # 4. TEE
            # 5. GenieZone (GZ)
            # 6. lk or aee (LK)
            # 7. Linux kernel (boot)
            # 8. ...
            #
            # BootROM is the first stage and is not modifiable (it's masked ROM) and
            # it ALWAYS verifies and loads the Preloader against the fused root key. 
            # Then, under normal circumstances, the Preloader verifies and loads bl2_ext, 
            # which is the first partition of 'lk' to get verified and loaded. Then
            # bl2_ext takes control of the boot process and verifies and loads
            # the next partitions: TEE, GZ, LK, and so on.
            #
            # HOWEVER, this is not the case when seccfg is unlocked. When this
            # happens, the Preloader DOES NOT verify bl2_ext even though bl2_ext
            # itself still verifies the subsequent partitions. This means that one
            # can arbitrarily modify bl2_ext so it does not verify the next
            # partitions, which would lead to a full takeover of the secure boot chain.
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                # This is because every partition inside the LK image has its own function
                # that is called to verify the next partition. We take advantage of the fact
                # that the signature of the function is always the same, so we can apply the
                # patch to all of them at once.
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),

            # Since at this point we have full control over the boot chain, we can
            # easily patch the lk partition, which is the one that takes care of
            # setting up the boot state of the device, which is then used by Android
            # to determine whether the device is locked or unlocked.
            #
            # The goal here is to spoof the boot state to always be set to green and
            # thus trick TEE and Android into thinking that the device hasn't been
            # tampered with so we can pass STRONG, DEVICE and BASIC Play Store Integrity
            # checks.
            #
            # Most likely the first two patches are not needed, but it's better to be safe
            # than sorry.
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='c8 03 00 90 00 21 01 b9 c0 03 5f d6',
                replacement='c8 03 00 90 1f 21 01 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='a9 74 01 94 20 01 00 36',
                replacement='a9 74 01 94 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
        },
    ),
    Device(
        'PacmanPro',
        'Nothing Phone 2a Plus',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='c8 03 00 b0 00 21 01 b9 c0 03 5f d6',
                replacement='c8 03 00 b0 1f 21 01 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='0b 75 01 94 20 01 00 36',
                replacement='0b 75 01 94 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            )
        },
    ),
    Device(
        'Tetris',
        'CMF Phone 1',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='68 04 00 f0 00 d9 04 b9 c0 03 5f d6',
                replacement='68 04 00 f0 1f d9 04 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c4 ff ff 97 e8 03 00 2a e0 03 1f 2a 68 02 00 b9',
                replacement='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 48 04 80 52 68 02 00 b9 e0 03 1f 2a f3 0b 40 f9 fd 7b c2 a8',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            )
        },
    ),
    Device(
        'Tetris240910',
        'CMF Phone 1 / Tetris U2.6-240910-1735',
        {
            # Tested on Tetris_U2.6-240910-1735 lk.img.
            # SHA256: 849fdabc71e39b007e8000f26c5744965b3e24bc076886d0eb0aefea2d87858b
            #
            # This profile intentionally avoids the older Tetris MatchMode.ALL
            # function patches.  Every patch is constrained to one partition and
            # one expected offset so a firmware drift fails closed instead of
            # silently patching a nearby table/function.
            'bl2_ext_lk_policy_table_no_vfy': PatchStage(
                'bl2_ext_lk_policy_table_no_vfy',
                partition='bl2_ext',
                pattern='01 00 00 00 02 00 00 00 01 00 00 00 03 00 00 00',
                replacement='00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00',
                expected_matches=21,
                match_offsets=[0xAB460],
                strict_length=True,
                fail_on_zero=True,
                description='Clear VFY_EN only for the bl2_ext lk/lk_a/lk_b policy entry',
            ),
            'final_unlock_orange_to_green': PatchStage(
                'final_unlock_orange_to_green',
                partition='lk',
                pattern='e8 0f 40 b9 1f 0d 00 71 61 00 00 54 40 00 80 52 9c 01 00 94 8d 01 00 94',
                replacement='e8 0f 40 b9 1f 0d 00 71 61 00 00 54 00 00 80 52 9c 01 00 94 8d 01 00 94',
                expected_matches=1,
                match_offsets=[0x565C4],
                strict_length=True,
                fail_on_zero=True,
                description='Use GREEN instead of ORANGE for the final unlocked-device boot-state setter',
            ),
            'rot_device_lock_smc_locked': PatchStage(
                'rot_device_lock_smc_locked',
                partition='lk',
                pattern='00 24 80 52 e1 37 80 b9 f3 43 00 91 02 c1 47 b9 00 40 b8 72',
                replacement='00 24 80 52 21 00 80 52 f3 43 00 91 02 c1 47 b9 00 40 b8 72',
                expected_matches=1,
                match_offsets=[0xA4870],
                strict_length=True,
                fail_on_zero=True,
                description='Pass DEVICE_STATE_LOCKED/1 to the RootOfTrust SMC payload',
            ),
            'main_lk_unlocked_literal_to_locked': PatchStage(
                'main_lk_unlocked_literal_to_locked',
                partition='lk',
                pattern='25 6c 6c 78 00 50 75 62 6c 69 73 68 20 70 61 72 74 69 74 69 6f 6e 20 65 72 72 6f 72 2e 00 75 6e 6c 6f 63 6b 65 64 00 44 41 54 41 25 30 38 78 00 6d 61 67 69 63 3a 20 30 78 25 78 0a 00',
                replacement='25 6c 6c 78 00 50 75 62 6c 69 73 68 20 70 61 72 74 69 74 69 6f 6e 20 65 72 72 6f 72 2e 00 6c 6f 63 6b 65 64 00 00 00 44 41 54 41 25 30 38 78 00 6d 61 67 69 63 3a 20 30 78 25 78 0a 00',
                expected_matches=1,
                match_offsets=[0xC0B45],
                strict_length=True,
                fail_on_zero=True,
                description='Replace the main lk AVB/cmdline unlocked literal with locked',
            ),
            'aee_unlocked_literal_to_locked': PatchStage(
                'aee_unlocked_literal_to_locked',
                partition='aee',
                pattern='25 6c 6c 78 00 50 75 62 6c 69 73 68 20 70 61 72 74 69 74 69 6f 6e 20 65 72 72 6f 72 2e 00 75 6e 6c 6f 63 6b 65 64 00 44 41 54 41 25 30 38 78 00 6d 61 67 69 63 3a 20 30 78 25 78 0a 00',
                replacement='25 6c 6c 78 00 50 75 62 6c 69 73 68 20 70 61 72 74 69 74 69 6f 6e 20 65 72 72 6f 72 2e 00 6c 6f 63 6b 65 64 00 00 00 44 41 54 41 25 30 38 78 00 6d 61 67 69 63 3a 20 30 78 25 78 0a 00',
                expected_matches=1,
                match_offsets=[0x9B61F],
                strict_length=True,
                fail_on_zero=True,
                description='Replace the aee AVB/cmdline unlocked literal with locked',
            ),
        },
        expected_sha256='849fdabc71e39b007e8000f26c5744965b3e24bc076886d0eb0aefea2d87858b',
    ),
    Device(
        'LG8n',
        'Tecno Pova 4 Pro',
        {
            'stage1': PayloadStage(
                'stage1',
                0xFFFF000050F23D60,
                0xFFFF000050F049E0,
                description='Pre-platform initialization stage',
            ),
            'stage2': PayloadStage(
                'stage2',
                0xFFFF000050F1FCD0,
                0xFFFF000050F0CCE4,
                description='Pre-fastboot initialization stage',
            ),
            'stage3': PayloadStage(
                'stage3',
                0xFFFF000050F21020, # msdc_config_bus()
                0xFFFF000050F0CD00, # bl dprintf("%s:%d: Notify boot linux.\n")
                description='Linux initialization stage',
            ),
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='e8 02 00 b0 00 f1 0a b9 c0 03 5f d6',
                replacement='e8 02 00 b0 1f f1 0a b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security check - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
        },
    ),
    Device(
        'LH7n',
        'Tecno Pova 5',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='a8 03 00 d0 00 29 0d b9 c0 03 5f d6',
                replacement='a8 03 00 d0 1f 29 0d b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            )
        },
    ),
    Device(
        'LG7n',
        'Tecno Pova 4',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='c8 02 00 f0 00 29 0a b9 c0 03 5f d6',
                replacement='c8 02 00 f0 1f 29 0a b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security check - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
        },
    ),
    Device(
        'Q25',
        'Zinwa Q25',
        {
            'stage1': PayloadStage(
                'stage1',
                0xffff000050f23670,  # unknown emmc_init() adjacent func
                0xffff000050f04a18,  # bl platform_init()
                description='Pre-platform initialization stage',
            ),
            'stage2': PayloadStage(
                'stage2',
                0xffff000050f1f690, # msdc_tune_cmdrsp()
                0xffff000050f0c858, # bl notify_enter_fastboot()
                description='Pre-fastboot initialization stage',
            ),
            'stage3': PayloadStage(
                'stage3',
                0xffff000050f209e0, # msdc_config_bus()
                0xffff000050f0c874, # bl dprintf("%s:%d: Notify boot linux.\n")
                description='Linux initialization stage',
            ),

            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='a8 02 00 b0 00 c1 09 b9 c0 03 5f d6',
                replacement='a8 02 00 b0 1f c1 09 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security check - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            ),
        },
    ),
    Device(
        'peridotl',
        'Lenovo IdeaTab Pro / Xiaoxin Pad Pro 12.7',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='c8 04 00 90 00 f9 03 b9 c0 03 5f d6',
                replacement='c8 04 00 90 1f f9 03 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='88 17 40 b9 c8 01 00 34',
                replacement='88 17 40 b9 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'bypass_lock_control': PatchStage(
                'bypass_lock_control',
                pattern='1f 0d 00 71 21 01 00 54',
                replacement='1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'bypass_region_check': PatchStage(
                'bypass_region_check',
                pattern='ff 03 01 d1 fd 7b 01 a9 f5 13 00 f9 f4 4f 03 a9 fd 43 00 91 f3 03 00 aa bf c3 1f b8',
                replacement='00 00 80 52 c0 03 5f d6 f5 13 00 f9 f4 4f 03 a9 fd 43 00 91 f3 03 00 aa bf c3 1f b8',
                match_mode=MatchMode.ALL,
                description='Skip region check - allow crossflashing',
            ),
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='e1 07 9f 1a fa 17 9f 1a 15 05 88 1a',
                replacement='e1 07 9f 1a 3a 00 80 52 15 05 88 1a',
                match_mode=MatchMode.ALL,
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
        },
    ),
    Device(
        'S666LN',
        'itel RS4',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='88 03 00 f0 00 e1 0c b9 c0 03 5f d6',
                replacement='88 03 00 f0 1f e1 0c b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 0b 40 b9 1f 0d 00 71 21 01 00 54',
                replacement='e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52',
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Prevent LK from relocking seccfg',
            )
        },
        cert_bypass=True
    ),
]
