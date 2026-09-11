from cert_bypass import CertBypass
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
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='88 17 40 b9 08 02 00 34',
                replacement='88 17 40 b9 1f 20 03 d5',
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'bypass_lock_control': PatchStage(
                'bypass_lock_control',
                pattern='20 01 00 36 88 13 40 b9',
                replacement='1f 20 03 d5 88 13 40 b9',
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='88 09 00 f0 00 51 08 b9 c0 03 5f d6',
                replacement='88 09 00 f0 1f 51 08 b9 c0 03 5f d6',
                partition='lk',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='e1 07 9f 1a fa 17 9f 1a 15 05 88 1a',
                replacement='e1 07 9f 1a 3a 00 80 52 15 05 88 1a',
                match_mode=MatchMode.ALL,
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
        },
        cert_bypass=CertBypass.OVERRIDE
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
        cert_bypass=CertBypass.OVERRIDE
    ),
    Device(
        'rodin',
        'Redmi Turbo 4/POCO X7 Pro',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='5f 24 03 d5 40 01 00 b4',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='28 17 40 b9 c8 01 00 34',
                replacement='28 17 40 b9 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_get_sboot_state',
                pattern='3f 23 03 d5 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
                replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='3f 23 03 d5 fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 00 aa 86 01 00 94',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'bypass_lock_control': PatchStage(
                'bypass_lock_control',
                pattern='00 74 3d 91 c3 00 00 14 e8 0f 40 b9 1f 05 00 71 21 01 00 54',
                replacement='00 74 3d 91 c3 00 00 14 e8 0f 40 b9 1f 05 00 71 09 00 00 14',
                match_mode=MatchMode.ALL,
                description='Allow fastboot flashing regardless of lock state',
            ),
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                pattern='e8 0f 40 b9 1f 05 00 71 81 00 00 54',
                replacement='e8 0f 40 b9 1f 05 00 71 04 00 00 14',
                match_mode=MatchMode.ALL,
                description='Allow fastboot erasing regardless of lock state',
            ),
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='e1 07 9f 1a f6 17 9f 1a 15 05 88 1a',
                replacement='e1 07 9f 1a 36 00 80 52 15 05 88 1a',
                match_mode=MatchMode.ALL,
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='e8 04 00 d0 00 c1 01 b9 bf 23 03 d5',
                replacement='e8 04 00 d0 1f c1 01 b9 bf 23 03 d5',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
        },
        cert_bypass=CertBypass.OVERRIDE
    ),
    Device(
        'duchamp',
        'Redmi K70E / POCO X6 Pro 5G ',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='e0 01 00 b4 fd 7b be a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='48 04 00 f0 00 a1 04 b9 c0 03 5f d6',
                replacement='48 04 00 f0 1f a1 04 b9 c0 03 5f d6',
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
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                pattern='1f 05 00 71 81 00 00 54 20 05 00 b0',
                replacement='1f 05 00 71 04 00 00 14 20 05 00 b0',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
            'bypass_cmd_flash_control': PatchStage(
                'bypass_cmd_flash_control',
                pattern='f6 8f 00 94 60 01 00 34',
                replacement='f6 8f 00 94 16 00 00 14',
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
            'spoof_custom_lock_state': PatchStage(
                'spoof_custom_lock_state',
                pattern='ff 43 05 d1 fd 7b 12 a9 fc 57 13 a9 f4 4f 14 a9 ',
                replacement='81 00 80 d2 01 00 00 b9 00 00 80 d2 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force custom lock state to always be LKS_LOCK',
            ),
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='e1 07 9f 1a fa 17 9f 1a 15 05 88 1a',
                replacement='e1 07 9f 1a 3a 00 80 52 15 05 88 1a',
                match_mode=MatchMode.ALL,
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
        },
        cert_bypass=CertBypass.OVERRIDE
    ),
    Device(
        'dash',
        'Redmi Turbo 5 Max / POCO X8 Pro Max',
        {
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='e1 07 9f 1a f6 17 9f 1a 15 05 88 1a',
                replacement='e1 07 9f 1a 36 00 80 52 15 05 88 1a',
                match_mode=MatchMode.ALL,
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='3f 23 03 d5 c8 05 00 90 00 91 09 b9',
                replacement='3f 23 03 d5 c8 05 00 90 1f 91 09 b9',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='3f 23 03 d5 fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 00 aa 7f 01 00 94',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force lock state to always be LKS_LOCK',
            ),
            'bypass_lock_control': PatchStage(
                'bypass_lock_control',
                pattern='1f 0d 00 71 21 01 00 54',
                replacement='1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute commands',
            ),
            'bypass_cmd_flash_control': PatchStage(
                'bypass_cmd_flash_control',
                pattern='f9 c7 01 94 80 00 00 34',
                replacement='f9 c7 01 94 04 00 00 14',
                match_mode=MatchMode.ALL,
                description='Allow fastboot flashing regardless of lock state',
            ),
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                pattern='e8 07 40 b9 1f 05 00 71 81 00 00 54',
                replacement='e8 0f 40 b9 1f 05 00 71 04 00 00 14',
                match_mode=MatchMode.ALL,
                description='Allow fastboot erasing regardless of lock state',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='28 17 40 b9 c8 01 00 34',
                replacement='28 17 40 b9 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Skip security error branch - always execute commands',
            ),
        },
        cert_bypass=CertBypass.OVERRIDE,
    ),
    Device(
        'xaga',
        'Redmi Note 11T Pro/Pro+/POCO X4 GT/Redmi K50i',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 3a 00 00 94',
                replacement='e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='68 03 00 b0 00 49 02 b9 c0 03 5f d6',
                replacement='68 03 00 b0 1f 49 02 b9 c0 03 5f d6',
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
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                pattern='a8 1f 40 b9 1f 05 00 71 81 00 00 54',
                replacement='a8 1f 40 b9 1f 05 00 71 04 00 00 14',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute erase',
            ),
            'bypass_cmd_flash_control': PatchStage(
                'bypass_cmd_flash_control',
                pattern='e8 07 40 b9 1f 05 00 71 21 01 00 54',
                replacement='e8 07 40 b9 1f 05 00 71 09 00 00 14',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute flash',
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
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
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
            'sec_otp_ver_get': PatchStage(
                'sec_otp_ver_get',
                pattern='ff 43 01 d1 fd 7b 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 43 00 91 f3 03 01 aa bf c3 1f b8 c1 02 00 b4',
                replacement='e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force otp verification to always return success',
            ),
        },
        cert_bypass=CertBypass.WRAP
    ),
    Device(
        'plato',
        'Xiaomi 12T',
        {
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 3a 00 00 94',
                replacement='e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Don\'t enforce secure boot policy',
            ),
            'force_green_state': PatchStage(
                'force_green_state',
                pattern='28 03 00 b0 00 49 02 b9 c0 03 5f d6',
                replacement='28 03 00 b0 1f 49 02 b9 c0 03 5f d6',
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
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                pattern='a8 1f 40 b9 1f 05 00 71 81 00 00 54',
                replacement='a8 1f 40 b9 1f 05 00 71 04 00 00 14',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute erase',
            ),
            'bypass_cmd_flash_control': PatchStage(
                'bypass_cmd_flash_control',
                pattern='e8 07 40 b9 1f 05 00 71 21 01 00 54',
                replacement='e8 07 40 b9 1f 05 00 71 09 00 00 14',
                match_mode=MatchMode.ALL,
                description='Skip lock error branch - always execute flash',
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
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
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
            'sec_otp_ver_get': PatchStage(
                'sec_otp_ver_get',
                pattern='ff 43 01 d1 fd 7b 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 43 00 91 f3 03 01 aa bf c3 1f b8 c1 02 00 b4',
                replacement='e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                description='Force otp verification to always return success',
            ),
        },
        cert_bypass=CertBypass.WRAP
    ),
    Device(
        'yunluo',
        'Redmi Pad / MT6789 yunluo',
        {
            # This is the minimal first-pass port. The same policy-check
            # sequence exists once in each executable LK stage of yunluo.
            'sec_get_vfy_policy': PatchStage(
                'sec_get_vfy_policy',
                pattern='00 01 00 b4 fd 7b bf a9',
                replacement='00 00 80 52 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                partition=['lk', 'bl2_ext', 'aee'],
                description='Disable the LK secure-boot policy check',
            ),
            # ------------------------------------------------------------------
            # The three patches below were each derived by disassembling yunluo's
            # own LK.  None of them reuses another device's pattern, because the
            # same byte sequence can mean something completely different here
            # (see the notes further down).
            #
            # lk 0x6fe28 = sec_otp_ver_get.  Its thunk at lk 0x2a9b0 prints
            # "Read otp version: Not avb or recovery group!".  It takes the otp
            # group in w0 and the out pointer in x1 (`0x6fe40 mov x19, x1`), and
            # only writes *out on the normal path - so a naive `return 0` stub
            # would leave *out uninitialised for the callers at 0x7ea3c/0x7ea54.
            # This stub returns 0 AND clears *out, keeping the original's NULL
            # guard (`cbz x1`).
            'sec_otp_ver_get': PatchStage(
                'sec_otp_ver_get',
                pattern='ff 43 01 d1 fd 7b 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 43 00 91 f3 03 01 aa bf c3 1f b8 c1 02 00 b4',
                # mov w0,#0 ; cbz x1,+8 ; str wzr,[x1] ; ret ; nop x5
                replacement='00 00 80 52 41 00 00 b4 3f 00 00 b9 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                partition='lk',
                description='Force OTP version verification to always succeed',
            ),
            # lk 0x2ab40 = sec_set_lock_state: it prints
            # "Seccfg set lock state failed!" / "Custom set lock state failed!"
            # and is called from exactly one place - the oem lock/unlock reporting
            # helper at lk 0x75538.  Making the setter a no-op keeps LK from ever
            # writing a locked seccfg, while the published getvar values
            # ("secure"/"unlocked"/"warranty") keep working.
            #
            # NOTE: the other devices' `dont_relock_seccfg` pattern hits lk
            # 0x75538 in yunluo, and 0x75538 is that *reporting helper* (it also
            # runs `oem unlock`'s flow).  Patching it would break
            # `fastboot oem lks` / getvar, so the lower-level setter is used.
            'dont_relock_seccfg': PatchStage(
                'dont_relock_seccfg',
                pattern='fd 7b be a9 f4 4f 01 a9 fd 03 00 91 d3 00 86 52 f4 03 00 2a 13 02 a0 72',
                # mov w0,#0 ; ret ; nop x4
                replacement='00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                partition='lk',
                description='Make sec_set_lock_state a no-op (never relock seccfg)',
            ),
            # lk 0x798d4 = libavb's avb_slot_verify
            # (external/lib/libavb/avb_slot_verify.c).  Its 4th argument is
            # `AvbSlotVerifyFlags flags`, copied into w26 at lk 0x798fc and tested
            # right below as `tbz w26, #0, 0x79acc` - that check rejects
            # AVB_HASHTREE_ERROR_MODE_LOGGING unless
            # AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR (bit 0) is set.
            # OR-ing bit 0 into flags makes verification errors tolerated.
            'avb_allow_verification_error': PatchStage(
                'avb_allow_verification_error',
                pattern='f3 03 05 aa f9 03 04 2a fa 03 03 2a f5 03 02 aa fb 03 01 aa f6 03 00 aa ff 4f 01 b9',
                # mov w26, w3  ->  orr w26, w3, #1
                replacement='f3 03 05 aa f9 03 04 2a 7a 00 00 32 f5 03 02 aa fb 03 01 aa f6 03 00 aa ff 4f 01 b9',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR',
            ),
            # ------------------------------------------------------------------
            # Boot-state patches. These are what Android actually reads to decide
            # whether the device is locked.
            #
            # LK publishes two relevant things on the kernel cmdline:
            #   androidboot.verifiedbootstate=green|yellow|orange|red
            #   androidboot.vbmeta.device_state=locked|unlocked
            #
            # verifiedbootstate comes from a single global ("vb_state") that is
            # only ever written through the tiny setter at lk 0x4aed4:
            #     adrp x8, ... ; str w0, [x8, #0x340] ; ret
            # Storing wzr instead of w0 pins vb_state to 0, and the pointer table
            # at lk 0x99878 maps index 0 -> "androidboot.verifiedbootstate=green".
            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # Boot state: LK internally GREEN, cmdline ORANGE.
            #
            # Two audiences need different answers from the same vb_state global
            # (VA 0xb5340, and it is touched at only four places):
            #   0x4aea8  ldrsw -> index into the cmdline string table
            #                     ("androidboot.verifiedbootstate=green|yellow|orange|red")
            #   0x4aec8  ldr   -> get_vb_state(), also read by 0xcfc8 / 0xdc00 / 0x4aaa4
            #   0x4aed4  str   -> set_vb_state(), the only writer
            #   0x4aee8  ldr   -> lk 0x4aee0, the logo overlay painter
            #
            #  * Everything internal must see GREEN (0): that is the "locked and
            #    verified" state, and it makes 0x4aee0 take its `b.ne 0x4afa0` exit
            #    so nothing is painted on the boot logo.  Done by pinning the setter
            #    itself to zero - one patch instead of chasing every reader.
            #  * Only the cmdline must say ORANGE: Android's fs_mgr/libfs_avb
            #    tolerates ERROR_VERIFICATION / PUBLIC_KEY_REJECTED only while
            #    ro.boot.verifiedbootstate == "orange" (measured: green+unlocked
            #    panics, orange boots).  This vbmeta is stock-signed with a few flag
            #    bits flipped, so its signature check always fails and the tolerance
            #    is mandatory.  Done by replacing the table index load with a
            #    constant 2.
            #
            # xaga's force_green_state does only the first half; that works there
            # because its vbmeta is untouched and never raises the error that needs
            # tolerating - but it panics here.
            'force_green_state': PatchStage(
                'force_green_state',
                # lk 0x4aed4: adrp x8 ; str w0,[x8,#0x340] ; ret  ->  str wzr
                pattern='48 03 00 f0 00 41 03 b9 c0 03 5f d6',
                replacement='48 03 00 f0 1f 41 03 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                partition='lk',
                description='Pin the LK-internal boot state to GREEN (locked/verified)',
            ),
            'spoof_cmdline_vb_state': PatchStage(
                'spoof_cmdline_vb_state',
                # lk 0x4aea8: ldrsw x8,[x8,#0x340] ; cmp w8,#3
                #         ->  mov   w8,#2           ; cmp w8,#3     (index 2 = ORANGE)
                pattern='08 41 83 b9 1f 0d 00 71',
                replacement='48 00 80 52 1f 0d 00 71',
                match_mode=MatchMode.ALL,
                partition='lk',
                description='Cmdline keeps androidboot.verifiedbootstate=orange (Android requires it)',
            ),
            # xaga-equivalent of `bypass_security_control`: skip the LKS_UNLOCK
            # branch and always fall through.  Verified by disassembly this is the
            # only "ldr w8,[sp,#N] ; cmp w8,#3 ; b.ne" sequence in yunluo's LK
            # (xaga's pattern uses sp offset 8, yunluo's uses 0x14, hence the
            # different bytes).  At lk 0x4aa44-0x4aa60 it guards the
            # `set_vb_state(2)` (orange) call:
            #     bl  sec_get_lock_state_adapter
            #     ldr w8, [sp, #0x14]
            #     cmp w8, #3
            #     b.ne skip          <-- patched to nop
            #     mov w0, #2
            #     bl  set_vb_state
            #
            # Harmless alongside force_green_state (which pins the setter to 0),
            # and it keeps the boot-state decision independent of lock state even
            # if force_green_state is ever disabled.
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='e8 17 40 b9 1f 0d 00 71 61 00 00 54',
                replacement='e8 17 40 b9 1f 0d 00 71 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                partition='lk',
                description='Skip the LKS_UNLOCK branch - always execute the boot-state path',
            ),
            # Second cmdline channel that reports the lock state:
            #   androidboot.vbmeta.device_state=locked|unlocked
            # Built by libavb's cmdline helper at lk 0x777b0:
            #     ldurb w8, [x29, #-0x40]     ; is_unlocked
            #     adrp  x9,  -> "unlocked"
            #     adrp  x10, -> "locked"
            #     csel  x2, x10, x9, eq       ; eq -> "locked"
            # Using x10 twice makes it unconditionally "locked", so Android sees
            # a locked bootloader (this is what the system UI reads).
            #
            # NOTE: this was DISABLED earlier because it panicked the boot.  That
            # was a misdiagnosis: at the time androidboot.verifiedbootstate was
            # still green, and the panic came from that.  Measured matrix:
            #     orange + unlocked -> boots
            #     green  + locked   -> panic
            #     green  + unlocked -> panic     <-- proves fs_mgr's tolerance test
            #                                        keys on verifiedbootstate, NOT on
            #                                        device_state
            # Since verifiedbootstate is now pinned to orange (see
            # spoof_cmdline_vb_state), reporting "locked" here is safe.
            'spoof_vbmeta_device_state': PatchStage(
                'spoof_vbmeta_device_state',
                pattern='1f 01 00 71 a1 01 00 f0 42 01 89 9a 21 64 18 91',
                replacement='1f 01 00 71 a1 01 00 f0 42 01 aa 09 21 64 18 91',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Force androidboot.vbmeta.device_state to "locked"',
            ),
            # The channel above does NOT work on its own - and this is the one
            # that actually decides what Android's Developer Options shows.
            #
            # xaga proves the mechanism: its /proc/bootconfig carries
            #     androidboot.vbmeta.device / .avb_version / .device_state="locked"
            # and Android derives ro.boot.flash.locked and
            # ro.secureboot.lockstate from androidboot.vbmeta.device_state.
            #
            # All three items are appended by libavb's cmdline helper at
            # lk 0x776b0..0x777c4, which only runs once vbmeta verification
            # succeeds.  yunluo has to keep AVB 2.0 disabled (the ported system
            # is not signed), so that whole block is skipped and all three go
            # missing:
            #     ro.boot.vbmeta.device_state   (empty)
            #     ro.boot.flash.locked          0
            #     ro.secureboot.lockstate       unlocked
            # which makes Developer Options report "unlocked".  spoof_vbmeta_
            # device_state above sits *behind* that skipped block, so it never
            # executes - measured on device, confirmed by /proc/bootconfig.
            #
            # So append the item ourselves on a path that always runs: the
            # verifiedbootstate emitter at lk 0x4aea4 pulls its string from the
            # table at lk 0x99878 and tail-calls the cmdline append helper:
            #     ldr x0, [x9, x8, lsl #3]
            #     b   append_cmdline          (lk 0x119c8)
            # That helper formats with " %s" (snprintf, see the literal at
            # lk 0x11a28), so a single string containing a space expands into two
            # separate cmdline items.
            #
            # The table is indexed by vb_state; spoof_cmdline_vb_state pins the
            # index to 2, and 0x4aea4 guards the load with `cmp w8,#3 / b.hi`
            # (plus force_green_state keeps vb_state at 0), so entries 0/1/3
            # (yellow / red / green) are never read.  Their 107 contiguous bytes
            # are reused for the combined string.
            #
            # Written at lk 0x99790 (103 bytes, covering "yellow\0", "red\0" and
            # "green\0"); the following "Red State" literal at lk 0x997fb is left
            # untouched:
            #   "androidboot.verifiedbootstate=orange
            #    androidboot.vbmeta.device_state=locked
            #    androidboot.flash.locked=1"
            #
            # flash.locked=1 is appended for ro.boot.flash.locked.  Measured on
            # device: that prop does NOT come from bootconfig (absent from both
            # /proc/bootconfig and /proc/cmdline) and init only carries a
            # start_waiting_for_property() reference to it, yet ro.boot.* can
            # only be written once - so supplying the androidboot.* item here
            # wins that race.
            #
            # NOTE: ro.secureboot.lockstate is NOT fixable from LK.  It is set by
            # /system_ext/etc/init/init.secureboot.rc:
            #   on init && property:ro.secureboot.devicelock=1 \
            #            && property:ro.boot.verifiedbootstate=orange
            #       setprop ro.secureboot.lockstate unlocked
            # and ro.secureboot.devicelock=1 comes from
            # /system_ext/etc/build.prop.  So it derives straight from
            # verifiedbootstate, which MUST stay orange for fs_mgr's
            # ERROR_VERIFICATION tolerance - a genuine deadlock that editing the
            # rc / system_ext would be needed to break, not LK.
            'spoof_vbmeta_device_state_cmdline': PatchStage(
                'spoof_vbmeta_device_state_cmdline',
                pattern='61 6e 64 72 6f 69 64 62 6f 6f 74 2e 76 65 72 69 66 69 65 64 62 6f 6f 74 73 74 61 74 65 3d 79 65 6c 6c 6f 77 00 61 6e 64 72 6f 69 64 62 6f 6f 74 2e 76 65 72 69 66 69 65 64 62 6f 6f 74 73 74 61 74 65 3d 72 65 64 00 61 6e 64 72 6f 69 64 62 6f 6f 74 2e 76 65 72 69 66 69 65 64 62 6f 6f 74 73 74 61 74 65 3d 67 72',
                replacement='61 6e 64 72 6f 69 64 62 6f 6f 74 2e 76 65 72 69 66 69 65 64 62 6f 6f 74 73 74 61 74 65 3d 6f 72 61 6e 67 65 20 61 6e 64 72 6f 69 64 62 6f 6f 74 2e 76 62 6d 65 74 61 2e 64 65 76 69 63 65 5f 73 74 61 74 65 3d 6c 6f 63 6b 65 64 20 61 6e 64 72 6f 69 64 62 6f 6f 74 2e 66 6c 61 73 68 2e 6c 6f 63 6b 65 64 3d 31 00',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Append vbmeta.device_state=locked and flash.locked=1 next to verifiedbootstate',
            ),
            # Repoint the vb_state table entry for index 2 (orange) at the
            # combined string above.  lk 0x99888 holds VA 0xffff000050f9956b
            # (the standalone "orange" literal) -> 0xffff000050f99590.
            'spoof_vbmeta_device_state_ptr': PatchStage(
                'spoof_vbmeta_device_state_ptr',
                pattern='6b 95 f9 50 00 00 ff ff',
                replacement='90 95 f9 50 00 00 ff ff',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Repoint vb_state table index 2 at the combined cmdline string',
            ),
            # ------------------------------------------------------------------
            # Still not ported (verified by disassembly, do NOT copy blindly):
            #   * `bypass_security_control` (`ldr w8,[sp,#8]; cmp w8,#3; b.ne`)
            #     and `bypass_lock_control` (`cmp w8,#3; b.ne`) have no matching
            #     instruction sequence anywhere in yunluo's LK.  Their intent is
            #     functionally covered by the command-scoped fastboot patches
            #     below, which are the yunluo-specific equivalent.
            #   * `bypass_region_check` / `spoof_custom_lock_state` are peridotl /
            #     duchamp specific and have no counterpart here.
            # ------------------------------------------------------------------
            # fastboot flash:/erase: has TWO independent lock gates in yunluo's LK.
            #
            # Gate 1 - command registration flags, checked by fastboot_command_loop
            # (lk 0x5740):
            #     if (((sboot_state == 0) || cmd->allowed_when_security_on)
            #             && (!cmd->forbidden_when_lock_on) || lock_state == LKS_UNLOCK)
            #         cmd->handle(...);
            #     else
            #         fastboot_fail("No support by lock control");
            # The command table is built at runtime by fastboot_register()
            # (lk 0x4f64), called from the single registration block at lk 0x7d40.
            # "flash:" and "erase:" are registered with forbidden_when_lock_on = 1
            # (only "download:" uses 0), so they are refused before the handler
            # even runs.  Patch flips that argument to wzr, exactly like "download:".
            #
            # Gate 2 - inside the handlers.  cmd_flash_bio (lk 0x7eb4) and
            # cmd_erase_bio (lk 0x8150) both call 0x2a998 -> 0x754fc, which writes
            # (lock_state != LKS_UNLOCK), then branch on it and fail with
            # "Flashing is not allowed in Lock state".  Patch makes the branch
            # unconditional so the handler always proceeds.
            #
            # Gate 1 and gate 2 must both be bypassed.  The registration patches
            # stay command scoped, so `oem ultraflash*` keeps its lock control and
            # the externally reported lock state is left untouched (still the
            # spoofed LKS_LOCK).
            'bypass_cmd_flash_lock_control': PatchStage(
                'bypass_cmd_flash_lock_control',
                # mov w2,#1 ; mov w3,#1 ; bl fastboot_register   ("flash:")
                pattern='22 00 80 52 23 00 80 52 79 f4 ff 97',
                # mov w2,#1 ; mov w3,wzr ; bl fastboot_register
                replacement='22 00 80 52 e3 03 1f 2a 79 f4 ff 97',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Register fastboot "flash:" with forbidden_when_lock_on=0',
            ),
            'bypass_cmd_erase_lock_control': PatchStage(
                'bypass_cmd_erase_lock_control',
                # mov w2,#1 ; mov w3,#1 ; bl fastboot_register   ("erase:")
                pattern='22 00 80 52 23 00 80 52 72 f4 ff 97',
                # mov w2,#1 ; mov w3,wzr ; bl fastboot_register
                replacement='22 00 80 52 e3 03 1f 2a 72 f4 ff 97',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='Register fastboot "erase:" with forbidden_when_lock_on=0',
            ),
            'bypass_flash_handler_lock_check': PatchStage(
                'bypass_flash_handler_lock_check',
                # cmd_flash_bio: ldr w8,[sp,#4] ; cmp w8,#1 ; b.ne 0x7f64
                pattern='e8 07 40 b9 1f 05 00 71 21 01 00 54',
                # b 0x7f64
                replacement='e8 07 40 b9 1f 05 00 71 09 00 00 14',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='cmd_flash_bio: skip "Flashing is not allowed in Lock state"',
            ),
            'bypass_erase_handler_lock_check': PatchStage(
                'bypass_erase_handler_lock_check',
                # cmd_erase_bio: ldr w8,[x29,#28] ; cmp w8,#1 ; b.ne 0x81e8
                pattern='a8 1f 40 b9 1f 05 00 71 81 00 00 54',
                # b 0x81e8
                replacement='a8 1f 40 b9 1f 05 00 71 04 00 00 14',
                match_mode=MatchMode.FIRST,
                partition='lk',
                description='cmd_erase_bio: skip "Flashing is not allowed in Lock state"',
            ),
            'spoof_lock_state': PatchStage(
                'spoof_lock_state',
                pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa',
                replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
                match_mode=MatchMode.ALL,
                partition=['lk', 'bl2_ext', 'aee'],
                description='Force LK lock-state queries to report locked',
            ),
            'spoof_sboot_state': PatchStage(
                'spoof_sboot_state',
                pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52 c9',
                replacement='48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
                match_mode=MatchMode.ALL,
                partition=['lk', 'bl2_ext', 'aee'],
                description='Force sboot-state queries to report locked/verified state',
            ),
        },
        # yunluo is legacy V6: leave CERT2 untouched here; pwnage24mtk
        # applies the single --legacy wrapper after all byte patches.
        cert_bypass=None,
    ),
]
