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
            'stage1': PayloadStage(
                'stage1',
                0xFFFF000050F6F0A8,  # emmc_init()
                0xFFFF000050F05DA4,  # platform_init()
                description='Pre-platform initialization stage',
            ),
            'stage2': PayloadStage(
                'stage2',
                0xFFFF000050F6AE98, # msdc_tune_cmdrsp()
                0xFFFF000050F0E088, # bl notify_enter_fastboot()
                description='Pre-fastboot initialization stage',
            ),
            'stage3': PayloadStage(
                'stage3',
                0xFFFF000050F6C168, # msdc_config_bus()
                0xFFFF000050F0E0A4, # bl dprintf("%s:%d: Notify boot linux.\n")
                description='Linux initialization stage',
            ),

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
                pattern='a8 03 00 f0 00 21 01 b9 c0 03 5f d6',
                replacement='a8 03 00 f0 1f 21 01 b9 c0 03 5f d6',
                match_mode=MatchMode.ALL,
                description='Force boot state to always be set to green',
            ),
            'bypass_security_control': PatchStage(
                'bypass_security_control',
                pattern='24 74 01 94 20 01 00 36',
                replacement='24 74 01 94 1f 20 03 d5',
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
            'bypass_security_control': PatchStage(
            'bypass_security_control',
            pattern='24 74 01 94 20 01 00 36',
            replacement='24 74 01 94 1f 20 03 d5',  # NOP instead of branch
            match_mode=MatchMode.ALL,
            description='Skip security error branch - always execute commands',
        )
    },
    base=0xFFFF000050700000
),
        },

        # This is the virtual address where 'lk' (not the image but the partition)
        # is loaded in memory. You can obtain this address by looking at the
        # 'expdb' partition of the device, which contains boot logs.
        base=0xFFFF000050F00000,
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
            ),
            'bypass_security_control': PatchStage(
            'bypass_security_control',
            pattern='24 74 01 94 20 01 00 36',
            replacement='24 74 01 94 1f 20 03 d5',  # NOP instead of branch
            match_mode=MatchMode.ALL,
            description='Skip security error branch - always execute commands',
        ),
    },
    base=0xFFFF000050700000
),
    Device(
        'LG8n',
        'Tecno Pova 4 Pro',
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
        base=0xFFFF000050F00000
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
        base=0xFFFF000050F00000
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
        base=0xFFFF000050F00000
    )
]
