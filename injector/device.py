from typing import Dict, Any
from injector import BootloaderInjector


class Device:
    def __init__(self, name: str, codename: str, stages: Dict[str, Any], 
                 base: int = 0xFFFF000050F00000, **kwargs: Any) -> None:
        self.name: str = name
        self.codename: str = codename
        self.stages: Dict[str, Any] = stages
        self.base: int = base
        self.device_opts: Dict[str, Any] = kwargs

    def execute(self, args: Any) -> int:
        injector: BootloaderInjector = BootloaderInjector(
            args.image, 
            args.payload_dir,
            bootloader_base=self.base,
            device_name=self.name
        )
        injector.stages = self.stages.copy()
        
        if args.config:
            injector.load_config(args.config)
        
        if args.list_stages:
            print("Available stages for %s (%s):" % (self.name, self.codename))
            for stage_name in injector.list_stages():
                stage = injector.stages[stage_name]
                base_addr, pivot_addr = stage.get_addresses()
                status = "enabled" if stage.is_enabled() else "disabled"
                description = stage.get_description()
                desc_text = " - %s" % description if description else ""
                print("  %s: base=0x%X, pivot=0x%X (%s)%s" % (stage_name, base_addr, pivot_addr, status, desc_text))
            return 0
        
        if injector.inject_all_stages():
            injector.save_patched_bootloader(args.output)
            return 0
        else:
            return 1