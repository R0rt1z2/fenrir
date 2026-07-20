from typing import Any, Dict, Optional

from cert_bypass import CertBypass
from injector import BootloaderInjector


class Device:
    def __init__(self, name: str, codename: str, stages: Dict[str, Any],
                 base: Optional[int] = None,
                 cert_bypass: Optional[CertBypass] = None,
                 **kwargs: Any) -> None:
        self.name: str = name
        self.codename: str = codename
        self.stages: Dict[str, Any] = stages
        self.base: Optional[int] = base
        self.cert_bypass: Optional[CertBypass] = cert_bypass
        self.device_opts: Dict[str, Any] = kwargs

    def execute(self, args: Any) -> int:
        injector: BootloaderInjector = BootloaderInjector(
            args.image,
            args.payload_dir,
            base=self.base,
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

        if not injector.inject_all_stages():
            return 1

        if self.cert_bypass is not None:
            injector.apply_cert_bypass(self.cert_bypass)

        injector.save_patched_bootloader(args.output)
        return 0
