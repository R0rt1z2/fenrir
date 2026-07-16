from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Optional

from injector import BootloaderInjector


class Device:
    def __init__(self, name: str, codename: str, stages: Dict[str, Any],
                 base: Optional[int] = None, cert_bypass: bool = False,
                 **kwargs: Any) -> None:
        self.name: str = name
        self.codename: str = codename
        self.stages: Dict[str, Any] = stages
        self.base: Optional[int] = base
        self.cert_bypass: bool = cert_bypass
        self.device_opts: Dict[str, Any] = kwargs

    def execute(self, args: Any) -> int:
        expected_sha256 = self.device_opts.get("expected_sha256")
        if expected_sha256:
            expected_hashes = (
                [expected_sha256]
                if isinstance(expected_sha256, str)
                else list(expected_sha256)
            )
            actual_sha256 = sha256(Path(args.image).read_bytes()).hexdigest()
            if actual_sha256.lower() not in [h.lower() for h in expected_hashes]:
                raise RuntimeError(
                    "Input image SHA256 mismatch for %s: expected one of %s, got %s"
                    % (self.name, ", ".join(expected_hashes), actual_sha256)
                )

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

        if self.cert_bypass:
            injector.apply_cert_bypass()

        injector.save_patched_bootloader(args.output)
        return 0
