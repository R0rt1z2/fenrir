import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from liblk.image import LkImage

from cert_bypass import CertBypass, apply_cert_bypass
from stage import InjectionContext, Stage, StageFactory


class BootloaderInjector:
    def __init__(self, bootloader_path: str, payload_dir: str = "payload/build",
                 base: Optional[int] = None, device_name: Optional[str] = None) -> None:
        self.bootloader_path: Path = Path(bootloader_path)
        self.payload_dir: Path = Path(payload_dir)
        self.device_name: Optional[str] = device_name
        self.stages: Dict[str, Stage] = {}

        if not self.bootloader_path.exists():
            raise RuntimeError("Bootloader not found: %s" % bootloader_path)

        self.image: LkImage = LkImage(str(self.bootloader_path))

        self.lk = self.image.partitions.get('lk')
        if self.lk is None:
            raise RuntimeError("No 'lk' partition found in %s" % bootloader_path)

        self.base: int = base or self.lk.lk_address or self.lk.header.memory_address
        self._trailing: bytes = self._compute_trailing()
        self._finalized: bool = False

    def _compute_trailing(self) -> bytes:
        region_end: int = 0
        for partition in self.image.partitions.values():
            region_end = max(region_end, partition.end_offset)
            for cert in partition.certs:
                region_end = max(region_end, cert.end_offset)
        return bytes(self.image.contents[region_end:])

    def load_config(self, config_path: str) -> None:
        with open(config_path, 'r') as f:
            config: Dict[str, Any] = json.load(f)

        if "stages" not in config:
            raise ValueError("Invalid config file: missing 'stages' key")

        self.stages.clear()
        for stage_name, stage_config in config["stages"].items():
            if isinstance(stage_config.get("base"), str):
                stage_config["base"] = int(stage_config["base"], 0)
            if isinstance(stage_config.get("pivot"), str):
                stage_config["pivot"] = int(stage_config["pivot"], 0)

            if "type" in stage_config:
                stage: Stage = StageFactory.create_stage(stage_name, stage_config)
            else:
                stage = StageFactory.create_from_legacy(stage_name, stage_config)

            self.stages[stage_name] = stage

    def add_stage(self, stage: Stage) -> None:
        self.stages[stage.name] = stage

    def remove_stage(self, stage_name: str) -> None:
        if stage_name in self.stages:
            del self.stages[stage_name]

    def update_stage_description(self, stage_name: str, description: str) -> None:
        if stage_name in self.stages:
            self.stages[stage_name].description = description

    def list_stages(self) -> List[str]:
        return list(self.stages.keys())

    def inject_all_stages(self) -> bool:
        ctx: InjectionContext = InjectionContext(
            self.image, self.lk, self.base, self.payload_dir, self.device_name or ''
        )

        injected_stages: List[str] = []
        payload_stages_skipped: List[str] = []

        for stage_name, stage in self.stages.items():
            if not stage.is_enabled():
                continue
            try:
                stage.execute(ctx)
                injected_stages.append(stage_name)
            except FileNotFoundError as e:
                if "payload" in str(e).lower():
                    print("Warning: Skipping payload stage %s (payload file not found)" % stage_name)
                    payload_stages_skipped.append(stage_name)
                    continue
                print("Error injecting %s: %s" % (stage_name, e))
                return False
            except Exception as e:
                print("Error injecting %s: %s" % (stage_name, e))
                return False

        if payload_stages_skipped:
            print("Skipped %d payload stages, applied %d patches" % (len(payload_stages_skipped), len(injected_stages)))

        return len(injected_stages) > 0 or len(payload_stages_skipped) > 0

    def apply_cert_bypass(self, mode: CertBypass = CertBypass.OVERRIDE) -> List[str]:
        signed: List[str] = apply_cert_bypass(self.image, self._trailing, mode)
        if signed:
            self._finalized = True
        return signed

    def save_patched_bootloader(self, output_path: str) -> None:
        if not self._finalized:
            self.image._rebuild_contents()
            self.image.contents = bytearray(self.image.contents) + bytearray(self._trailing)
            self._finalized = True

        try:
            with open(output_path, 'wb') as f:
                f.write(bytes(self.image.contents))
        except Exception as e:
            raise RuntimeError("Error writing output file: %s" % e)
