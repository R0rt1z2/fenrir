import struct
import json
from pathlib import Path
from typing import Dict, Optional, Any, List
from stage import Stage, StageFactory


class BootloaderInjector:
    def __init__(self, bootloader_path: str, payload_dir: str = "payload/build", 
                 bootloader_base: int = 0xFFFF000050F00000, device_name: str = None) -> None:
        self.bootloader_path: Path = Path(bootloader_path)
        self.payload_dir: Path = Path(payload_dir)
        self.stages: Dict[str, Stage] = {}
        self.data: Optional[bytearray] = None
        self.original_code_sz: Optional[int] = None
        self.bootloader_base: int = bootloader_base
        self.device_name: str = device_name

        if not self.bootloader_path.exists():
            raise RuntimeError("Bootloader not found: %s" % bootloader_path)

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

    def load_bootloader(self) -> None:
        try:
            with open(self.bootloader_path, 'rb') as f:
                header: bytes = f.read(4)

                # This is required for signed bootloader images
                f.seek(0x4040 if header == b'BFBF' else 0)
                self.data = bytearray(f.read())
        except Exception as e:
            raise RuntimeError("Error reading bootloader image: %s" % e)

        _, self.original_code_sz = struct.unpack('<II', self.data[:8])

    def inject_all_stages(self) -> bool:
        self.load_bootloader()

        injected_stages: List[str] = []
        for stage_name, stage in self.stages.items():
            if stage.is_enabled():
                try:
                    self.data = stage.execute(self.data, self.payload_dir, self.bootloader_base, self.device_name)
                    injected_stages.append(stage_name)
                except Exception as e:
                    print("Error injecting %s: %s" % (stage_name, e))
                    return False

        return len(injected_stages) > 0

    def save_patched_bootloader(self, output_path: str) -> None:
        if self.data is None:
            raise RuntimeError("No bootloader data loaded")

        try:
            with open(output_path, 'wb') as f:
                f.write(self.data)
        except Exception as e:
            raise RuntimeError("Error writing output file: %s" % e)