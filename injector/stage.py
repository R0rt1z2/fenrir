from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Tuple, Union
from utils import inject_payload, HDR_SIZE, encode_bl
from patch_utils import PatternMatcher, MatchMode


class Stage(ABC):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, enabled: bool = True, description: str = "", **kwargs: Any) -> None:
        self.name: str = name
        self.base_addr: int = base_addr
        self.pivot_addr: int = pivot_addr
        self.enabled: bool = enabled
        self.description: str = description
        self.stage_opts: Dict[str, Any] = kwargs

    @abstractmethod
    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        pass

    def is_enabled(self) -> bool:
        return self.enabled

    def get_addresses(self) -> Tuple[int, int]:
        return self.base_addr, self.pivot_addr

    def get_description(self) -> str:
        return self.description

    def execute(self, data: bytearray, payload_dir: Path, bootloader_base: int, device_name: str) -> bytearray:
        if not self.enabled:
            return data

        payload: bytes = self.load_payload(payload_dir, device_name)
        data, payload_vaddr = inject_payload(data, payload, self.base_addr, bootloader_base)

        pivot_offset: int = self.pivot_addr - bootloader_base + HDR_SIZE
        branch_inst: bytes = encode_bl(self.pivot_addr, payload_vaddr)
        data[pivot_offset:pivot_offset + 4] = branch_inst

        print("Successfully injected stage '%s' at 0x%08X with pivot at 0x%08X" % (self.name, self.base_addr, self.pivot_addr))

        return data


class PayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_file: str = "payload.bin", description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_file: str = payload_file

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        payload_path: Path = payload_dir / device_name.lower() / self.name / self.payload_file

        if not payload_path.exists():
            raise RuntimeError("Payload not found: %s" % payload_path)

        with open(payload_path, 'rb') as f:
            payload: bytes = f.read()

        return payload.ljust((len(payload) + 15) & ~15, b'\x00')


class CustomPayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_path: str, description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_path: Path = Path(payload_path)

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        if not self.payload_path.exists():
            raise RuntimeError("Custom payload not found: %s" % self.payload_path)

        with open(self.payload_path, 'rb') as f:
            payload: bytes = f.read()

        return payload.ljust((len(payload) + 15) & ~15, b'\x00')


class InlinePayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_data: bytes, description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_data: bytes = payload_data

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        return self.payload_data.ljust((len(self.payload_data) + 15) & ~15, b'\x00')


class PatchStage(Stage):
    def __init__(self, name: str, pattern: Union[str, bytes], replacement: Union[str, bytes], 
                 match_mode: Union[int, MatchMode] = MatchMode.FIRST, description: str = "", **kwargs: Any) -> None:
        super().__init__(name, 0, 0, description=description, **kwargs)
        
        if isinstance(pattern, str):
            self.pattern: bytes = PatternMatcher.hex_to_bytes(pattern)
        else:
            self.pattern = pattern
            
        self.match_mode: Union[int, MatchMode] = match_mode
        self.replacement: bytes = self._process_replacement(replacement)

    def _process_replacement(self, replacement: Union[str, bytes]) -> bytes:
        if isinstance(replacement, bytes):
            return replacement
        
        return PatternMatcher.hex_to_bytes(replacement)

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        return b''

    def execute(self, data: bytearray, payload_dir: Path, bootloader_base: int, device_name: str) -> bytearray:
        if not self.enabled:
            return data

        patches_applied = PatternMatcher.apply_variable_patch(data, self.pattern, self.replacement, self.match_mode)
        
        if patches_applied > 0:
            match_desc = "all matches" if self.match_mode == -1 or self.match_mode == MatchMode.ALL else "match #%s" % (self.match_mode if isinstance(self.match_mode, int) and self.match_mode >= 0 else 'first')
            print("Successfully applied patch '%s': %d bytes -> %d bytes (%s)" % 
                  (self.name, len(self.pattern), len(self.replacement), match_desc))
        else:
            print("Warning: Pattern not found for patch '%s'" % self.name)

        return data


class StageFactory:
    @staticmethod
    def create_stage(name: str, config: Dict[str, Any]) -> Stage:
        stage_type: str = config.get("type", "payload")
        enabled: bool = config.get("enabled", True)
        description: str = config.get("description", "")

        if stage_type == "payload":
            base_addr: int = config["base"]
            pivot_addr: int = config["pivot"]
            payload_file: str = config.get("payload_file", "payload.bin")
            return PayloadStage(name, base_addr, pivot_addr, payload_file, description=description, enabled=enabled)
        elif stage_type == "custom":
            base_addr: int = config["base"]
            pivot_addr: int = config["pivot"]
            payload_path: str = config["payload_path"]
            return CustomPayloadStage(name, base_addr, pivot_addr, payload_path, description=description, enabled=enabled)
        elif stage_type == "inline":
            base_addr: int = config["base"]
            pivot_addr: int = config["pivot"]
            payload_data: bytes = bytes.fromhex(config["payload_hex"])
            return InlinePayloadStage(name, base_addr, pivot_addr, payload_data, description=description, enabled=enabled)
        elif stage_type == "patch":
            pattern: Union[str, bytes] = config["pattern"]
            replacement: Union[str, bytes] = config["replacement"]
            match_mode_val = config.get("match_mode", "first")
            
            if isinstance(match_mode_val, str):
                if match_mode_val.lower() == "all":
                    match_mode = MatchMode.ALL
                elif match_mode_val.lower() == "first":
                    match_mode = MatchMode.FIRST
                else:
                    match_mode = int(match_mode_val)
            else:
                match_mode = match_mode_val
            
            return PatchStage(name, pattern, replacement, match_mode, description=description, enabled=enabled)
        else:
            raise ValueError("Unknown stage type: %s" % stage_type)

    @staticmethod
    def create_from_legacy(name: str, config: Dict[str, Any]) -> Stage:
        return PayloadStage(
            name,
            config["base"],
            config["pivot"],
            description=config.get("description", ""),
            enabled=config.get("enabled", True)
        )