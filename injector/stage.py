from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from liblk.image import LkImage
from liblk.structures.partition import LkPartition
from patch_utils import MatchMode, PatternMatcher
from utils import encode_bl, pad_payload


@dataclass
class InjectionContext:
    image: LkImage
    lk: LkPartition
    base: int
    payload_dir: Path
    device_name: str


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

    def execute(self, ctx: InjectionContext) -> None:
        if not self.enabled:
            return

        payload: bytes = self.load_payload(ctx.payload_dir, ctx.device_name)
        data: bytearray = bytearray(ctx.lk.data)

        payload_off: int = self.base_addr - ctx.base
        if payload_off < 0 or payload_off + len(payload) > len(data):
            raise ValueError("Target address 0x%X is outside 'lk' partition bounds" % self.base_addr)
        data[payload_off:payload_off + len(payload)] = payload

        pivot_off: int = self.pivot_addr - ctx.base
        if pivot_off < 0 or pivot_off + 4 > len(data):
            raise ValueError("Pivot address 0x%X is outside 'lk' partition bounds" % self.pivot_addr)
        data[pivot_off:pivot_off + 4] = encode_bl(self.pivot_addr, self.base_addr)

        ctx.lk.data = bytes(data)

        print("Injected stage '%s'" % self.name)


class PayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_file: str = "payload.bin", description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_file: str = payload_file

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        payload_path: Path = payload_dir / device_name.lower() / self.name / self.payload_file

        if not payload_path.exists():
            raise FileNotFoundError("Payload not found: %s" % payload_path)

        with open(payload_path, 'rb') as f:
            payload: bytes = f.read()

        return pad_payload(payload)


class CustomPayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_path: str, description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_path: Path = Path(payload_path)

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        if not self.payload_path.exists():
            raise FileNotFoundError("Custom payload not found: %s" % self.payload_path)

        with open(self.payload_path, 'rb') as f:
            payload: bytes = f.read()

        return pad_payload(payload)


class InlinePayloadStage(Stage):
    def __init__(self, name: str, base_addr: int, pivot_addr: int, payload_data: bytes, description: str = "", **kwargs: Any) -> None:
        super().__init__(name, base_addr, pivot_addr, description=description, **kwargs)
        self.payload_data: bytes = payload_data

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        return pad_payload(self.payload_data)


class PatchStage(Stage):
    def __init__(self, name: str, pattern: Union[str, bytes], replacement: Union[str, bytes],
                 match_mode: Union[int, MatchMode] = MatchMode.FIRST, partition: Optional[str] = None,
                 description: str = "", **kwargs: Any) -> None:
        super().__init__(name, 0, 0, description=description, **kwargs)

        if isinstance(pattern, str):
            self.pattern: bytes = PatternMatcher.hex_to_bytes(pattern)
        else:
            self.pattern = pattern

        self.match_mode: Union[int, MatchMode] = match_mode
        self.partition: Optional[str] = partition
        self.replacement: bytes = self._process_replacement(replacement)

    def _process_replacement(self, replacement: Union[str, bytes]) -> bytes:
        if isinstance(replacement, bytes):
            return replacement

        return PatternMatcher.hex_to_bytes(replacement)

    def load_payload(self, payload_dir: Path, device_name: str) -> bytes:
        return b''

    def _select_matches(self, matches: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
        if isinstance(self.match_mode, MatchMode):
            if self.match_mode == MatchMode.ALL:
                return matches
            return matches[:1]

        if self.match_mode == -1:
            return matches
        if 0 <= self.match_mode < len(matches):
            return [matches[self.match_mode]]
        return []

    def execute(self, ctx: InjectionContext) -> None:
        if not self.enabled:
            return

        if self.partition is not None:
            if self.partition not in ctx.image.partitions:
                print("Warning: partition '%s' not found for patch '%s'" % (self.partition, self.name))
                return
            targets: List[Tuple[str, LkPartition]] = [(self.partition, ctx.image.partitions[self.partition])]
        else:
            targets = list(ctx.image.partitions.items())

        matches: List[Tuple[str, int]] = []
        for part_name, part in targets:
            data: bytes = part.data
            start: int = 0
            while True:
                idx: int = data.find(self.pattern, start)
                if idx == -1:
                    break
                matches.append((part_name, idx))
                start = idx + 1

        selected: List[Tuple[str, int]] = self._select_matches(matches)

        if not selected:
            print("Warning: Pattern not found for patch '%s'" % self.name)
            return

        by_partition: Dict[str, List[int]] = {}
        for part_name, offset in selected:
            by_partition.setdefault(part_name, []).append(offset)

        applied: int = 0
        for part_name, offsets in by_partition.items():
            part = ctx.image.partitions[part_name]
            data_buf: bytearray = bytearray(part.data)
            for offset in sorted(offsets, reverse=True):
                PatternMatcher._apply_single_patch(data_buf, offset, self.pattern, self.replacement)
                applied += 1
            part.data = bytes(data_buf)

        match_desc = "all matches" if self.match_mode in (-1, MatchMode.ALL) else "first match" if self.match_mode == MatchMode.FIRST else "match #%s" % self.match_mode
        print("Successfully applied patch '%s': %d bytes -> %d bytes (%s, %d hit(s))" %
              (self.name, len(self.pattern), len(self.replacement), match_desc, applied))


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
            base_addr = config["base"]
            pivot_addr = config["pivot"]
            payload_path: str = config["payload_path"]
            return CustomPayloadStage(name, base_addr, pivot_addr, payload_path, description=description, enabled=enabled)
        elif stage_type == "inline":
            base_addr = config["base"]
            pivot_addr = config["pivot"]
            payload_data: bytes = bytes.fromhex(config["payload_hex"])
            return InlinePayloadStage(name, base_addr, pivot_addr, payload_data, description=description, enabled=enabled)
        elif stage_type == "patch":
            pattern: Union[str, bytes] = config["pattern"]
            replacement: Union[str, bytes] = config["replacement"]
            partition: Optional[str] = config.get("partition")
            match_mode_val = config.get("match_mode", "first")

            if isinstance(match_mode_val, str):
                if match_mode_val.lower() == "all":
                    match_mode: Union[int, MatchMode] = MatchMode.ALL
                elif match_mode_val.lower() == "first":
                    match_mode = MatchMode.FIRST
                else:
                    match_mode = int(match_mode_val)
            else:
                match_mode = match_mode_val

            return PatchStage(name, pattern, replacement, match_mode, partition=partition, description=description, enabled=enabled)
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