from typing import List, Union
from enum import Enum


class MatchMode(Enum):
    FIRST = 0
    ALL = -1


class PatternMatcher:
    @staticmethod
    def hex_to_bytes(hex_string: str) -> bytes:
        hex_string = hex_string.replace(' ', '').replace('0x', '')
        if len(hex_string) % 2:
            hex_string = '0' + hex_string
        return bytes.fromhex(hex_string)

    @staticmethod
    def find_pattern_matches(data: bytearray, pattern: bytes) -> List[int]:
        matches = []
        start = 0
        while True:
            index = data.find(pattern, start)
            if index == -1:
                break
            matches.append(index)
            start = index + 1
        return matches

    @staticmethod
    def apply_variable_patch(data: bytearray, pattern: bytes, replacement: bytes, 
                           match_mode: Union[int, MatchMode]) -> int:
        matches = PatternMatcher.find_pattern_matches(data, pattern)
        
        if not matches:
            return 0
        
        patches_applied = 0
        
        if isinstance(match_mode, MatchMode):
            if match_mode == MatchMode.ALL:
                for match_offset in reversed(matches):
                    PatternMatcher._apply_single_patch(data, match_offset, pattern, replacement)
                    patches_applied += 1
            elif match_mode == MatchMode.FIRST and matches:
                match_offset = matches[0]
                PatternMatcher._apply_single_patch(data, match_offset, pattern, replacement)
                patches_applied = 1
        elif isinstance(match_mode, int):
            if match_mode == -1:
                for match_offset in reversed(matches):
                    PatternMatcher._apply_single_patch(data, match_offset, pattern, replacement)
                    patches_applied += 1
            elif 0 <= match_mode < len(matches):
                match_offset = matches[match_mode]
                PatternMatcher._apply_single_patch(data, match_offset, pattern, replacement)
                patches_applied = 1
        
        return patches_applied

    @staticmethod
    def _apply_single_patch(data: bytearray, offset: int, pattern: bytes, replacement: bytes) -> None:
        original_len = len(pattern)
        replacement_len = len(replacement)
        
        if replacement_len <= original_len:
            data[offset:offset + replacement_len] = replacement
        else:
            data[offset:offset + original_len] = replacement[:original_len]
            for i, byte in enumerate(replacement[original_len:]):
                data.insert(offset + original_len + i, byte)