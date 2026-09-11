#!/usr/bin/env python3
"""
patch_bl2_ext.py — Patch MTK bl2_ext signature verification (EXPERIMENTAL)

Heuristically locates and patches verification check functions in bl2_ext.
Developed based on MT6895 and MT6991 samples — may not work on all SoCs.
Always use --dry-run first to review patch points.

NOTE: Not all V6 devices require bl2_ext patching. Some bl2_ext binaries
skip verification when SBC efuse is not blown, or use CERT2-based verification
that can be bypassed without code patching. Only patch if cert bypass alone
fails to load modified LK/ATF.

Supports standalone bl2_ext.bin and MKIMG composite images (lk.img).

Usage:
    python3 patch_bl2_ext.py lk.img --minimal --dry-run
    python3 patch_bl2_ext.py lk.img --minimal -o lk_patched.img
    python3 patch_bl2_ext.py bl2_ext.bin -o bl2_ext_patched.bin
"""

import argparse
import struct
import sys

PART_MAGIC = 0x58881688
HDR_SZ = 512
PART_HDR_FMT = '<II32sIIIIIIIIII'

MOV_W0_WZR = 0x2A1F03E0
INSN_RET   = 0xD65F03C0
INSN_NOP   = 0xD503201F
PACIASP    = 0xD503233F
AUTIASP    = 0xD50323BF

SEC_STRINGS = [
    b'cert chain vfy fail',
    b'image auth fail',
    b'header auth fail',
]
SBC_STRINGS = [
    b'[SBC] sbc_en = %d',
    b'[SBC] sbc_en = 1',
]

# ─── ARM64 helpers ───

def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]

def p32(v):
    return struct.pack('<I', v)

def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v

def bl_tgt(insn, pc):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    return pc + sext(insn & 0x3FFFFFF, 26) * 4

def b_tgt(insn, pc):
    if (insn & 0xFC000000) != 0x14000000:
        return None
    return pc + sext(insn & 0x3FFFFFF, 26) * 4

def cbz_tgt(insn, pc):
    if ((insn >> 25) & 0x3F) != 0x1A:
        return None
    return pc + sext((insn >> 5) & 0x7FFFF, 19) * 4

def cbz_is_nz(insn):
    return bool(insn & (1 << 24))

def cbz_reg(insn):
    return insn & 0x1F

def adrp_page(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    lo = (insn >> 29) & 3
    hi = (insn >> 5) & 0x7FFFF
    imm = sext((hi << 2) | lo, 21)
    return (pc & ~0xFFF) + (imm << 12)

def add_imm(insn):
    if (insn & 0x7F800000) not in (0x11000000, 0x91000000):
        return None
    sh = (insn >> 22) & 3
    imm12 = (insn >> 10) & 0xFFF
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    if sh == 1:
        imm12 <<= 12
    return (rd, rn, imm12)

def is_mov_wx_w0(insn):
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        rm = (insn >> 16) & 0x1F
        if rm == 0:
            return insn & 0x1F
    return None

def is_func_prologue(insn):
    if (insn & 0xFFC07FFF) == 0xA9807BFD:
        return True
    if (insn & 0xFF8003FF) == 0xD10003FF:
        return True
    return False

# ─── Search utilities ───

def find_all_bytes(data, pattern):
    result, start = [], 0
    while True:
        idx = data.find(pattern, start)
        if idx < 0:
            break
        result.append(idx)
        start = idx + 1
    return result

def find_xrefs(code, target, scan_limit):
    page = target & ~0xFFF
    low = target & 0xFFF
    refs = []
    for pc in range(0, min(scan_limit, len(code) - 8), 4):
        insn = u32(code, pc)
        p = adrp_page(insn, pc)
        if p is None or p != page:
            continue
        reg = insn & 0x1F
        for d in range(4, 24, 4):
            npc = pc + d
            if npc >= min(scan_limit, len(code) - 4):
                break
            ai = add_imm(u32(code, npc))
            if ai and ai[0] == reg and ai[1] == reg and ai[2] == low:
                refs.append(pc)
                break
    return refs

def find_func_start(code, addr, max_back=0x400):
    for off in range(addr & ~3, max((addr & ~3) - max_back, 0), -4):
        if is_func_prologue(u32(code, off)):
            return off
    return None

def follow_trampoline(code, addr, depth=4):
    seen = set()
    for _ in range(depth):
        if addr in seen or addr < 0 or addr + 4 > len(code):
            break
        seen.add(addr)
        insn = u32(code, addr)
        t = b_tgt(insn, addr)
        if t is not None:
            addr = t
            continue
        if insn == PACIASP and addr + 12 <= len(code):
            n1 = u32(code, addr + 4)
            if n1 == AUTIASP:
                t2 = b_tgt(u32(code, addr + 8), addr + 8)
                if t2 is not None:
                    addr = t2
                    continue
        break
    return addr

# ─── Trampoline table detection ───

def find_trampoline_tables(code, scan_limit):
    tables = []
    i = 0
    while i < scan_limit - 4:
        insn = u32(code, i)

        # Simple B trampoline: 4+ consecutive B to high addresses
        t = b_tgt(insn, i)
        if t is not None and t > scan_limit * 0.3:
            entries = [(i, t)]
            j = i + 4
            while j < scan_limit - 4:
                nt = b_tgt(u32(code, j), j)
                if nt is not None and nt > scan_limit * 0.3:
                    entries.append((j, nt))
                    j += 4
                else:
                    break
            if len(entries) >= 4:
                tables.append(('simple', entries))
            i = j
            continue

        # PAC trampoline: PACIASP + AUTIASP + B, 4+ consecutive
        if insn == PACIASP and i + 12 <= scan_limit:
            n1 = u32(code, i + 4)
            if n1 == AUTIASP:
                t = b_tgt(u32(code, i + 8), i + 8)
                if t is not None:
                    entries = [(i, t)]
                    j = i + 12
                    while j + 12 <= scan_limit:
                        p1 = u32(code, j)
                        p2 = u32(code, j + 4)
                        if p1 == PACIASP and p2 == AUTIASP:
                            pt = b_tgt(u32(code, j + 8), j + 8)
                            if pt is not None:
                                entries.append((j, pt))
                                j += 12
                                continue
                        break
                    if len(entries) >= 4:
                        tables.append(('pac', entries))
                    i = j
                    continue
        i += 4
    return tables

# ─── Verification pattern detection ───

def count_bl_cbz_in_region(code, start, end):
    count = 0
    pc = start
    while pc < min(end, len(code) - 8):
        insn = u32(code, pc)
        if bl_tgt(insn, pc) is not None:
            for d in (4, 8):
                if pc + d < end and cbz_tgt(u32(code, pc + d), pc + d) is not None:
                    count += 1
                    break
        pc += 4
    return count

def find_check_calls(code, func_start, scan_len=0x300):
    results = []
    end = min(func_start + scan_len, len(code) - 4)
    for pc in range(func_start, end, 4):
        insn = u32(code, pc)
        tgt = bl_tgt(insn, pc)
        if tgt is None or tgt < 0 or tgt >= len(code):
            continue
        w0_alias = {0}
        for gap in range(1, 20):
            npc = pc + gap * 4
            if npc >= end:
                break
            ni = u32(code, npc)
            mr = is_mov_wx_w0(ni)
            if mr is not None:
                w0_alias.add(mr)
                continue
            ct = cbz_tgt(ni, npc)
            if ct is None:
                continue
            if cbz_is_nz(ni):
                break
            reg = cbz_reg(ni)
            if reg not in w0_alias:
                continue
            skip = ct - npc
            if skip < 0x30:
                continue
            vfy = count_bl_cbz_in_region(code, npc + 4, ct)
            if vfy >= 2 or skip >= 0x100:
                results.append({
                    'bl_pc': pc, 'bl_tgt': tgt,
                    'cbz_pc': npc, 'skip': skip, 'vfy': vfy,
                })
            break
    return results

# ─── Main analysis ───

def analyze(code, minimal=False):
    patches = []
    log = []

    # Find security strings
    all_sec_offsets = []
    for s in SEC_STRINGS:
        for off in find_all_bytes(code, s):
            all_sec_offsets.append(off)
            log.append(f'字符串 "{s.decode()}" @ 0x{off:x}')

    sbc_offsets = []
    for s in SBC_STRINGS:
        for off in find_all_bytes(code, s):
            sbc_offsets.append(off)
            log.append(f'字符串 "{s.decode()}" @ 0x{off:x}')

    if not all_sec_offsets:
        log.append('未找到安全验证字符串，可能不是 bl2_ext')
        return patches, log

    code_end = min(all_sec_offsets)
    log.append(f'代码区域: 0x0 - 0x{code_end:x}')

    check_funcs = {}
    found_via = {}

    # ── Strategy 1: trampoline table ──
    log.append('')
    log.append('── 策略1: 查找跳转表 ──')
    tables = find_trampoline_tables(code, code_end)
    log.append(f'找到 {len(tables)} 个跳转表')

    sec_table = None
    for ttype, entries in tables:
        for _, target in entries:
            actual = follow_trampoline(code, target)
            for soff in all_sec_offsets:
                if abs(actual - soff) < 0x20000:
                    sec_table = (ttype, entries)
                    break
            if sec_table:
                break
        if sec_table:
            break

    if not sec_table:
        for ttype, entries in tables:
            threshold = code_end * 0.55
            if all(follow_trampoline(code, t) > threshold for _, t in entries):
                sec_table = (ttype, entries)
                break

    if sec_table:
        ttype, entries = sec_table
        first_addr, first_tgt = entries[0]
        actual = follow_trampoline(code, first_tgt)
        log.append(f'安全跳转表 ({ttype}): {len(entries)} 个条目, 起始 0x{first_addr:x}')
        log.append(f'  首条目 → 0x{actual:x} (check function)')
        if actual not in check_funcs:
            check_funcs[actual] = first_addr
            found_via[actual] = 'trampoline_table'
    else:
        log.append('未找到安全跳转表')

    # ── Strategy 2: string xref → dispatcher → check call ──
    if not minimal:
        log.append('')
        log.append('── 策略2: 字符串交叉引用 ──')
        for s in SEC_STRINGS:
            for str_off in find_all_bytes(code, s):
                refs = find_xrefs(code, str_off, code_end)
                if not refs:
                    continue
                for ref_pc in refs:
                    fs = find_func_start(code, ref_pc)
                    if fs is None:
                        continue
                    checks = find_check_calls(code, fs)
                    for c in checks:
                        actual = follow_trampoline(code, c['bl_tgt'])
                        if actual not in check_funcs:
                            check_funcs[actual] = c['bl_tgt']
                            found_via[actual] = 'string_xref'
                        log.append(
                            f'  Dispatcher 0x{fs:x}: BL 0x{c["bl_tgt"]:x} → 0x{actual:x}'
                            f' (CBZ skip {c["skip"]}B, {c["vfy"]} verify calls)'
                        )

        # ── Strategy 3: find callers of trampoline entries for deeper dispatchers ──
        if sec_table:
            log.append('')
            log.append('── 策略3: 查找深层调度器 ──')
            _, entries = sec_table
            for entry_off, entry_tgt in entries[1:4]:
                for pc in range(0, min(code_end, len(code) - 4), 4):
                    insn = u32(code, pc)
                    tgt = bl_tgt(insn, pc)
                    if tgt is not None and tgt == entry_off:
                        fs = find_func_start(code, pc)
                        if fs is None:
                            continue
                        checks = find_check_calls(code, fs)
                        for c in checks:
                            actual = follow_trampoline(code, c['bl_tgt'])
                            if actual not in check_funcs:
                                check_funcs[actual] = c['bl_tgt']
                                found_via[actual] = 'caller_trace'
                                log.append(
                                    f'  深层 Dispatcher 0x{fs:x} (调用 0x{entry_off:x}): '
                                    f'check → 0x{actual:x}'
                                )
                break

    # ── SBC efuse reader ──
    if sbc_offsets:
        log.append('')
        log.append('── SBC efuse 检测 ──')
        for str_off in sbc_offsets:
            refs = find_xrefs(code, str_off, code_end)
            for ref_pc in refs:
                fs = find_func_start(code, ref_pc)
                if fs is None:
                    continue
                checks = find_check_calls(code, fs, scan_len=0x120)
                for c in checks:
                    actual = follow_trampoline(code, c['bl_tgt'])
                    if actual in check_funcs:
                        continue
                    has_ret = False
                    for off in range(actual, min(actual + 0x40, len(code) - 4), 4):
                        if u32(code, off) == INSN_RET:
                            has_ret = True
                            break
                    if has_ret:
                        check_funcs[actual] = c['bl_tgt']
                        found_via[actual] = 'sbc_efuse'
                        log.append(f'  SBC efuse reader @ 0x{actual:x}')

    # ── Generate patches ──
    log.append('')
    log.append('── 生成 Patch ──')

    if not check_funcs:
        log.append('未找到可 patch 的验证函数')
        return patches, log

    for actual in sorted(check_funcs):
        via = found_via[actual]
        primary = via in ('trampoline_table', 'sbc_efuse')
        tag = 'PRIMARY' if primary else 'SECONDARY'
        entry = u32(code, actual)
        next_insn = u32(code, actual + 4) if actual + 4 < len(code) else 0

        if via == 'sbc_efuse' and entry == PACIASP:
            patch_sbc_efuse(code, actual, patches, log, tag)
        else:
            patches.append({
                'off': actual,
                'orig': entry,
                'new': MOV_W0_WZR,
                'desc': f'[{tag}] MOV W0, WZR  (was {entry:#010x})',
            })
            patches.append({
                'off': actual + 4,
                'orig': next_insn,
                'new': INSN_RET,
                'desc': f'[{tag}] RET          (was {next_insn:#010x})',
            })
            log.append(f'  [{tag}] 0x{actual:x}: MOV W0, WZR; RET ({via})')

    return patches, log


def patch_sbc_efuse(code, func_addr, patches, log, tag='PRIMARY'):
    for off in range(func_addr, min(func_addr + 0x20, len(code) - 4), 4):
        insn = u32(code, off)
        if insn in (PACIASP, AUTIASP):
            continue
        # STP / SUB SP / ADD X29 — prologue
        if (insn & 0xFFC00000) == 0xA9800000:
            continue
        if (insn & 0xFF8003FF) == 0xD10003FF:
            continue
        if (insn & 0xFF8003FF) == 0x910003FD:
            continue
        # Found first "real" instruction — patch here
        cleanup = None
        for r in range(off + 4, min(func_addr + 0x40, len(code) - 4), 4):
            ri = u32(code, r)
            if (ri & 0xFFC07FFF) == 0xA8C07BFD:
                cleanup = r
                break
            if ri == AUTIASP:
                cleanup = r
                break
        if cleanup is None:
            for r in range(off + 4, min(func_addr + 0x40, len(code) - 4), 4):
                if u32(code, r) == INSN_RET:
                    cleanup = r
                    break
        if cleanup is None:
            log.append(f'  0x{func_addr:x}: SBC efuse — 未找到清理代码，跳过')
            return

        patches.append({
            'off': off,
            'orig': insn,
            'new': MOV_W0_WZR,
            'desc': f'[{tag}] MOV W0, WZR  (was {insn:#010x})',
        })
        if off + 4 < cleanup:
            skip = (cleanup - (off + 4)) // 4
            b_insn = 0x14000000 | (skip & 0x3FFFFFF)
            next_insn = u32(code, off + 4)
            patches.append({
                'off': off + 4,
                'orig': next_insn,
                'new': b_insn,
                'desc': f'[{tag}] B 0x{cleanup:x}     (was {next_insn:#010x})',
            })
        log.append(f'  [{tag}] 0x{off:x}: MOV W0, WZR; B cleanup (sbc_efuse)')
        return

    log.append(f'  0x{func_addr:x}: SBC efuse — 未找到可 patch 点')


def iter_mkimg(data):
    off = 0
    while off + HDR_SZ <= len(data):
        if u32(data, off) != PART_MAGIC:
            break
        vals = struct.unpack_from(PART_HDR_FMT, data, off)
        name = vals[2].split(b'\x00')[0].decode('latin-1', errors='replace')
        dsize = vals[1]
        align = vals[10] if vals[10] > 0 else 1
        padded = (dsize + align - 1) & ~(align - 1)
        img_list_end = vals[9]
        yield name, off, off + HDR_SZ, dsize, padded
        off += HDR_SZ + padded
        if img_list_end:
            break


def find_bl2_ext_in_mkimg(data):
    for name, hdr_off, data_off, dsize, padded in iter_mkimg(data):
        if name == 'bl2_ext':
            return hdr_off, data_off, dsize
    return None


def main():
    ap = argparse.ArgumentParser(
        description='Patch bl2_ext signature verification (自动检测验证函数并 patch)')
    ap.add_argument('input', help='bl2_ext.bin 或 lk.img (MKIMG 复合镜像)')
    ap.add_argument('-o', '--output', help='输出文件路径')
    ap.add_argument('--dry-run', action='store_true', help='仅分析，不写入')
    ap.add_argument('--minimal', action='store_true',
                    help='只 patch 核心 gate 函数 (跳转表首条目 + SBC efuse)')
    args = ap.parse_args()

    data = bytearray(open(args.input, 'rb').read())
    print(f'[*] 输入: {args.input} ({len(data)} bytes)')

    mkimg_base = 0
    hdr_off = 0
    is_mkimg = False

    if len(data) > HDR_SZ and u32(data, 0) == PART_MAGIC:
        first_name = data[8:40].split(b'\x00')[0].decode('latin-1', errors='replace')
        if first_name == 'bl2_ext':
            hdr_off = HDR_SZ
            dsize = u32(data, 4)
            print(f'[*] 单独 bl2_ext: dsize={dsize}')
        else:
            loc = find_bl2_ext_in_mkimg(data)
            if loc is None:
                subs = [n for n, *_ in iter_mkimg(data)]
                print(f'[!] MKIMG 复合镜像未找到 bl2_ext 子镜像')
                print(f'    子镜像: {", ".join(subs)}')
                sys.exit(1)
            mkimg_base, code_start, dsize = loc
            hdr_off = code_start
            is_mkimg = True
            print(f'[*] MKIMG 复合镜像, bl2_ext @ 0x{mkimg_base:x}')
            print(f'[*] bl2_ext: hdr=0x{mkimg_base:x}, code=0x{code_start:x}, dsize={dsize}')

    code = bytes(data[hdr_off:hdr_off + dsize]) if is_mkimg else bytes(data[hdr_off:])
    print(f'[*] 代码大小: {len(code)} bytes (0x{len(code):x})')
    print()

    patches, log = analyze(code, minimal=args.minimal)

    for line in log:
        print(f'  {line}')

    if not patches:
        print('\n[!] 未找到 patch 点')
        sys.exit(1)

    print(f'\n[*] 共 {len(patches)} 处 patch:')
    print()
    for p in patches:
        code_off = p['off']
        file_off = p['off'] + hdr_off
        print(f'  code 0x{code_off:06x}  file 0x{file_off:06x}  {p["desc"]}')

    if args.dry_run:
        print('\n[*] dry-run 模式，未写入文件')
        return

    if not args.output:
        print('\n[!] 未指定输出文件 (-o)')
        sys.exit(1)

    mismatch = False
    for p in patches:
        file_off = p['off'] + hdr_off
        actual = u32(data, file_off)
        if actual != p['orig']:
            print(f'  [!] 0x{file_off:x}: 期望 {p["orig"]:#010x}，实际 {actual:#010x}')
            mismatch = True
        data[file_off:file_off + 4] = p32(p['new'])

    if mismatch:
        print('\n[!] 部分字节不匹配（可能已 patch 或偏移有误），仍然写入')

    open(args.output, 'wb').write(data)
    print(f'\n[*] 已写入: {args.output} ({len(data)} bytes)')


if __name__ == '__main__':
    main()
