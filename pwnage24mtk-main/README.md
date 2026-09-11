# pwnage24mtk

MediaTek 安全启动 CERT2 哈希覆盖工具集。利用 preloader 中 ASN.1 解析逻辑缺陷，在不破坏 CERT2 签名的前提下替换镜像哈希，使修改过的 LK/ATF/TEE/GZ 通过签名验证。

> **仅用于安全研究。使用前确保已获授权。**

---

## 漏洞原理

Preloader 用 CERT1 + CERT2 两级证书验证启动镜像。CERT2 内含两个 OID 哈希：

| OID | 用途 |
|-----|------|
| `2.16.886.2454.2.4` | 镜像头（part_hdr_t 512字节）的 SHA-256/384 |
| `2.16.886.2454.2.1` | 镜像数据（padding 后）的 SHA-256/384 |

工具在 CERT2 DER 前插入一个 `0xA0`（context-specific）包装块，内含新的 OID + BitString。Preloader 的哈希比对逻辑优先命中插入的值，而原始 CERT2 结构和签名不变。

### bypass_mode

| 模式 | 适用设备 | 做法 |
|------|---------|------|
| `bypass_mode=0`（默认） | 新 V6 | 只插 `0xA0` 块。解析器跳过非 `0x30` 对象 |
| `bypass_mode=1`（`--legacy`） | V5 / 旧 V6 | 额外插一个 BitString 包装原始 CERT2 DER，让旧解析器能步入找到原始 SEQUENCE |

**不确定用哪个？** 先不加 `--legacy` 试。刷入后如果签名验证失败，改用 `--legacy`。

---

## 启动链与 Patch 策略

### V5（无 bl2_ext）

```
BootROM → Preloader → LK (cert bypass) → Kernel
                    → ATF/TEE (cert bypass)
```

Preloader 直接用 CERT1/CERT2 验证 LK 和 ATF。cert bypass 直接绕过，不需要额外 patch。

### V6（有 bl2_ext）

```
BootROM → Preloader (CERT2验证) → bl2_ext → LK (bl2_ext 二次验证)
                                           → ATF/TEE (bl2_ext 二次验证)
```

bl2_ext 本身由 preloader 通过 CERT2 验证。bl2_ext 内部**可能**有独立的签名验证逻辑（RSA+SHA，不走 CERT2），会二次验证 LK/ATF。

**是否需要 patch bl2_ext？**

- **不一定。** 部分 V6 设备的 bl2_ext 验证在 SBC（Secure Boot Control）efuse 未烧写时是关闭的，或者验证策略允许跳过。这种情况下 bl2_ext 不会阻止修改过的 LK/ATF 加载，只需 cert bypass 签名 LK/ATF 即可。
- **需要 patch 的情况：** bl2_ext 内部强制验证 LK/ATF 且 cert bypass 无法绕过时（bl2_ext 自身的验证不使用 CERT2 的 ASN.1 解析），才需要 patch bl2_ext 的验证函数。patch 之后 bl2_ext 的哈希变了，才需要对 bl2_ext 做 cert bypass 重签。
- **判断方法：** 先只做 cert bypass 签名 LK/ATF，不动 bl2_ext，刷入测试。如果 LK/ATF 加载失败（bl2_ext 报签名错误），再用 `patch_bl2_ext.py` patch。

需要 patch 时的流程：
1. Patch bl2_ext 去掉它对 LK/ATF 的验证调用
2. cert bypass 签名 bl2_ext（bl2_ext 代码改了哈希变了，需要重签让 preloader 接受）
3. cert bypass 签名修改后的 LK/ATF

**不需要 patch 时：** bl2_ext 完全不用动，也不用签——它没改过，preloader 的原始 CERT2 验证本来就能通过。

**判断是否有 bl2_ext：** 用 `parse_preloader.py` 查看分区策略表，有 `bl2_ext` 条目就是 V6，没有就是 V5。

---

## 工具一览

| 脚本 | 做什么 | 关键参数 |
|------|--------|---------|
| `parse-part-img.py` | 解析/拆分 MKIMG 复合镜像 | `--dump` 看结构, `--split -o dir/` 拆分（生成 manifest.json） |
| `build-part-img.py` | 重组复合镜像 | `rebuild dir/` 一键重签打包, `concat`, `replace` |
| `sign_mtk_cert.py` | **核心：CERT2 哈希覆盖** | `-w` 写入, `-o` 输出, `--all` 签全部子镜像, `--legacy` 旧设备 |
| `verify_mtk_image.py` | 验证 CERT1/CERT2 签名和哈希 | 直接跟文件名 |
| `parse_mtk_certs.py` | 打印 CERT1/CERT2 的 ASN.1 结构 | 调试用 |
| `parse_preloader.py` | 解析 preloader 头、加载地址、分区策略表 | 直接跟文件名 |
| `parse_da.py` | 解析 Download Agent 二进制 | 直接跟文件名 |
| `patch_bl2_ext.py` | 自动 patch bl2_ext 签名验证 (**实验性**) | `-o` 输出, `--minimal` 最小 patch, `--dry-run` 仅分析 |

---

## 操作流程：修改 LK 并刷入

以下假设你的 `lk.img` 是 MKIMG 复合镜像（包含 lk + cert 等子镜像）。

### 1. 查看复合镜像结构

```bash
python3 parse-part-img.py lk.img --dump
```

输出示例：
```
[0] name=lk         type=0x00000000  dsize=360448  ...
[1] name=lk_cert1   type=0x02000000  dsize=1420    ...
[2] name=lk_cert2   type=0x02000002  dsize=1836    ...  img_list_end=1
```

### 2. 拆分子镜像

```bash
python3 parse-part-img.py lk.img --split -o lk_parts/
```

每个逻辑镜像（含它的 CERT1 + CERT2）打包成一个文件：
```
lk_parts/
├── lk.bin              # part_hdr + LK 数据 + CERT1 + CERT2 (一体)
├── lk_main_dtb.bin     # 如果有多个子镜像，每个各一个文件
└── lk_second_dtb.bin   # 部分 V6 设备特有：无 part_hdr_t 的第二设备树 + CERT
```

> **注意：** 部分 V6 设备的 lk.img 中第二设备树（lk_second_dtb）存储在主镜像列表之后，
> 没有标准的 part_hdr_t 头部。split 会自动检测并提取为 `lk_second_dtb.bin`，
> concat 时也会自动附加回去。

### 3. 修改 LK 数据

用 IDA/Ghidra 或十六进制编辑器修改 `lk_parts/lk.bin`。注意：

- 前 512 字节是 part_hdr_t 头，**不要动**
- 偏移 512 开始才是 LK 代码
- 典型修改：NOP 签名验证调用、跳过 bootloader 锁检查等

### 4. cert bypass 签名

```bash
# 方式一：直接对完整 lk.img 签名所有子镜像（最简单）
python3 sign_mtk_cert.py -w --all lk.img -o lk_signed.img

# 方式二：对单个拆分文件签名
python3 sign_mtk_cert.py -w lk_parts/lk.bin -o lk_parts/lk_signed.bin

# 如果失败，用 legacy 模式（加 --legacy）
python3 sign_mtk_cert.py -w --all --legacy lk.img -o lk_signed.img
```

这一步做了什么：
1. 找到文件中的 CERT2 分区
2. 计算修改后 LK 的 part_hdr 哈希和数据哈希
3. 构建 `0xA0` 覆盖块（含新哈希的 OID + BitString）
4. 插入 CERT2 DER 前面
5. 更新 CERT2 的 dsize 字段

### 5. 重建复合镜像

如果原始 `lk.img` 只有一个子镜像，签名后的 `lk_signed.bin` 就能直接刷。

如果有多个子镜像（如 lk + lk_main_dtb），用 `concat` 把它们拼回去：

```bash
# V5（无 bl2_ext）
python3 build-part-img.py concat lk_parts/ --order lk,lk_main_dtb -o lk_final.img

# V6 — lk_second_dtb.bin 会自动附加（如有）
python3 build-part-img.py concat lk_parts/ --order lk,bl2_ext,aee,lk_main_dtb -o lk_final.img

# V6+AVF — lk_dtbo 是标准子镜像，直接在 order 中列出
python3 build-part-img.py concat lk_parts/ --order lk,bl2_ext,aee,lk_main_dtb,lk_dtbo -o lk_final.img
```

或者用 `replace` 替换原始镜像中的指定子镜像（会自动处理 cert 区域对齐）：

```bash
python3 build-part-img.py replace lk.img \
    --name lk \
    --file lk_parts/lk_signed.bin \
    -o lk_final.img
```

### 6. 验证

```bash
python3 verify_mtk_image.py lk_final.img
```

输出中关注：
- `Image header hash`: 显示 OK（override 哈希与当前数据匹配）
- `Image data hash`: 显示 OK
- `CERT2 signature`: 显示 OK（原始签名未变，覆盖块不影响签名验证）

### 7. 刷入

```bash
# SP Flash Tool: 选择对应分区，加载 lk_final.img 刷入
# 或 fastboot:
fastboot flash lk lk_final.img
```

---

## 操作流程：修改 ATF/TEE（V5/V6 设备）

ATF 通常打包在 `tee1.img` 内，也是 MKIMG 复合镜像。

### 快速方式（直接对完整镜像操作）

```bash
# 1. 修改（用十六进制编辑器或 patch 工具直接改 tee1.img 中的 ATF 代码）

# 2. 一次性重签所有子镜像
python3 sign_mtk_cert.py -w --all tee1.img -o tee1_signed.img

# 3. 验证 + 刷入
python3 verify_mtk_image.py tee1_signed.img
fastboot flash tee1 tee1_signed.img
```

### 拆分方式（需要精确修改某个子镜像时）

```bash
# 1. 查看结构
python3 parse-part-img.py tee1.img --dump

# 2. 拆分
python3 parse-part-img.py tee1.img --split -o tee_parts/

# 3. 修改 tee_parts/atf.bin 或 tee_parts/tee.bin（偏移 512 之后是代码）

# 4. 一键重签 + 打包
python3 build-part-img.py rebuild tee_parts/ -o tee1_final.img

# 5. 验证 + 刷入
python3 verify_mtk_image.py tee1_final.img
fastboot flash tee1 tee1_final.img
```

---

## 操作流程：V6 设备 bypass（有 bl2_ext）

> **不是所有 V6 设备都需要 patch bl2_ext。** 先只做 cert bypass 签名 LK/ATF（不动 bl2_ext），刷入测试。只有 bl2_ext 验证确实阻止了加载时才需要 patch。

### 不需要 patch bl2_ext 的情况（优先试这个）

bl2_ext 没改过，哈希没变，preloader 原始 CERT2 验证能直接通过，不需要任何操作。只需 cert bypass 签名你修改过的 LK/ATF 即可。

### 需要 patch bl2_ext 的情况

**方法 A：直接操作复合镜像（简单场景）**

```bash
# 1. 先 --dry-run 查看 patch 点
python3 patch_bl2_ext.py lk.img --minimal --dry-run

# 2. patch（直接对 lk.img，自动定位 bl2_ext 子镜像）
python3 patch_bl2_ext.py lk.img --minimal -o lk_patched.img

# 3. bl2_ext 代码改了 → 哈希变了 → 需要 cert bypass 重签
python3 sign_mtk_cert.py -w lk_patched.img -o lk_final.img

# 4. 验证 + 刷入
python3 verify_mtk_image.py lk_final.img
fastboot flash lk lk_final.img
```

**方法 B：拆分 → patch → 一键重签打包（推荐，需要同时改多个子镜像时）**

```bash
# 1. 拆分（自动生成 manifest.json）
python3 parse-part-img.py lk.img --split -o lk_parts/

# 2. patch bl2_ext（或其他修改）
python3 patch_bl2_ext.py lk_parts/bl2_ext.bin --minimal -o lk_parts/bl2_ext.bin

# 3. 一键重签所有子镜像 + 打包（自动处理 headerless 格式、填充到原始大小）
python3 build-part-img.py rebuild lk_parts/ -o lk_final.img
```

> 如果需要手动控制签名过程，也可以逐个签名后用 `concat` 拼接（见下方手动流程）。

<details>
<summary>手动签名 + concat（高级用法）</summary>

```bash
# 逐个签名
python3 sign_mtk_cert.py -w lk_parts/bl2_ext.bin -o lk_parts/bl2_ext.bin
python3 sign_mtk_cert.py -w lk_parts/lk_second_dtb.bin -o lk_parts/lk_second_dtb.bin

# 手动 concat（需要指定顺序，lk_second_dtb.bin 会自动附加）
python3 build-part-img.py concat lk_parts/ --order lk,bl2_ext,aee,lk_main_dtb -o lk_final.img
```

</details>

### patch_bl2_ext.py（实验性）

> **实验性工具。** 基于 V6 和 V6+AVF 两个样本的逆向分析开发，通过启发式方法定位验证函数。不保证适用于所有 MTK SoC 的 bl2_ext。使用前务必 `--dry-run` 检查 patch 点是否合理。

脚本自动检测两种已知的验证架构：

| 架构 | 特征 | 代表 SoC | patch 方式 |
|------|------|---------|-----------|
| `sec_get_vfy_policy` | simple 跳转表 (连续 B) | V6 | 首条目 → MOV W0,WZR; RET |
| `get_sbc_en` + efuse | PAC 跳转表 (PACIASP+AUTIASP+B) | V6+AVF | 首条目 + efuse reader → return 0 |

检测流程：找安全字符串 → 定位跳转表 → 确认首条目是验证 gate → patch 为 return 0。

支持输入格式：单独 `bl2_ext.bin`、带 part_hdr 的 `bl2_ext.bin`、MKIMG 复合镜像 (`lk.img`)。

---

## 分区策略分析

```bash
# 查看 preloader 加载地址和分区策略表
python3 parse_preloader.py preloader.bin
```

输出的 `policy_part_map` 表显示每个分区的验证策略（签名类型、CERT 格式等），用于确定哪些分区需要签名、用什么算法。

---

## 各平台 lk.img 结构差异

| 类型 | 子镜像 | lk_second_dtb |
|------|--------|--------------|
| V5 | lk, lk_main_dtb | 无 |
| V6 | lk, bl2_ext, aee, lk_main_dtb, lk_second_dtb | headerless（无 part_hdr_t，带 cert1+cert2） |
| V6+AVF | lk, bl2_ext, aee, lk_main_dtb, lk_dtbo | 无（lk_dtbo 是标准子镜像，有 part_hdr_t） |

### Headerless 第二设备树（部分 V6 设备）

部分 V6 设备的 lk.img 中，`lk_main_dtb` 的 cert2 设置了 `img_list_end=1` 终止镜像列表。但在列表结束后还存储了第二设备树（带独立的 cert1 + cert2）：

```
[主镜像列表: lk + bl2_ext + aee + lk_main_dtb（各带 cert1/cert2）]
[零填充至页对齐]
[第二设备树原始数据（无 part_hdr_t，直接是 DTB）]
[cert1 (有 part_hdr_t)]
[cert2 (有 part_hdr_t, img_list_end=1)]
[零填充至分区结尾]
```

工具自动处理：
- `parse-part-img.py --split` 自动检测并提取为 `lk_second_dtb.bin`
- `build-part-img.py concat` 自动检测目录中的 `lk_second_dtb.bin` 并附加
- `sign_mtk_cert.py` 自动识别 headerless 格式并支持重签

---

## 一键重签打包（rebuild）

`rebuild` 是最简化的工作流：解包后修改，一条命令完成所有重签和打包。

### 工作原理

1. `parse-part-img.py --split` 解包时自动生成 `manifest.json`，记录子镜像顺序、文件名、是否带证书、尾部特殊数据等
2. `build-part-img.py rebuild` 读取 manifest，对所有 `has_cert: true` 的文件自动执行 cert bypass 签名，然后按顺序拼接并 pad 到原始大小

### manifest.json 格式

```json
{
  "source": "lk.img",
  "source_size": 8388608,
  "images": [
    {"name": "lk", "file": "lk.bin", "has_cert": true},
    {"name": "bl2_ext", "file": "bl2_ext.bin", "has_cert": true},
    {"name": "aee", "file": "aee.bin", "has_cert": true},
    {"name": "lk_main_dtb", "file": "lk_main_dtb.bin", "has_cert": true}
  ],
  "tail": {
    "file": "lk_second_dtb.bin",
    "has_cert": true,
    "headerless": true
  }
}
```

### 使用方法

```bash
# 1. 解包（自动生成 manifest.json）
python3 parse-part-img.py lk.img --split -o lk_parts/

# 2. 修改（改 LK 代码 / patch bl2_ext / 编辑设备树等）
python3 patch_bl2_ext.py lk_parts/bl2_ext.bin --minimal -o lk_parts/bl2_ext.bin

# 3. 一键重签 + 打包
python3 build-part-img.py rebuild lk_parts/ -o lk_final.img
```

### rebuild 命令参数

```
build-part-img.py rebuild <dir> [-o output.img] [--legacy] [-v]
```

| 参数 | 说明 |
|------|------|
| `<dir>` | 包含 manifest.json 和子镜像文件的目录 |
| `-o` | 输出文件路径（默认：`<dir>_rebuild.img`） |
| `--legacy` | 对所有子镜像使用 legacy bypass 模式（V5 旧设备） |
| `-v` | 详细输出（显示每个文件的签名过程） |

### 各平台完整示例

**V5（无 bl2_ext）：**
```bash
python3 parse-part-img.py lk.img --split -o lk_parts/
# 修改 lk_parts/lk.bin ...
python3 build-part-img.py rebuild lk_parts/ -o lk_final.img --legacy
```

**V6（含 headerless 第二设备树）：**
```bash
python3 parse-part-img.py lk.img --split -o lk_parts/
# 修改 lk_parts/bl2_ext.bin / lk.bin / lk_second_dtb.bin ...
python3 build-part-img.py rebuild lk_parts/ -o lk_final.img
```

**V6+AVF（含 lk_dtbo）：**
```bash
python3 parse-part-img.py lk.img --split -o lk_parts/
# 修改 lk_parts/bl2_ext.bin / lk.bin ...
python3 build-part-img.py rebuild lk_parts/ -o lk_final.img
```

### 验证

```bash
python3 verify_mtk_image.py lk_final.img
```

所有带证书的子镜像应显示 override hash 匹配。

---

## 注意事项

1. **备份原始镜像**。错误的 patch 可能导致硬砖（需 BROM 模式救砖）
2. **镜像大小**。cert bypass 会增大 CERT2 的 dsize，脚本会自动截断尾部零填充保持原始大小。如果尾部无零填充会发出警告。重建后需要 pad 到原始分区大小
3. **漏洞时效性**。此漏洞可能在新版 preloader 中已修复。如果 CERT2 bypass 失败，可能说明设备已更新
4. **V6 设备**。有 bl2_ext 的设备**可能**需要 patch bl2_ext 去除二次验证。先只做 cert bypass 测试，失败再 patch。用 `parse_preloader.py` 确认是否有 bl2_ext
5. **Bootloader 已解锁的设备**。部分设备解锁 bootloader 后 bl2_ext 不再验证子镜像，此时只需 cert bypass 签名修改过的子镜像即可，无需 patch bl2_ext
6. **Preloader 本身**。修改 preloader 需要 Image Key 私钥做 PSS 重签名。cert bypass 只适用于 preloader 验证的下游镜像（LK/ATF/TEE/GZ）
