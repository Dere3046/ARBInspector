# arb_inspector

[English Version](README.md)

检测和生成高通安全镜像的工具

## 功能

- 解析 32/64 位 ELF 带高通 HASH 段
- 解析 MBN v3/v5/v6/v7/v8
- 从 OEM metadata 提取 ARB 版本
- 检测 QTI/OEM 签名和加密参数
- 生成哈希段 签名 (ECDSA/RSA) 加密参数
- LZMA/XZ 压缩和 PIL split
- 所有功能可在编译时裁剪

## 用法

```
arb_inspector [--fast] [--debug] [--verify] <镜像>
arb_inspector secure-image [选项]
```

无参数 = 完整显示
`--fast` = 只输出 ARB
`--debug` = 逐步追踪

### secure-image

```
--infile <路径>  --outfile <路径>
--hash           生成哈希表段
--sign           签名 (local|test|plugin)
--encrypt        添加加密参数 (qbec|uie)
--inspect        打印镜像信息
--validate       校验
--compress       LZMA 压缩输出
--pil-split      分割为 .mdt + .bXX
```

### 编译

```
cargo build --release                     # 全功能
cargo build --no-default-features         # 仅检测
cargo build --features sign               # +签名
cargo build --features "sign encrypt"     # +加密
```

## 示例

```bash
# 快速查看 ARB
arb_inspector --fast xbl_a

# 完整查看
arb_inspector abl_a

# 生成哈希段 更新 ARB
arb_inspector secure-image --infile abl_a --outfile abl_new.elf --hash --anti-rollback-version 5

# 哈希 + 签名 使用内建 ECDSA 测试证书
arb_inspector secure-image --infile abl_a --outfile abl_signed.elf --hash --sign --signing-mode test
```

### 输出示例

```
File: xbl_a
Format: ELF (64-bit)
Program headers: 9

Hash Table Segment Header:
  Version: 7
  Common Metadata Size: 24 (bytes)
  OEM Metadata Size: 224 (bytes)
  Hash Table Size: 432 (bytes)

Signed: Yes (QTI + OEM)

Common Metadata:
  Version: 0.0
  Software ID: 0x36
  Hash Table Algorithm: SHA384 (3)

OEM Metadata:
  Version: 3.0
  Anti-Rollback Version: 0

Anti-Rollback Version: 0
```

## Metadata 格式

Common Metadata V0.0 24 字节
  major minor software_id secondary_sw_id hash_table_algo mrc_target

OEM Metadata V2.0/V3.0 224 字节
  12 个 soc_hw_vers product_segment_id jtag_id 8 个 serial u64
  oem_id oem_product_id lifecycle states oem_rch_hash flags

OEM Metadata V0.0/V1.0 120 字节 (v6 旧格式)

## 许可证

MIT
