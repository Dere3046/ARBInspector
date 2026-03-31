# arb_inspector_next

[English Version](README.md)

用于解析高通固件镜像（ELF/MBN 格式）中 Anti-Rollback (ARB) 版本的轻量级工具。

## 功能特性

- 解析 32/64 位 ELF 文件（带 Qualcomm HASH 段）
- 解析 MBN 文件（v3/v5/v6/v7/v8）
- 从 OEM metadata 提取 ARB 版本
- 支持 Hash Table Segment Header v3/v5/v6/v7/v8
- 支持 Metadata v0.0/v1.0/v2.0/v3.0/v3.1
- 支持 Common Metadata v0.0/v0.1
- 快速模式：仅输出 ARB 值
- 完整模式：显示详细的镜像信息，包括：
  - ELF/MBN 头部信息
  - 程序头及其 Qualcomm OS 段类型
  - Hash Table Segment Header
  - Common Metadata
  - OEM Metadata（含 ARB 版本）
  - Hash Table 内容
- 计算和验证段哈希

## 使用方法

```
arb_inspector_next [--debug] [--quick|--full] [-v] <镜像文件>
```

### 选项

- `--debug` / `-d`: 启用详细调试输出
- `--quick` / `-q`: 仅输出 ARB 版本号（默认模式）
- `--full` / `-f`: 输出完整的镜像信息
- `--version` / `-v`: 显示版本并退出

### 示例

```bash
# 快速模式 - 仅输出 ARB 版本
arb_inspector_next xbl_config.img

# 完整模式 - 详细分析
arb_inspector_next --full xbl_config.img

# 调试模式 - 详细输出
arb_inspector_next --debug --full xbl_config.img
```

## 编译

```bash
cargo build --release
```

编译后的二进制文件位于 `target/release/arb_inspector`（Windows 上为 `arb_inspector.exe`）。

## 输出格式

### 快速模式
仅输出 ARB 版本号：
```
0
```

### 完整模式
输出详细信息：
```
File: xbl_config.img
Format: ELF (64-bit)
Entry point: 0x1494e000
Machine: 0x1
Type: 0x2
Flags: 0x5
Program headers: 8

Program Headers:
  [0] Type: NULL Offset: 0x0 VAddr: 0x0 FileSize: 0x200 MemSize: 0x0
      Flags: 0x7000000 Perm: None OS_Type: PHDR OS_Access: RW Page_Mode: NON_PAGED
  ...

Hash Table Segment Header:
  Version: 7
  Common Metadata Size: 24 (bytes)
  QTI Metadata Size: 0 (bytes)
  OEM Metadata Size: 224 (bytes)
  Hash Table Size: 384 (bytes)
  ...

Common Metadata:
  Version: 0.0
  One-shot Hash Algorithm: 37
  Segment Hash Algorithm: 0

OEM Metadata:
  Version: 3.0
  Anti-Rollback Version: 0
  ...

Anti-Rollback Version: 0
```

## 支持的格式

### ELF 文件
- 32 位和 64 位 ELF
- Qualcomm OS 段类型（AMSS、HASH、PHDR 等）
- 带 metadata 的 Hash Table Segment

### MBN 文件
- MBN v3、v5、v6、v7、v8
- 镜像头部解析

## Metadata 版本

### Common Metadata
- v0.0: 基础哈希算法配置
- v0.1: 添加 ZI 段哈希算法支持

### OEM Metadata
- v0.0: 基础 ARB 和平台绑定
- v1.0: 添加 JTAG ID 和 OEM Product ID 绑定
- v2.0: 添加生命周期状态和 OEM 根证书哈希
- v3.0: 添加 QTI 生命周期状态
- v3.1: 添加测量寄存器目标

## 许可证

MIT - 详见 [LICENSE](LICENSE)
