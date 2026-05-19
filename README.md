# SecureWipe-Cpp

SecureWipe-Cpp 是一个以 C++ 实现的安全擦除 CLI 原型，目标不是简单复刻“多次覆盖”工具，而是逐步演进成一个具备设备感知、风险提示和可验证交付能力的擦除引擎。

当前版本已经提供可构建、可测试的命令行工具与静态库，并把文件级擦除明确定位为 best-effort 行为，而不是对 SSD 或现代文件系统的绝对安全承诺。

## 当前能力

- `inspect <path>`: 检查路径类型、存储类型、风险级别和建议策略。
- `wipe <path>`: 对单个普通文件执行覆盖后删除。
- `wipe-dir <dir>`: 递归处理目录，支持 `--dry-run` 预览和 `--yes` 确认执行。
- 拒绝符号链接与危险目录，避免目录逃逸和明显的误删场景。
- 通过 CMake 和 CTest 提供统一的构建与测试入口。

## 安全边界

- 当前实现只覆盖文件和目录路径，不直接执行 ATA Secure Erase、NVMe Sanitize、PSID revert 等设备级 destructive 操作。
- 在 SSD、快照、日志型或 CoW 文件系统上，文件级覆盖只能视为 best-effort；底层控制器、重映射块和文件系统元数据可能保留历史数据。
- `inspect` 会尽量判断目标所在介质，并在介质未知、固定盘或可移动盘场景下提高告警等级。
- 对根目录、用户主目录根、系统目录等危险目标会直接拒绝递归擦除。

研究背景与后续路线见 [refs/deep-research-report.md](refs/deep-research-report.md)。

## 构建

### Windows

```powershell
cmake -S . -B build
cmake --build build --config Debug
```

可执行文件通常位于 `build/Debug/securewipe.exe`。

### Linux / macOS

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

可执行文件通常位于 `build/securewipe`。

## 测试

### Windows

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

### Linux / macOS

```bash
ctest --test-dir build --output-on-failure
```

## 用法

```text
securewipe --help
securewipe inspect <path>
securewipe wipe <path> [--passes N] [--pattern zeros|random]
securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]
```

示例：

```text
securewipe inspect secret.txt
securewipe wipe secret.txt --passes 1 --pattern zeros
securewipe wipe-dir ./scratch --dry-run
securewipe wipe-dir ./scratch --passes 1 --pattern random --yes
```

## 项目结构

```text
include/secure_wipe.h   公共 API
src/main.cpp            CLI 入口
src/secure_wipe.cpp     检查与擦除核心实现
tests/                  CTest 测试
refs/                   研究与需求背景
ai/plan.md              实施计划
```

## 下一阶段

- 设备级 sanitize 能力骨架扩展为真实 ATA/NVMe 实现
- 更细粒度的设备识别与策略引擎
- 验证报告与审计日志
- GUI 或更完整的批处理接口
