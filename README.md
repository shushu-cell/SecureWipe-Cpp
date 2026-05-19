# SecureWipe-Cpp

SecureWipe-Cpp 是一个以 C++ 实现的安全擦除 CLI 原型，目标不是简单复刻“多次覆盖”工具，而是逐步演进成一个具备设备感知、风险提示和可验证交付能力的擦除引擎。

当前版本已经提供可构建、可测试的命令行工具与静态库，并把文件级擦除明确定位为 best-effort 行为，而不是对 SSD 或现代文件系统的绝对安全承诺。

## 当前能力

- `inspect <path>`: 检查路径类型、存储类型、风险级别和建议策略。
- `wipe <path>`: 对单个普通文件执行覆盖后删除。
- `wipe-dir <dir>`: 递归处理目录，支持 `--dry-run` 预览和 `--yes` 确认执行。
- 拒绝符号链接与危险目录，避免目录逃逸和明显的误删场景。
- 通过 CMake 和 CTest 提供统一的构建与测试入口。

## 架构设计

当前实现围绕稳定外观层与可替换内部对象协作展开，尽量保持公共 API 简洁，同时把平台分支、擦除策略和 CLI 表现层拆开。

- `include/secure_wipe.h` 保持稳定的公共 API，避免 CLI 与内部实现细节直接耦合。
- `src/secure_wipe.cpp` 只保留外观职责，把调用转发到内部引擎对象。
- `src/secure_wipe_engine.cpp` 与 `src/internal/secure_wipe_engine.h` 承担核心领域逻辑，并把职责拆为 `PathInspector`、`NativeFile`、`FileWiper`、`DirectoryWiper` 与 `SecureWipeFacade`。
- `src/cli_application.cpp` 与 `src/internal/cli_application.h` 负责命令解析、参数校验、帮助输出与结果呈现，使 CLI 不再与底层擦除逻辑混写在 `main` 中。

### 头文件边界

把 `secure_wipe.h` 放在 `include/` 是正确的，因为它属于项目的公共契约。相对地，`secure_wipe_engine.h` 和 `cli_application.h` 这类只服务于实现层的头文件，如果直接平铺在 `src/` 根目录，虽然能工作，但不是最清晰的工程表达：

- 它会让 `src/` 同时承载“可直接编译的翻译单元”和“仅供实现层包含的私有接口”，目录语义不够明确。
- 当项目继续扩展时，开发者更容易误把私有头当成“半公开接口”复用，削弱封装边界。
- README、代码导航和未来的构建脚本都更难一眼分辨哪些头会被安装、哪些头绝不应该被外部依赖。

因此当前仓库采用的修正方案是：

- 公共头继续放在 `include/`。
- 私有头移动到 `src/internal/`，显式表达“只供实现层使用，不属于安装接口”。
- `.cpp` 文件仍保留在 `src/`，通过包含 `internal/...` 头文件完成实现协作。

这个分层遵循的原则是：

- 单一职责：检查、文件擦除、目录遍历、CLI 解析分别由独立对象承担。
- 资源即对象：文件句柄通过 `NativeFile` 以 RAII 方式管理，减少手工 `fclose` 分支。
- 稳定接口、可替换实现：公共 API 不因内部重构而变化，便于后续扩展设备级 sanitize。
- 值类型优先：`InspectionReport`、`WipeResult`、`WipeOptions` 等继续作为清晰的数据边界。

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
src/main.cpp            最小入口，只负责启动 CLI 应用对象
src/cli_application.cpp CLI 应用层实现
src/internal/cli_application.h CLI 应用层私有接口
src/secure_wipe.cpp     公共 API 外观层
src/secure_wipe_engine.cpp 内部检查与擦除引擎实现
src/internal/secure_wipe_engine.h 内部引擎私有接口
tests/                  CTest 测试
refs/                   研究与需求背景
ai/plan.md              实施计划
```

## 下一阶段

- 设备级 sanitize 能力骨架扩展为真实 ATA/NVMe 实现
- 更细粒度的设备识别与策略引擎
- 验证报告与审计日志
- GUI 或更完整的批处理接口
