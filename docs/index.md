# SecureWipe-Cpp

SecureWipe-Cpp 是一个以 C++ 实现的安全擦除 CLI 原型，当前重点是把“文件/目录擦除 + 风险提示 + 可验证交付”做成可维护的工程基线，而不是过早宣称自己已经覆盖所有设备级 sanitization 场景。

## 当前状态

- 交付形态：命令行工具 + 静态库
- 已实现能力：路径检查、单文件擦除、目录 dry-run、目录确认执行、基础媒体/风险提示
- 当前策略：文件级覆盖是 best-effort，不把它包装成 SSD 上的绝对安全保证
- 当前工程实践：CMake 构建、CTest 测试、MkDocs Material 文档、GitHub Actions 文档构建校验

## 当前能力

- `inspect <path>`：检查目标类型、危险标记、推荐策略和介质提示
- `wipe <path>`：对单个普通文件执行覆盖、截断、重命名与删除
- `wipe-dir <dir>`：递归擦除目录中的普通文件，支持 `--dry-run` 与 `--yes`
- 拒绝危险目录和符号链接，避免明显的误删或目录逃逸

## 当前非目标

以下能力仍处于规划或未来阶段，不属于当前版本交付：

- ATA Secure Erase / NVMe Sanitize / PSID revert 等真实设备级 destructive 操作
- 审计证书、取证级验证和完整报告系统
- GUI 与 boot-disk 擦除场景

## 快速开始

### 构建

Windows:

```powershell
cmake -S . -B build
cmake --build build --config Debug
```

Linux / macOS:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### 测试

Windows:

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

Linux / macOS:

```bash
ctest --test-dir build --output-on-failure
```

### 文档预览

```powershell
.venv\Scripts\python -m pip install -r docs\requirements.txt
.venv\Scripts\python -m mkdocs serve
```

## 文档地图

- [需求分析](engineering/requirements.md)：问题定义、范围边界、功能/非功能需求与验收口径
- [CLI 使用](guide/cli.md)：命令、参数、输出字段和退出码
- [安全边界](guide/safety.md)：当前实现的真实承诺与风险范围
- [安全擦除算法](technical/secure-erasure-algorithms.md)：预备知识、算法选型、源码关联、参考文献与评估结论
- [系统架构](engineering/architecture.md)：系统上下文、组件关系、运行时主干流程和关键设计决策
- [公共 API](engineering/api.md)：头文件、数据结构和顶层接口
- [开发指南](engineering/development.md)：构建、测试、目录结构和变更流程
- [文档维护](engineering/docs-maintenance.md)：如何让文档持续跟随代码变化