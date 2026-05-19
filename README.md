# SecureWipe-Cpp

SecureWipe-Cpp 是一个以 C++ 实现的安全擦除 CLI 原型，目标不是简单复刻“多次覆盖”工具，而是逐步演进成一个具备设备感知、风险提示和可验证交付能力的擦除引擎。

当前版本已经提供可构建、可测试的命令行工具与静态库，并把文件级擦除明确定位为 best-effort 行为，而不是对 SSD 或现代文件系统的绝对安全承诺。

## 文档

项目当前采用 MkDocs Material 作为 docs-as-code 工具链，规范文档统一维护在 `docs/` 目录下，根配置位于 `mkdocs.yml`。

- 入口页：`docs/index.md`
- CLI 使用：`docs/guide/cli.md`
- 安全边界：`docs/guide/safety.md`
- 架构说明：`docs/engineering/architecture.md`
- 公共 API：`docs/engineering/api.md`
- 开发与文档维护：`docs/engineering/development.md`、`docs/engineering/docs-maintenance.md`

本地预览：

```powershell
.venv\Scripts\python -m pip install -r docs\requirements.txt
.venv\Scripts\python -m mkdocs serve
```

严格构建校验：

```powershell
.venv\Scripts\python -m mkdocs build --strict
```

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

### CLI 概览

```text
securewipe --help
securewipe inspect <path>
securewipe wipe <path> [--passes N] [--pattern zeros|random]
securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]
```

## 文档同步要求

文档现在被视为和代码同等重要的交付物。任何涉及以下内容的代码变更，都应同步更新 `docs/` 内对应页面并通过 `mkdocs build --strict`：

- CLI 命令、参数、输出格式或错误语义
- 公共 API、目录结构或架构边界
- 安全边界、平台限制、构建与测试命令

仓库中已增加专门的文档 CI，用于在 `main` 和 Pull Request 上验证文档站点可构建。

详细说明见 `docs/engineering/docs-maintenance.md`。
