# 开发指南

## 环境要求

- CMake 3.21+
- C++17 编译器
- Windows、Linux 或 macOS 开发环境
- Python 3，用于文档构建

## 常用命令

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

### 文档

```powershell
.venv\Scripts\python -m pip install -r docs\requirements.txt
.venv\Scripts\python -m mkdocs build --strict
```

## 目录结构

```text
include/                 公共头文件
src/                     源文件
src/internal/            实现层私有头文件
tests/                   CTest 测试
docs/                    MkDocs 文档源文件
mkdocs.yml               MkDocs 站点配置
.github/workflows/       CI / 发布流程
```

当前 `src/` 已按职责拆分为多个翻译单元，重点包括：

- `path_inspector.cpp`
- `native_file.cpp`
- `file_wiper.cpp`
- `directory_wiper.cpp`
- `secure_wipe_engine.cpp`
- `cli_application.cpp`
- `secure_wipe.cpp`

## 变更流程建议

当你修改代码时，至少同步检查以下几件事：

| 变更类型 | 需要同步更新 |
|---|---|
| CLI 参数或输出变化 | `docs/guide/cli.md`、`README.md` |
| 安全边界变化 | `docs/guide/safety.md` |
| 架构或目录结构变化 | `docs/engineering/architecture.md`、`README.md` |
| 公共 API 变化 | `docs/engineering/api.md` |
| 构建/测试命令变化 | `docs/engineering/development.md`、`README.md` |

## 提交前建议检查

- 代码变更已通过对应构建或测试
- 文档变更已通过 `mkdocs build --strict`
- README 只保留仓库入口性质的信息，避免和 `docs/` 大量重复