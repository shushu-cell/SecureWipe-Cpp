# 开发指南

## 环境要求

- CMake 3.21+
- C++20 编译器
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
python tools/validate_docs_code_links.py
.venv\Scripts\python -m mkdocs build --strict
```

## 目录结构

| 路径 | 说明 |
|---|---|
| [include/][include-dir] | 公共头文件 |
| [src/][src-dir] | 源文件 |
| [src/internal/][src-internal-dir] | 实现层私有头文件 |
| [tests/][tests-dir] | CTest 测试 |
| [docs/][docs-dir] | MkDocs 文档源文件 |
| [mkdocs.yml][mkdocs-yml] | MkDocs 站点配置 |
| [.github/workflows/][github-workflows-dir] | CI / 发布流程 |
| [tools/][tools-dir] | 仓库辅助校验脚本 |

当前 [src/][src-dir] 已按职责拆分为多个翻译单元，重点包括：

- [src/path_inspector.cpp][path-inspector-src]
- [src/native_file.cpp][native-file-src]
- [src/file_wiper.cpp][file-wiper-src]
- [src/directory_wiper.cpp][directory-wiper-src]
- [src/secure_wipe_engine.cpp][secure-wipe-engine-src]
- [src/cli_application.cpp][cli-application-src]
- [src/secure_wipe.cpp][secure-wipe-src]

## 变更流程建议

当你修改代码时，至少同步检查以下几件事：

| 变更类型 | 需要同步更新 |
|---|---|
| CLI 参数或输出变化 | [docs/guide/cli.md][guide-cli-doc]、[README.md][readme-file] |
| 安全边界变化 | [docs/guide/safety.md][guide-safety-doc] |
| 架构或目录结构变化 | [docs/engineering/architecture.md][architecture-doc]、[README.md][readme-file] |
| 公共 API 变化 | [docs/engineering/api.md][api-doc] |
| 构建/测试命令变化 | [docs/engineering/development.md][development-doc]、[README.md][readme-file] |

## 提交前建议检查

- 代码变更已通过对应构建或测试
- 文档变更已通过 `mkdocs build --strict`
- [README.md][readme-file] 只保留仓库入口性质的信息，避免和 [docs/][docs-dir] 大量重复

[include-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/include
[src-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/src
[src-internal-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/src/internal
[tests-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/tests
[docs-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/docs
[mkdocs-yml]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/mkdocs.yml
[github-workflows-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/.github/workflows
[tools-dir]: https://github.com/shushu-cell/SecureWipe-Cpp/tree/main/tools
[path-inspector-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/path_inspector.cpp
[native-file-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/native_file.cpp
[file-wiper-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/file_wiper.cpp
[directory-wiper-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/directory_wiper.cpp
[secure-wipe-engine-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/secure_wipe_engine.cpp
[cli-application-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/cli_application.cpp
[secure-wipe-src]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/src/secure_wipe.cpp
[guide-cli-doc]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/docs/guide/cli.md
[guide-safety-doc]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/docs/guide/safety.md
[architecture-doc]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/docs/engineering/architecture.md
[api-doc]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/docs/engineering/api.md
[development-doc]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/docs/engineering/development.md
[readme-file]: https://github.com/shushu-cell/SecureWipe-Cpp/blob/main/README.md