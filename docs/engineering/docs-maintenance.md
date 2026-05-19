# 文档维护

## 工具链选择

当前项目选择 MkDocs Material，原因是：

- 上手成本低，适合以 Markdown 维护工程文档
- 主题现代，适合项目首页、工程说明和使用指南并存的场景
- 构建速度快，适合在 CI 中做严格校验
- 对 docs-as-code 工作流友好，不需要为当前阶段引入更重的站点框架

## 文档目录约定

- `docs/`：文档源文件
- `mkdocs.yml`：站点配置与导航
- `docs/requirements.txt`：文档依赖
- `site/`：生成产物，已被 `.gitignore` 忽略

## 本地工作流

安装依赖：

```powershell
.venv\Scripts\python -m pip install -r docs\requirements.txt
```

本地预览：

```powershell
.venv\Scripts\python -m mkdocs serve
```

严格构建：

```powershell
.venv\Scripts\python -m mkdocs build --strict
```

## 同步更新原则

文档必须和代码一起演进，而不是在功能完成后再补写。当前仓库采用以下规则：

1. 修改 CLI、公共 API、架构、平台限制或安全边界时，必须在同一次开发周期内更新对应文档页面。
2. `README.md` 只保留仓库入口和快速开始信息，详细内容以 `docs/` 为准。
3. 文档修改完成后，必须通过 `mkdocs build --strict`。
4. 如果是纯文档更新，推荐单独形成一次提交，便于审阅与回溯。

## CI 约束

仓库新增了专门的文档工作流：

- 在 `main` 分支 push 时校验文档
- 在 Pull Request 上校验文档
- 使用 `mkdocs build --strict` 防止失效链接或无效导航悄悄进入主干

## 维护者检查清单

- 页面内容是否反映当前代码状态
- 命令是否与当前 CMake / CTest / CLI 一致
- 架构图和目录说明是否与当前仓库一致
- README 是否仍是“入口页”而不是“第二份完整文档”