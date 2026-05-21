# 文档维护

## 工具链选择

当前项目选择 MkDocs Material，原因是：

- 上手成本低，适合以 Markdown 维护工程文档
- 主题现代，适合项目首页、工程说明和使用指南并存的场景
- 构建速度快，适合在 CI 中做严格校验
- 对 docs-as-code 工作流友好，不需要为当前阶段引入更重的站点框架

## 文档目录约定

- [docs/][docs-dir]：文档源文件
- [mkdocs.yml][mkdocs-yml]：站点配置与导航
- [docs/requirements.txt][docs-requirements]：文档依赖
- [docs/javascripts/][docs-javascripts-dir]：文档站点前端增强脚本
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

代码引用校验：

```powershell
python tools/validate_docs_code_links.py
```

严格构建：

```powershell
.venv\Scripts\python -m mkdocs build --strict
```

## 代码引用链接规则

仓库内源码、头文件、测试、文档源文件和关键配置文件在正文、表格、列表中出现时，必须写成可跳转链接，而不是单独的反引号文本。

- 源 Markdown 中的仓库路径引用统一使用工作区相对路径链接，这样在 VS Code 编辑器里可以直接从文档跳转到本地文件。
- 对 [src/](../../src/)、[include/](../../include/)、[tests/](../../tests/)、[tools/](../../tools/)、[.github/](../../.github/)、[refs/](../../refs/) 这类 [docs/][docs-dir] 目录外目标，站点构建时会通过 [tools/mkdocs_local_repo_links.py][docs-link-hook] 自动转换成站点可工作的只读链接；文档源文件本身仍保持本地相对路径。
- 在 [docs/engineering/api.md][api-doc] 中，公共类型、顶层函数以及关键配置字段至少应链接到对应章节或 [include/secure_wipe.h][secure-wipe-header] 中的定义。
- Mermaid 图中的代码路径节点必须补 `click` 指令，让图中的代码引用也能直接跳转。
- 纯命令示例或代码块中的路径可按命令原样保留，但解释性内容里的仓库引用仍必须链接化。
- 提交前必须运行 [tools/validate_docs_code_links.py][docs-link-validator]；CI 也会执行同一校验。

推荐写法：

- `[src/secure_wipe.cpp](../../src/secure_wipe.cpp)`
- `[include/secure_wipe.h](../../include/secure_wipe.h)`

Mermaid 示例：

```text
click ApiFacade "../../src/secure_wipe.cpp" "src/secure_wipe.cpp"
```

## 同步更新原则

文档必须和代码一起演进，而不是在功能完成后再补写。当前仓库采用以下规则：

1. 修改 CLI、公共 API、架构、平台限制或安全边界时，必须在同一次开发周期内更新对应文档页面。
2. [README.md][readme-file] 只保留仓库入口和快速开始信息，详细内容以 [docs/][docs-dir] 为准。
3. 文档修改完成后，必须通过 `mkdocs build --strict`。
4. 如果是纯文档更新，推荐单独形成一次提交，便于审阅与回溯。
5. 文档中的仓库代码/配置引用必须通过链接校验脚本，不能退回成不可跳转的反引号文本。
6. 当文档中引入新的存储、安全擦除、文件系统或设备能力术语时，必须同步更新 [背景知识与术语](../technical/background-and-terms.md)。

## 图示规范

当前项目同时维护两类图示：

- Mermaid：适合轻量架构图、流程图和背景图示，直接嵌在 Markdown 正文中。
- PlantUML：适合需要明确遵守 UML 视角的用例图、组件图、类图、时序图和活动图。

Mermaid 仍然保留，原因是：

- 它与当前 MkDocs Material 工具链兼容，不需要额外维护二进制图片源文件。
- 图和正文可以在同一 Markdown 页面中演进，便于 code review。
- 对架构重构而言，文本化图示比截图更容易一起变更和审阅。

维护约定：

1. 优先使用 `mermaid` fenced block，而不是截图或导出的流程图图片。
2. 图示只表达当前代码已落地的结构和行为，不把规划内容画成“现状”。
3. 架构或需求变化时，相关图示必须与正文一起更新。
4. 修改图示后仍需通过 `mkdocs build --strict`。
5. UML 图的事实来源是 [docs/uml/diagrams/](../uml/diagrams/) 下的 `.puml` 文件；展示产物是 [docs/uml/rendered/](../uml/rendered/) 下的 `.svg`。
6. 修改 UML 源文件后，必须运行 [tools/render_uml.py](../../tools/render_uml.py)，并同步检查 [UML 视图](uml.md) 与 [系统架构](architecture.md) 是否仍然一致。

## CI 约束

仓库新增了专门的文档工作流：

- 在 `main` 分支 push 时校验文档
- 在 Pull Request 上校验文档
- 使用 `mkdocs build --strict` 防止失效链接或无效导航悄悄进入主干

## 维护者检查清单

- 页面内容是否反映当前代码状态
- 命令是否与当前 CMake / CTest / CLI 一致
- 仓库路径与代码引用是否都已写成可跳转链接
- 架构图和目录说明是否与当前仓库一致
- Mermaid 图是否仍能表达当前边界与主干流程
- PlantUML 源文件、渲染结果和 UML 文档页是否已同步更新
- README 是否仍是“入口页”而不是“第二份完整文档”

[docs-dir]: ../index.md
[mkdocs-yml]: ../../mkdocs.yml
[docs-requirements]: ../requirements.txt
[docs-javascripts-dir]: ../javascripts/
[docs-link-validator]: ../../tools/validate_docs_code_links.py
[docs-link-hook]: ../../tools/mkdocs_local_repo_links.py
[api-doc]: api.md
[readme-file]: ../../README.md
[secure-wipe-header]: ../../include/secure_wipe.h