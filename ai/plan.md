## 2026-05-19 设备感知 CLI 首轮实现

### 目标

- 以现有 C++ 原型为基础，先交付可构建、可测试、可发布的 CLI 工具。
- 明确当前版本只承诺文件/目录擦除与风险提示，不把多次覆盖包装成 SSD 上的强安全保证。
- 为后续设备感知、策略选择、设备级 sanitize 和审计报告保留接口与结构。

### 实施阶段

1. 建立构建基线：补齐 CMake，产出库目标、CLI 目标和测试入口。
2. 硬化擦除引擎：加强参数校验、危险目录拒绝、遍历安全和平台相关 flush/close 行为。
3. 引入检查与策略骨架：增加 inspect 命令，输出目标类型、限制说明和推荐路径。
4. 补齐测试：覆盖文件擦除、目录 dry-run、危险目录拒绝、CLI 参数错误和策略建议。
5. 完成文档与发布：更新 README、检查 GitHub workflow，并在验证通过后执行 git push。

### 首轮范围

- 包含：CLI、文件/目录擦除、设备类型与风险提示、CMake、CTest、文档、发布流程梳理。
- 不包含：真实 ATA Secure Erase、NVMe Sanitize、PSID revert、GUI、证书系统、boot-disk 擦除。

### 验证标准

- `cmake -S . -B build`
- `cmake --build build`
- `ctest --test-dir build --output-on-failure`
- 手工验证 `wipe`、`wipe-dir --dry-run`、危险目录拒绝和 `inspect` 输出
