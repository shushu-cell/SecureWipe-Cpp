## 2026-05-20 14:24 Modern C++ 全局职责解耦

- 识别到的主要坏味道：`secure_wipe_engine.cpp` 过大且多职责；库层与 `std::cout/std::cerr` 耦合；CLI 解析与错误构造重复；顶层调用缺少清晰的执行上下文抽象。
- 本轮重构目标：按职责拆分引擎实现文件，引入内部报告抽象以隔离库层输出，收敛 CLI 解析与展示逻辑，保持公共 API 与现有行为稳定。
- 实施结果：引擎拆分为 `path_inspector.cpp`、`native_file.cpp`、`file_wiper.cpp`、`directory_wiper.cpp` 与轻量 `secure_wipe_engine.cpp`；新增 `OperationReporter` 抽象；CLI 解析改为更强类型的退出码与统一错误构造；`secure_wipe.cpp` 收敛默认 facade 接线。
- 验证标准：`cmake --build build`、`ctest --test-dir build -C Debug --output-on-failure` 通过，并保留 `inspect`、`wipe`、`wipe-dir --dry-run` 的当前行为。
