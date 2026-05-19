# 架构设计

## 设计目标

当前架构的目标不是为了“做出更多文件”，而是为了把公共契约、内部领域逻辑和表现层边界拆清楚，降低未来引入设备级 sanitization、报告系统和更复杂平台探测时的耦合成本。

## 分层概览

| 层次 | 位置 | 职责 |
|---|---|---|
| 公共接口层 | `include/secure_wipe.h` | 提供稳定的对外 API、值类型和顶层函数 |
| 外观层 | `src/secure_wipe.cpp` | 将顶层函数转发到内部对象协作 |
| 内部引擎层 | `src/secure_wipe_engine.cpp` + `src/internal/secure_wipe_engine.h` | 路径检查、文件句柄管理、文件擦除、目录擦除、组合协调 |
| CLI 应用层 | `src/cli_application.cpp` + `src/internal/cli_application.h` | 参数解析、帮助输出、CLI 返回码和表现逻辑 |
| 测试层 | `tests/` | 回归行为与参数校验验证 |
| 文档层 | `docs/`, `mkdocs.yml` | 维护项目知识、使用方式和工程约束 |

## 关键对象职责

### `PathInspector`

- 解析路径
- 判断目标类型
- 检查危险目录
- 估算介质类型和 recommendation

### `NativeFile`

- 封装底层文件句柄
- 用 RAII 方式管理打开/关闭
- 提供 seek、write、flush、close 操作

### `FileWiper`

- 验证文件级参数
- 执行覆盖、刷新、截断、重命名、删除
- 生成 `WipeResult`

### `DirectoryWiper`

- 枚举目录中的普通文件
- 实现 dry-run 与确认执行流程
- 调用 `FileWiper`
- 尝试清理空目录

### `SecureWipeFacade`

- 组合 `PathInspector`、`FileWiper`、`DirectoryWiper`
- 为公共 API 提供稳定入口

### `CommandLineApplication`

- 解析命令行参数
- 校验参数组合是否合法
- 控制输出和退出码
- 作为 CLI 的唯一应用层对象

## 头文件边界

公共头和私有头必须明确分层：

- `include/` 只放会被安装或被外部依赖的头文件
- `src/internal/` 只放实现层私有头文件

这样做的原因是：

- 避免实现细节被误当成稳定接口
- 降低未来重构对外部调用方的影响
- 让目录语义对新维护者一眼可见

## 当前扩展方向

未来如果引入设备级 sanitization，推荐继续沿用当前边界：

- 新增设备能力探测对象，而不是把逻辑重新塞回 `FileWiper`
- 对外 API 保持稳定，优先扩展值类型和 recommendation 语义
- CLI 只负责暴露能力，不直接内联平台分支或设备命令