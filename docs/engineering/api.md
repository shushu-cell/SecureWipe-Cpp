# 公共 API

## 头文件

对外公共接口定义在：

```cpp
#include "secure_wipe.h"
```

## 顶层函数

```cpp
InspectionReport inspect_target(std::string_view path);
WipeResult wipe_file(std::string_view path, const WipeOptions& opt);
WipeResult wipe_directory(std::string_view dir, const WipeOptions& opt, bool dry_run, bool yes);
```

当前公共 API 将路径参数声明为 `std::string_view`。这表示调用方可以传入 `std::string`、字符串字面量或其他只读字符串视图，而领域层在真正进入文件系统操作前再把它转换为 `std::filesystem::path`。

## 值类型

### `Pattern`

用于指定覆盖模式：

- `Pattern::Zeros`
- `Pattern::Random`

### `WipeOptions`

| 字段 | 含义 |
|---|---|
| `passes` | 覆盖次数，必须大于等于 1 |
| `pattern` | 覆盖模式 |
| `block_size` | 块大小，必须大于等于 1 |

### `TargetKind`

描述目标路径的类型：

- `Missing`
- `RegularFile`
- `Directory`
- `Symlink`
- `Other`

### `StorageKind`

描述当前可识别的介质类型：

- `Unknown`
- `FixedDisk`
- `RotationalDisk`
- `SolidState`
- `RemovableDisk`
- `NetworkShare`

### `StrategyRecommendation`

描述策略建议：

- `None`
- `Refuse`
- `BestEffortFileOverwrite`
- `BestEffortDirectoryWipe`
- `ReviewBeforeWipe`

### `InspectionReport`

路径检查返回值，核心字段包括：

- `ok`
- `dangerous`
- `target_kind`
- `storage_kind`
- `recommendation`
- `canonical_path`
- `volume_name`
- `message`
- `warnings`

### `WipeResult`

擦除结果值对象，核心字段包括：

- `ok`
- `dry_run`
- `files_total`
- `files_wiped`
- `files_failed`
- `message`

## 兼容性约定

当前项目约定是：

- `include/secure_wipe.h` 是稳定公共边界
- 内部引擎头文件不属于对外 API，不保证兼容性
- 当顶层行为变化时，应同步更新本页和 CLI 文档