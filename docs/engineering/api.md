# 公共 API

## 头文件

对外公共接口定义在：

```cpp
#include "secure_wipe.h"
```

源码定义见 [include/secure_wipe.h][secure-wipe-header]。

## 顶层函数

```cpp
InspectionReport inspect_target(std::string_view path);
WipeResult wipe_file(std::string_view path, const WipeOptions& opt);
WipeResult wipe_directory(std::string_view dir, const WipeOptions& opt, bool dry_run, bool yes);
```

- [`inspect_target(...)`][inspect-target-def] 返回 [`InspectionReport`][inspection-report-def]。
- [`wipe_file(...)`][wipe-file-def] 与 [`wipe_directory(...)`][wipe-directory-def] 接收 [`WipeOptions`][wipe-options-def] 并返回 [`WipeResult`][wipe-result-def]。

当前公共 API 将路径参数声明为 `std::string_view`。这表示调用方可以传入 `std::string`、字符串字面量或其他只读字符串视图，而领域层在真正进入文件系统操作前再把它转换为 `std::filesystem::path`。

其中 [`inspect_target(...)`][inspect-target-def] 现在会返回两层结果：

- 原有的粗粒度安全结论：`target_kind`、`storage_kind`、`recommendation`
- 新增的非破坏性能力与路径解释：`device_capabilities`、`erase_path_advice`

## 值类型

### [`Pattern`][pattern-def]

用于指定覆盖模式：

- [`Pattern::Zeros`][pattern-def]
- [`Pattern::Random`][pattern-def]

### [`WipeOptions`][wipe-options-def]

| 字段 | 含义 |
|---|---|
| [`passes`][wipe-options-passes-field] | 覆盖次数，必须大于等于 1 |
| [`pattern`][wipe-options-pattern-field] | 覆盖模式，类型为 [`Pattern`][pattern-def] |
| [`block_size`][wipe-options-block-size-field] | 块大小，必须大于等于 1 |

### [`TargetKind`][target-kind-def]

描述目标路径的类型：

- `Missing`
- `RegularFile`
- `Directory`
- `Symlink`
- `Other`

### [`StorageKind`][storage-kind-def]

描述当前可识别的介质类型：

- `Unknown`
- `FixedDisk`
- `RotationalDisk`
- `SolidState`
- `RemovableDisk`
- `NetworkShare`

### [`StrategyRecommendation`][strategy-recommendation-def]

描述策略建议：

- `None`
- `Refuse`
- `BestEffortFileOverwrite`
- `BestEffortDirectoryWipe`
- `ReviewBeforeWipe`

### [`DeviceBusKind`][device-bus-kind-def]

描述当前路径背后的总线或设备形态级别线索：

- `Unknown`
- `Usb`
- `Ata`
- `Sata`
- `Nvme`
- `Scsi`
- `Virtual`
- `Network`

### [`CapabilityState`][capability-state-def]

显式区分能力结论的可信度与约束：

- `Unknown`
- `Unsupported`
- `Supported`
- `Restricted`

### [`EraseMethod`][erase-method-def]

描述 `inspect` 在当前阶段给出的更细粒度路径建议：

- `Unknown`
- `Refuse`
- `BestEffortFileOverwrite`
- `BestEffortDirectoryWipe`
- `DeviceSanitizeReview`
- `CryptoEraseReview`
- `ManualReview`

### [`DeviceCapabilities`][device-capabilities-def]

非破坏性的设备能力视图，核心字段包括：

- `bus_kind`
- `trim_support`
- `device_sanitize_review`
- `crypto_erase_review`
- `is_removable_media`
- `usb_bridge_suspected`
- `evidence`

### [`ErasePathAdvice`][erase-path-advice-def]

更细粒度的推荐结果，核心字段包括：

- `preferred_method`
- `reasons`

### [`InspectionReport`][inspection-report-def]

路径检查返回值，核心字段包括：

- `ok`
- `dangerous`
- `target_kind`
- `storage_kind`
- `recommendation`
- `device_capabilities`
- `erase_path_advice`
- `canonical_path`
- `volume_name`
- `message`
- `warnings`

[`InspectionReport`][inspection-report-def] 的新增能力字段仍然属于“探测与解释”，不是“设备级 destructive command 已确认可执行”的承诺。

### [`WipeResult`][wipe-result-def]

擦除结果值对象，核心字段包括：

- `ok`
- `dry_run`
- `files_total`
- `files_wiped`
- `files_failed`
- `message`

## 兼容性约定

当前项目约定是：

- [include/secure_wipe.h][secure-wipe-header] 是稳定公共边界
- 内部引擎头文件不属于对外 API，不保证兼容性
- 当顶层行为变化时，应同步更新本页和 CLI 文档

[secure-wipe-header]: ../../include/secure_wipe.h
[pattern-def]: ../../include/secure_wipe.h#L10
[wipe-options-def]: ../../include/secure_wipe.h#L15
[wipe-options-passes-field]: ../../include/secure_wipe.h#L16
[wipe-options-pattern-field]: ../../include/secure_wipe.h#L17
[wipe-options-block-size-field]: ../../include/secure_wipe.h#L18
[target-kind-def]: ../../include/secure_wipe.h#L21
[storage-kind-def]: ../../include/secure_wipe.h#L29
[strategy-recommendation-def]: ../../include/secure_wipe.h#L38
[device-bus-kind-def]: ../../include/secure_wipe.h#L46
[capability-state-def]: ../../include/secure_wipe.h#L57
[erase-method-def]: ../../include/secure_wipe.h#L64
[device-capabilities-def]: ../../include/secure_wipe.h#L74
[erase-path-advice-def]: ../../include/secure_wipe.h#L84
[wipe-result-def]: ../../include/secure_wipe.h#L89
[inspection-report-def]: ../../include/secure_wipe.h#L98
[inspect-target-def]: ../../include/secure_wipe.h#L112
[wipe-file-def]: ../../include/secure_wipe.h#L113
[wipe-directory-def]: ../../include/secure_wipe.h#L114