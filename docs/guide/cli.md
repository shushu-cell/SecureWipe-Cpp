# CLI 使用

## 命令概览

```text
securewipe --help
securewipe inspect <path>
securewipe inspect --detail <path>
securewipe wipe <path> [--passes N] [--pattern zeros|random]
securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]
```

## `inspect`

用于在执行破坏性操作前检查路径和风险提示。

```text
securewipe inspect secret.txt
securewipe inspect --detail secret.txt
```

默认输出字段包括：

- `path`：归一化后的路径
- `target-kind`：目标类型，例如 `regular-file`、`directory`、`symlink`
- `storage-kind`：当前可判断的介质类型，例如 `fixed-disk`、`solid-state`、`unknown`
- `recommendation`：策略建议，例如 `review-before-wipe` 或 `refuse`
- `volume`：可识别时返回文件系统或卷信息
- `dangerous`：是否属于危险目标
- `summary` / `warning`：说明与风险提示

`inspect --detail <path>` 会在保留默认字段的同时，追加非破坏性的设备能力与路径解释字段：

- `device-bus`：总线或设备形态级别的推断，例如 `usb`、`sata`、`nvme`、`virtual`、`network`
- `trim-support`：`unknown`、`unsupported`、`supported`、`restricted`
- `device-sanitize-review`：当前是否值得进入设备级 sanitize review
- `crypto-erase-review`：当前是否值得进入 crypto-erase review
- `removable-media`：当前路径是否位于可移动介质上
- `usb-bridge-suspected`：当前探测是否疑似落在 USB 桥接场景
- `preferred-erase-method`：当前更细粒度的推荐路径，例如 `best-effort-file-overwrite`、`device-sanitize-review`、`manual-review`
- `capability-evidence`：设备能力结论背后的非破坏性证据文本
- `erase-advice`：为什么当前更适合这条路径的解释文本

这组详细字段仍然是**探测与解释**，不是设备级命令执行结果。

## `wipe`

用于对单个普通文件执行覆盖后删除。

```text
securewipe wipe secret.txt --passes 1 --pattern zeros
securewipe wipe secret.txt --passes 1 --pattern random
```

支持参数：

- `--passes N`：覆盖次数，必须是正整数
- `--pattern zeros|random`：覆盖模式

不支持参数：

- `--dry-run`
- `--yes`

这些参数只允许在 `wipe-dir` 中使用，当前实现会直接报错。

## `wipe-dir`

用于递归处理目录中的普通文件。

```text
securewipe wipe-dir ./scratch --dry-run
securewipe wipe-dir ./scratch --passes 1 --pattern random --yes
```

支持参数：

- `--passes N`
- `--pattern zeros|random`
- `--dry-run`：仅列出将被处理的文件
- `--yes`：跳过安全确认并真正执行

当前策略要求：

- `wipe-dir` 必须先使用 `--dry-run` 预览，或显式传入 `--yes` 才会执行
- 符号链接不会被跟随
- 危险目录会被直接拒绝

## 退出码约定

- `0`：成功，或 `--help` 正常输出
- `1`：执行失败，例如目标无法擦除或 inspect 运行失败
- `2`：参数错误，或 `inspect` 给出 `refuse` 建议

## 示例

```text
securewipe inspect ./sample.txt
securewipe inspect --detail ./sample.txt
securewipe wipe ./sample.txt --passes 1 --pattern zeros
securewipe wipe-dir ./tmp --dry-run
securewipe wipe-dir ./tmp --passes 1 --pattern random --yes
```