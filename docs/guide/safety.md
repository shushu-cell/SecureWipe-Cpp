# 安全边界

## 当前版本真正承诺什么

当前版本承诺的是“本地文件和目录的 best-effort 擦除工作流”，不是“对所有介质、文件系统和控制器都能提供绝对不可恢复”的通用答案。

这意味着：

- 项目会尝试覆盖文件内容、刷新数据、截断文件并删除它
- 项目会在执行前提供危险路径检查、介质提示以及可选的详细能力解释
- 项目不会把多次覆盖包装成对 SSD 的强安全保证

## SSD 与现代文件系统限制

在以下场景中，文件级覆盖只能视为 best-effort：

- SSD、eMMC、U 盘等存在重映射或磨损均衡的介质
- 支持快照、CoW 或复杂元数据日志的文件系统
- 控制器、缓存层或底层块重映射无法由应用层直接控制的环境

因此当前实现会在 `inspect` 输出中附带风险提示，并在介质未知、固定盘或可移动盘场景下提高告警等级。若使用 `inspect --detail`，系统还会输出总线、trim/discard 线索、USB 桥接嫌疑、更细粒度的路径建议，以及结构化证据/风险/候选动作字段；若使用 `inspect --json`，同一份只读结论会以机器可读 JSON 对象导出。但这些字段仍然都是非破坏性的推断结果。

## 当前拒绝或限制的目标

当前实现至少会对以下对象给出明确拒绝或高风险提示：

- 符号链接
- 文件系统根目录
- 用户主目录根
- 系统目录
- network share 场景下的 `refuse` recommendation

对于 network share，当前建议是：先执行 `inspect`，并遵从 `recommendation` 结果；这类目标不应被视为本项目当前版本的可靠擦除范围。

## 为什么需要先 `inspect`

`inspect` 不是附属功能，而是当前安全模型的一部分。它会在真正执行破坏性命令前暴露出：

- 目标类型是否受支持
- 目标是否属于危险路径
- 当前介质判断和推荐策略
- 为什么当前操作只能是 best-effort，或者为什么更适合先进入设备级 review
- 哪些候选动作面向 `current-path`，哪些只应理解为 `underlying-device` 级别的人工复核入口

如果需要把这些结论接入自动化流程，`inspect --json` 只是把同一份 inspection result 序列化出来，并不会改变任何安全边界或自动触发下一步 destructive 动作。

需要特别强调的是：

- `device-sanitize-review` 和 `crypto-erase-review` 代表“值得进一步审查的路径”，不是“当前版本已经能执行该命令”
- `preflight-action` 里的 `preferred` / `available` / `blocked` 代表解释性的决策状态，不代表程序已经进入或验证了对应设备命令
- `Unknown`、`Unsupported`、`Supported`、`Restricted` 是显式建模的一部分，目的是避免把推断写成确认事实
- USB 桥接、虚拟盘、RAID 或平台探测缺口都应优先落入保守结论，而不是乐观放行

## 当前未实现的安全能力

以下能力仍不在当前版本内：

- ATA Secure Erase
- NVMe Sanitize / Format
- PSID revert
- 取证级验证报告
- 对 boot disk 的专用擦除流程

如果未来引入这些能力，文档页和 CLI 帮助都必须同步更新。

关于当前版本已经采用的路径检查、文件覆盖、目录递归与 recommendation 推导算法，请继续参见[安全擦除算法技术文档](../technical/secure-erasure-algorithms.md)。