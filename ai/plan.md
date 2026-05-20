## 2026-05-20 下一步核心功能计划（经三轮审查修订）

### 结论

下一步最值得添加的核心功能，不是立刻执行 ATA Secure Erase / NVMe Sanitize，也不是先做空闲空间覆盖，而是：

**设备能力探测 + 擦除路径解释器（先做非破坏性版本）**。

也就是先把“当前目标位于什么介质、背后是什么总线/设备形态、理论上支持哪些擦除路径、当前为什么推荐某种路径”做成一个正式的、可测试的能力层，并通过现有 `inspect` 入口暴露出来。

### 为什么下一步先做这个

结合 `refs/deep-research-report.md` 与当前 `docs/`，这个选择最符合“谨慎的小步迭代、从易到难”的原则：

1. 当前系统已经有 `inspect`、粗粒度 `StorageKind` 和 `StrategyRecommendation`，但还缺少真正的设备能力层。
2. 研究报告明确指出，项目真正的差异化方向不是继续堆叠文件级覆盖花样，而是把设备感知、正确擦除路径和验证链路做起来。
3. 相比直接上设备级 destructive 命令，这一阶段是**非破坏性**的，风险明显更低，但对后续 ATA/NVMe sanitize、crypto-erase、验证报告都有直接铺垫作用。
4. 当前架构文档已经预留了这个扩展方向：新增独立设备探测对象，而不是把逻辑重新塞回 `FileWiper`。

### 为什么不是别的功能

#### 不是先做空闲空间覆盖

- 研究报告与当前算法文档都指出，空闲空间覆盖风险高、系统扰动大、边界条件复杂。
- 它仍然主要停留在文件系统层，不能解决“正确设备语义”这个更核心的问题。

#### 不是先做真实设备级 sanitize 执行

- 没有设备能力探测层时，系统无法可靠回答“当前设备是否支持、是否被 USB 桥接屏蔽、是否值得执行、是否应该拒绝”。
- 直接做 destructive path 风险过高，不符合当前“小步、可审查”的策略。

#### 不是先做验证/证书系统

- 验证与证书当然重要，但前提是系统先知道自己走的是哪条擦除路径、这条路径有哪些能力与限制。
- 先补“设备能力 + 路径解释”更合理，否则验证对象本身就不清楚。

#### 不是先做 crash consistency / crypto-delete

- 这些方向研究价值很高，但复杂度显著高于当前基线。
- 在尚未建立设备能力模型前，直接进入这类高难度路线，工程收益与风险不平衡。

### 建议批准的下一阶段范围

本次待批准、待后续实现的范围，仅限于：

**阶段 1：增强 `inspect`，使其具备设备能力探测与擦除路径解释能力。**

不包含：

- 真实 ATA Secure Erase / ATA Sanitize 执行
- 真实 NVMe Sanitize / Format 执行
- free-space wipe
- GUI
- 审计证书导出
- 崩溃恢复日志

### 目标效果

在这一阶段完成后，用户执行 `inspect` 时，系统除了现有字段外，还应能回答更具体的问题，例如：

- 当前目标位于本地盘、USB 外接盘、网络盘还是可能的虚拟设备上
- 当前底层设备更像 HDD、SATA SSD、NVMe SSD 还是无法可靠判断
- 当前环境下文件级 overwrite 只是 best-effort，还是更应该改走设备级 sanitize / crypto-erase
- 为什么推荐这条路径，而不是另一条路径
- 当前结论是“已确认支持”“已确认不支持”还是“无法可靠探测”

### 三轮设计审查

#### 第 1 轮：安全语义与公共契约审查

##### 发现的问题

- 原方案把 `AtaSecureErase`、`AtaSanitize`、`NvmeSanitize`、`NvmeFormat` 等具体 destructive 方法过早放进阶段 1 的推荐动作枚举，容易把“总线形态像 NVMe”误写成“已确认支持 NVMe sanitize”。
- 原方案倾向于把大量字段直接平铺到 `InspectionReport` 中，会让公共报告结构快速膨胀，也会让默认 CLI 输出难以控制复杂度。
- 原方案有输出 vendor / model / serial 等设备识别信息的倾向，但在 phase 1 中这类信息的产品价值低于误导和隐私风险。

##### 审查结论

- 阶段 1 的目标不是给出“具体执行命令”，而是给出**更可信的设备级风险判断与路径建议**。
- 公共 API 应优先新增**聚合后的报告子结构**，而不是把细字段分散到顶层。
- 阶段 1 不默认暴露完整敏感设备标识；优先暴露与策略判断直接相关的能力结论与证据说明。

##### 修改后的设计决策

- 保留现有 `StrategyRecommendation`，继续承担“粗粒度安全建议”。
- 新增聚合型结构，建议命名方向为：
  - `DeviceCapabilities`
  - `ErasePathAdvice`
- 阶段 1 的 `EraseMethod` 不再过度细分到真实 destructive 命令级别，而是先收敛为：
  - `Unknown`
  - `Refuse`
  - `BestEffortFileOverwrite`
  - `BestEffortDirectoryWipe`
  - `DeviceSanitizeReview`
  - `CryptoEraseReview`
  - `ManualReview`

这样做的原因是：phase 1 只做探测和解释，不做命令执行；先把“应不应该进入设备级清除路线”说对，比过早枚举具体协议动作更重要。

#### 第 2 轮：职责边界与架构演进审查

##### 发现的问题

- 若继续把新逻辑塞回 `PathInspector`，它会从“路径安全检查 + 粗粒度介质判断”膨胀成一个新的 God object。
- 计划里虽然提到了 `DeviceCapabilityInspector` 和 `StrategyAdvisor`，但没有明确谁负责 orchestrate inspect 主流程。
- 若平台探测细节直接泄漏到 CLI 或 facade 之外，后续设备级执行阶段会更难重构。

##### 审查结论

- `PathInspector` 应保持窄职责：路径解析、目标类型判断、危险目录判断、当前粗粒度 `StorageKind`。
- 新能力应该由**独立对象**承载，且在 inspect 流程中由更高层进行组合。
- 当前最自然的编排点不是 CLI，也不是 `PathInspector`，而是 `SecureWipeFacade::inspect(...)`。

##### 修改后的设计决策

- `SecureWipeFacade` 扩展为 inspect 编排者：
  1. `PathInspector` 生成基础 `InspectionReport`
  2. `DeviceCapabilityInspector` 读取非破坏性设备能力快照
  3. `ErasePathAdvisor` 基于基础报告 + 设备能力生成更细粒度路径建议与解释
- 新增内部对象建议：
  - `DeviceCapabilityInspector`
  - `ErasePathAdvisor`
- 不新增新的对外 inspect API，而是让现有 `inspect_target(...)` 返回增强后的 `InspectionReport`。

##### 同步缩减实现风险

- phase 1 不引入新的大而全“inspection service”层，先由 `SecureWipeFacade` 直接组合三个对象即可。
- phase 1 不要求平台探测模块输出原始厂商协议细节，只输出内部消化后的能力结论与证据文本。

#### 第 3 轮：测试策略、CLI 变更与交付风险审查

##### 发现的问题

- 如果能力探测依赖当前机器真实硬件，测试会高度脆弱、难以复现。
- 如果默认 `inspect` 输出一次性扩展太多字段，现有 CLI 行为和文档会发生大范围漂移。
- 如果把“推断”“确认”“无法探测”混在一起，用户会误解输出可信度。

##### 审查结论

- phase 1 必须从设计上保证可 fake、可 stub、可做稳定断言。
- CLI 默认输出应尽量稳定，把新字段集中到详细模式中暴露。
- 能力结论必须显式区分 `Unknown / Unsupported / Supported / Restricted` 这一类状态，不能退化成布尔值。

##### 修改后的设计决策

- 新增 `CapabilityState`，用于表达：
  - `Unknown`
  - `Unsupported`
  - `Supported`
  - `Restricted`
- 新增 `DeviceBusKind`，但只用于**总线/设备形态级别**判断，不把它直接等价为 sanitize 支持。
- CLI 变更收敛为：
  - 默认 `inspect <path>` 保持当前简洁输出为主
  - 新增 `inspect --detail <path>` 输出 `device-capabilities` 与 `erase-path-advice` 相关字段
- 测试设计必须允许注入 fake probe / fake capability snapshot，单元测试重点断言“给定能力快照时，advisor 是否给出正确路径建议”。

### 审查后的最终实施方案

#### 1. 领域模型扩展

保持现有 `StrategyRecommendation` 不变，继续让它承担“粗粒度安全建议”职责；在此基础上，**新增聚合型设备能力与路径建议结构**，避免把已有语义硬改得过重。

建议新增的值类型方向：

- `DeviceBusKind`：描述 `Unknown / Usb / Ata / Sata / Nvme / Scsi / Virtual / Network` 等设备连接形态
- `CapabilityState`：明确用 `Unknown / Unsupported / Supported / Restricted` 表达能力结论，避免把“探测不到”误写成“不支持”
- `EraseMethod`：阶段 1 先收敛为 `Unknown / Refuse / BestEffortFileOverwrite / BestEffortDirectoryWipe / DeviceSanitizeReview / CryptoEraseReview / ManualReview`
- `DeviceCapabilities`：封装设备总线、是否可移动、是否疑似 USB 桥接、trim/discard 能力、设备级擦除路径是否值得进入 review、证据文本等
- `ErasePathAdvice`：封装当前首选路径建议与理由列表

建议将 `DeviceCapabilities` 与 `ErasePathAdvice` **以子结构形式附加到 `InspectionReport`**，而不是创建一个完全平行的新 inspect API。原因是当前系统已经把 `inspect` 作为安全模型入口，继续沿用这一入口更自然。

#### 2. 内部分层方案

建议新增两个内部对象，而不是继续膨胀 `PathInspector`：

- `DeviceCapabilityInspector`
  - 输入：解析后的 `fs::path`、已有 `StorageKind`、平台上下文
  - 输出：`DeviceCapabilities`
  - 职责：只做非破坏性的设备能力探测与证据收集

- `ErasePathAdvisor`
  - 输入：`InspectionReport` 的现有结论 + `DeviceCapabilities`
  - 输出：`ErasePathAdvice`
  - 职责：只负责“基于能力与风险做推荐”，不直接执行擦除命令

这样可以保持职责清晰：

- `PathInspector` 继续做路径安全与粗粒度介质判断
- `DeviceCapabilityInspector` 负责更细的设备能力探测
- `ErasePathAdvisor` 负责解释“为什么推荐这条路径”
- `SecureWipeFacade::inspect(...)` 负责编排三者，而不是让 `PathInspector` 自己扩张

#### 3. 平台实现策略

建议按“先读信息、后做决定”的方式实现，只做只读探测，不发 destructive 命令。

##### Windows

优先考虑只读查询路径：

- `IOCTL_STORAGE_QUERY_PROPERTY`
- `STORAGE_DEVICE_DESCRIPTOR`
- `DEVICE_TRIM_DESCRIPTOR`
- 必要时再评估 `STORAGE_PROTOCOL_*` 相关识别查询

目标是先拿到：

- bus type
- trim/discard 类能力线索
- 是否疑似可移动设备或 USB 桥接

阶段 1 不要求默认输出 vendor / model / serial；如内部读取到，也先只用于推断，不作为默认外部字段暴露。

##### Linux

优先考虑：

- `/sys/class/block`
- `/sys/block/.../queue/*`
- `/sys/class/nvme`
- 现有 `/proc/self/mounts` / `rotational` 信息链路的扩展

目标是先拿到：

- 块设备名称与传输线索
- 是否 rotational
- discard / trim 线索
- 是否为 NVMe 命名空间、SATA 盘、USB 外接或无法确认

##### macOS

本阶段不追求完整实现。

建议策略：

- 先保留 `Unknown` / `Restricted` 回退路径
- 明确在文档和输出中说明“当前平台尚未实现细粒度能力探测”

#### 4. CLI 暴露方案

建议继续复用现有 `inspect` 子命令，而不是立刻再造新命令。

更稳妥的暴露方式：

- 默认 `inspect <path>` 保持当前简洁输出和现有字段顺序尽量稳定
- 新增 `inspect --detail <path>`，输出新增的设备能力字段、路径建议和理由列表

这样做的好处：

- 避免当前 CLI 文本回归大范围波动
- 允许逐步增加新信息，而不是一次性把默认输出变得过于嘈杂
- 后续若要支持 JSON 或报告导出，也有自然扩展点

#### 5. 测试方案

这一步若想可维护，必须避免把硬件真实状态写死在测试里。

建议：

- 抽象平台探测快照或平台 probe seam，让 `DeviceCapabilityInspector` 可以注入 fake probe / stub
- 单元测试重点覆盖“给定设备能力快照时 advisor 的映射结果”，而不是依赖本机真实硬件
- CLI 测试重点验证：
  - `inspect --detail` 新字段是否出现
  - `EraseMethod` / 理由文案是否稳定
  - 无法探测时是否输出 `unknown` / `restricted`，而不是误报支持

#### 6. 文档同步方案

一旦批准并实现，至少需要同步更新：

- `docs/engineering/requirements.md`
- `docs/engineering/architecture.md`
- `docs/guide/cli.md`
- `docs/guide/safety.md`
- `docs/technical/secure-erasure-algorithms.md`

重点不是宣传“更强了”，而是准确说明：

- 这一步仍然是**非破坏性能力探测与解释**
- 它改进的是“决策质量”和“用户理解”，不是已经交付了设备级 sanitize

### 需要特别注意的问题

#### 1. 不要把启发式判断写成确定事实

很多平台信息只能说明“像 NVMe”“疑似 USB bridge”“可能支持 discard”，不能直接等价为“支持 sanitize”。

因此：

- 能力状态必须至少是三态或四态，不能是二元布尔值
- 输出文案必须区分“confirmed”与“inferred”

#### 2. 不要把文件级与设备级路径混在一起

研究报告已经明确指出，文件级 overwrite 和设备级 sanitize 不是一回事。

因此：

- `FileWiper` 继续只负责文件级 best-effort
- 新增设备能力与路径推荐层，但暂不进入 destructive device command 执行

#### 3. USB 桥接、RAID、虚拟磁盘会让探测结果失真

这类场景很容易导致：

- 看不到真实设备能力
- 只看到桥接层能力
- 明明是 SSD，却只能获得模糊块设备信息

计划里必须把这些场景默认视为“需要保守处理”，而不是乐观假设。

#### 4. 不要默认把 system disk / boot disk 纳入可执行范围

这一阶段虽然不执行设备级擦除，但一旦开始输出更具体的设备推荐，用户会自然期待“那能不能现在就执行”。

因此需要在文档和输出里提前把范围讲清楚：

- 当前只是探测与解释
- 并不表示当前版本可以安全执行该设备级操作

#### 5. 注意敏感信息暴露

若后续输出 model / serial / device path 等信息：

- 默认不应过度打印完整敏感标识
- 文档要说明哪些字段主要用于诊断，不应被包装成审计证书

### 阶段 1 的最小实现边界

为了确保这一步真正“小步且可交付”，阶段 1 的实现边界进一步收敛为：

- 必做：
  - 扩展 `InspectionReport` 的公共结构
  - 新增 `DeviceCapabilityInspector` 与 `ErasePathAdvisor`
  - `SecureWipeFacade::inspect(...)` 组合基础检查、能力探测和路径建议
  - CLI 新增 `inspect --detail`
  - 测试新增 fake probe 场景和详细输出断言
  - docs 同步更新

- 不做：
  - 真实 destructive 设备命令
  - 结构化 JSON 输出
  - 完整设备品牌识别展示
  - 审计证书或验证日志

### 小步迭代顺序（从易到难）

建议按下面顺序推进，而不是一步冲到设备级执行：

1. **阶段 1：设备能力探测与擦除路径解释器**
	- 非破坏性
	- 复用现有 `inspect`
	- 本计划建议优先批准这一阶段

2. **阶段 2：结构化证据输出**
	- 为 inspect / recommendation 增加更结构化的证据表示
	- 可以考虑 JSON，但仍然不执行 destructive device command

3. **阶段 3：Linux / Windows 单平台先行的设备级执行路径**
	- 先选一条最可控路径，例如 Linux-first NVMe sanitize 或 Windows-first 只读识别 + 受限执行
	- 必须以阶段 1 的能力探测结论为前提

4. **阶段 4：验证与报告**
	- 在真正有设备级执行路径后，再做状态验证与更像样的报告

### 本阶段验收口径（待批准后实现时使用）

- `inspect` 仍可稳定工作，现有行为不倒退
- `inspect --detail` 或等价详细模式能够输出新增设备能力与推荐路径解释
- 无法确认能力时，系统输出保守结论，不夸大支持范围
- 新增测试不依赖开发机真实磁盘型号
- 现有默认 `inspect` CLI 输出核心字段不回归
- `cmake --build build` 通过
- `ctest --test-dir build -C Debug --output-on-failure` 通过
- 相关文档同步更新并保持 `mkdocs build --strict` 通过

### 审查后批准的实现版本

以下方向作为进入实现阶段前的最终版本：

1. 先做“设备能力探测 + 擦除路径解释器”的非破坏性增强，而不是直接做设备级执行。
2. 继续复用 `inspect`，新增 `--detail` 模式承载新增输出。
3. phase 1 对 macOS 保守回退为 `Unknown / Restricted`，优先把 Windows / Linux 做扎实。
4. 保留现有 `StrategyRecommendation`，增量添加 `DeviceCapabilities` 与 `ErasePathAdvice`，不重写现有 recommendation 体系。
