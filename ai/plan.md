## 2026-05-20 下一步核心功能计划（经三轮审查修订）

### 结论

下一步最值得添加的核心功能，不是立刻执行 ATA Secure Erase / NVMe Sanitize，也不是先做空闲空间覆盖，而是：

**设备能力探测 + 擦除路径解释器（先做非破坏性版本）**。

也就是先把“当前目标位于什么介质、背后是什么总线/设备形态、理论上支持哪些擦除路径、当前为什么推荐某种路径”做成一个正式的、可测试的能力层，并通过现有 `inspect` 入口暴露出来。

### 实施状态更新

阶段 1 的核心实现已经落地，当前代码状态为：

- `InspectionReport` 已增量携带 `DeviceCapabilities` 与 `ErasePathAdvice`
- `SecureWipeFacade::inspect(...)` 已按审查后的职责边界编排：基础路径检查、能力探测、路径建议
- CLI 已新增 `inspect --detail <path>`，默认 `inspect <path>` 的简洁输出保持稳定
- Windows / Linux 已接入只读能力探测；macOS 与其他平台仍保守回退到 `Unknown` / `Restricted` 风格的结果
- 测试已覆盖 fake probe 场景、advisor 映射与详细输出字段

当前仍未进入的范围保持不变：

- 不执行 ATA / NVMe destructive device command
- 不输出审计证书
- 不把“总线推断”包装成“已确认支持 sanitize”

后续工作转入实现后的三轮审查 / 重构阶段，而不是继续扩大阶段 1 范围。

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

## 2026-05-21 下一步核心功能计划（结构化证据与预执行计划）

### 结论

结合 `refs/deep-research-report.md` 与当前 `docs/`，下一步最值得添加的核心功能，不是立刻执行 ATA Secure Erase / NVMe Sanitize，也不是先补 free-space wipe，而是：

**把当前 `inspect` 升级为“结构化设备证据 + 预执行擦除计划（read-only preflight）”能力。**

换句话说，系统下一步应先学会：

- 用结构化字段而不只是自由文本，说明当前 recommendation 背后的证据来源与可信度
- 把“当前路径可做什么”和“底层整设备值得 review 什么”明确区分开
- 输出一个可复核、可测试、可导出的 preflight 结果，为后续真实设备级执行与验证报告打基础

这一阶段仍然是**非破坏性**的，不执行任何设备级 destructive command。

### 为什么是这一步

当前代码和文档状态已经说明了一件事：项目已经完成了“路径检查 + 文件/目录 best-effort 擦除 + 非破坏性设备能力解释”这三件事，但还没进入“可验证的 sanitization orchestration”。

研究报告和当前 docs 对下一步方向其实是一致的：

1. `refs/deep-research-report.md` 反复强调，项目的真正价值不在于继续堆文件级覆盖花样，而在于把**设备语义、验证与审计链路**做起来。
2. `docs/technical/secure-erasure-algorithms.md` 已经明确给出未来演进顺序：
  - 先细化**结构化证据输出**
  - 再建立 **ATA / NVMe 设备级执行与状态验证路径**
  - 最后把**验证与报告**做成一等能力
3. 当前 `inspect --detail` 虽然已经能输出 `device-bus`、`trim-support`、`device-sanitize-review` 等字段，但证据仍然主要停留在 `std::vector<std::string>` 风格的自由文本里，这不足以支撑下一阶段的设备级执行前置检查，更不足以支撑后续验证与报告。

因此，最稳妥的小步迭代，不是直接跨进高风险 destructive path，而是先把“为什么得出这个建议”做成正式的、结构化的、可机读的工程资产。

### 为什么不是别的功能

#### 不是先做 ATA / NVMe 设备级执行

- 当前 docs 仍把真实设备级 destructive 操作列为**当前非目标**。
- 在没有结构化证据、target scope 建模、安全闸门和状态验证基线之前，直接做执行路径，风险过高。
- 现在的 `EraseMethod::DeviceSanitizeReview` / `CryptoEraseReview` 语义仍然是“值得 review”，不是“已确认可执行”；跳过中间层会迫使代码和文档一起冒进。

#### 不是先做 free-space wipe

- 研究报告明确指出 free-space wipe 在 FAT32、系统盘、低剩余空间和现代文件系统场景下风险高、扰动大、边界复杂。
- 它也不能解决当前项目最关键的差距：**设备级语义和验证链路仍不完整**。

#### 不是先做取证级报告 / 审计证书

- 当前系统还没有设备级执行状态、状态日志和可验证结果来源。
- 在没有结构化 preflight artifact 的情况下，直接做“报告”只会把 CLI 文本包装成看起来更正式的输出，不够硬。

#### 不是先做 crypto-delete / crash consistency

- 研究报告明确把这些方向放在更高复杂度层级。
- 它们会引入新的存储模型、状态模型和一致性模型，不适合作为当前 CLI 原型的下一小步。

### 建议批准的下一阶段范围

本次待批准、待后续实现的范围，仅限于：

**阶段 2：结构化 inspect 证据与预执行计划。**

它是现有 `inspect` 的增强，不是新的 destructive 子系统。建议范围收敛为：

- 为 `inspect_target(...)` 增量补入结构化 evidence / risk / action-plan 数据
- 为 CLI 增量补入更清晰的 detailed preflight 展示
- 在不破坏默认 `inspect` 简洁输出的前提下，为未来 JSON / report 导出预留 schema

明确不包含：

- ATA Secure Erase / ATA Sanitize 执行
- NVMe Sanitize / Format 执行
- PSID revert
- free-space wipe
- GUI
- 取证级证书
- 崩溃恢复日志

### 目标效果

这一阶段完成后，系统在执行 `inspect --detail` 或等价详细模式时，应该能更可信地回答下面这些问题：

- 当前 recommendation 是基于哪几类证据得出的：路径安全、平台查询、sysfs / storage stack、启发式保守规则，还是受限场景
- 当前结论是“观测到的事实”“启发式推断”还是“由于限制只能保守处理”
- 当前更适合的动作是“继续文件级 best-effort”“进入整设备 sanitize review”“进入 crypto-erase review”还是“直接阻断”
- 当前推荐动作的作用域到底是“当前 path”还是“底层整设备 review”
- 哪些阻塞项让某条路径不能执行，例如 USB bridge、network share、平台探测缺口、target scope 不匹配等

### 具体实现方案

#### 1. 领域模型扩展

当前 `DeviceCapabilities::evidence` 和 `ErasePathAdvice::reasons` 都是自由文本集合，这对人类可读性足够，但对后续验证链路不够。

建议增量引入以下结构化模型，而不是推翻当前 API：

- `EvidenceSource`
  - 描述证据来自哪里，例如 `PathInspection`、`WindowsStorageQuery`、`LinuxSysfs`、`MountMetadata`、`HeuristicGuard`
- `EvidenceConfidence`
  - 至少区分 `Observed`、`Inferred`、`ConservativeFallback`
- `EvidenceSubject`
  - 指向当前证据在解释什么，例如 `BusKind`、`TrimSupport`、`DeviceSanitizeReview`、`CryptoEraseReview`、`Restriction`
- `RiskFlag`
  - 显式表达 `UsbBridgeSuspected`、`NetworkBacked`、`VirtualizedDevice`、`PlatformProbeGap`、`WholeDeviceReviewRequired` 等
- `ActionCandidateState`
  - 建议至少区分 `Preferred`、`ReviewOnly`、`Blocked`、`Unavailable`
- `ActionTargetScope`
  - 显式区分 `CurrentPath` 与 `UnderlyingDevice`
- `CapabilityEvidenceItem`
  - 单条结构化证据：subject、source、confidence、summary、optional details
- `ActionCandidate`
  - 一条预执行动作候选：method、target_scope、state、reasons、blockers
- `InspectPreflightPlan`
  - 聚合 `risk_flags`、`action_candidates`、以及可选的诊断说明

与现有公共 API 的兼容策略建议如下：

- 保留当前 `DeviceCapabilities::evidence` 与 `ErasePathAdvice::reasons`
- 新增结构化字段作为增量补充
- 由结构化模型派生当前自由文本，而不是让两套数据源并行漂移

这样做的好处是：

- 不破坏当前 CLI 和外部调用方的基本使用方式
- 为后续 JSON 导出、报告系统和设备级执行前置检查提供稳定 schema
- 让 docs 里反复强调的“推断 vs 确认”真正落到可建模对象上

#### 2. 内部分层方案

建议继续沿用当前架构，而不是新增大而全服务层：

- `PathInspector`
  - 继续负责目标类型、危险路径、粗粒度 `StorageKind`、基础 warning
- `DeviceCapabilityInspector`
  - 继续负责平台只读探测，但输出从“能力值 + 自由文本”扩展为“能力值 + 结构化 evidence items”
- `ErasePathAdvisor`
  - 从“首选路径 + 理由文本”扩展为“首选 advice + 多条 action candidates + blockers / reasons”
- `SecureWipeFacade::inspect(...)`
  - 继续做三段式编排，不把 schema 组装逻辑泄漏到 CLI

当前阶段不建议新增一个全新 `InspectionService` 或 `ExecutionPlanner` 公共对象。理由是：现有 `inspect` 已经是自然入口，先在当前对象边界内演进，复杂度最低。

#### 3. CLI 暴露方案

建议继续复用 `inspect`，不新增新的破坏性命令，也不抢先设计“设备擦除执行”子命令。

推荐的 CLI 方案：

- 默认 `inspect <path>` 保持尽量稳定，继续输出简洁摘要
- `inspect --detail <path>` 增加新的分组输出：
  - structured capability evidence
  - risk flags
  - action candidates / blockers
- 若实现成本可控，可以把 JSON 作为**阶段 2 的后半步**，例如：
  - `inspect --json <path>`
  - 或 `inspect --detail --format json`

但即使加入 JSON，也应坚持以下约束：

- 默认文本输出优先服务人工审查
- JSON schema 必须围绕已有公共语义设计，而不是临时拼接 CLI 文本
- 默认不输出完整敏感设备标识，避免把诊断信息误包装成“审计证书”

#### 4. 测试方案

这一阶段的测试重点，不是“当前机器到底是不是 NVMe”，而是“给定 probe 结果时，系统是否能稳定地产生正确 evidence / risk / plan”。

建议：

- 继续复用 `FakeDeviceCapabilityProbe`
- 为 `DeviceCapabilityInspector` 增加 evidence-item 级断言
- 为 `ErasePathAdvisor` 增加 action-candidate 顺序、state 与 blocker 断言
- 为 CLI 增加 detailed 模式的 grouped-output 断言
- 若加入 JSON，再补 schema 级测试：
  - 核心字段存在
  - 枚举值稳定
  - 不依赖当前开发机真实磁盘

#### 5. 文档同步方案

一旦批准并实现，至少需要同步更新：

- `docs/engineering/requirements.md`
- `docs/engineering/architecture.md`
- `docs/engineering/api.md`
- `docs/guide/cli.md`
- `docs/guide/safety.md`
- `docs/technical/secure-erasure-algorithms.md`
- 若引入新的术语枚举，还要同步 `docs/technical/background-and-terms.md`

文档重点应放在：

- 这一步仍然是 **read-only preflight**，不是 destructive command 执行
- 输出变得更“结构化”和“可复核”，不代表已经得到设备厂商级验证
- `UnderlyingDevice` 级候选动作只表示“值得进入整设备 review”，不是“当前 path 可以直接触发整盘清除”

### 需要特别注意的问题

#### 1. 不要把 path 级 inspect 和整设备级执行混为一谈

这是当前系统迈向设备级能力时最容易踩的坑。

用户检查的是一个 `path`，但 `DeviceSanitizeReview` / `CryptoEraseReview` 指向的往往是**底层整设备**。因此，preflight 模型里必须显式带 `ActionTargetScope`，否则后续 CLI 很容易给出误导性暗示。

#### 2. 不要把启发式推断伪装成“设备已确认支持”

当前 docs 已多次强调：`Supported` 在当前阶段仍然是“值得 review 的支持线索”，不是 destructive command 已可执行的最终结论。结构化 schema 需要进一步把这个事实编码进去，而不是继续让调用方从字符串语气里猜。

#### 3. USB bridge / RAID / 虚拟盘 / 平台探测缺口必须显式成为 blocker

这类场景不应只是 warning 文案，而应该进入 `risk_flags` 或 `action_candidates.blockers`。这样后续若进入真实设备级执行阶段，系统才能复用这些信号做硬性拒绝，而不是再次从文本里解析。

#### 4. 默认不要泄露过多敏感设备标识

若后续确实需要 model / serial / device path：

- 默认应脱敏或部分隐藏
- 仅在明确诊断模式下展开
- 文档中应明确说明：这些字段属于诊断与 preflight，不属于证书级审计证明

#### 5. 公共 API 需要加法式演进

当前 `include/secure_wipe.h` 已被文档和测试广泛引用。下一阶段应避免：

- 直接删除现有自由文本字段
- 修改现有枚举的既有含义
- 让 CLI 才知道如何拼装 structured preflight

正确做法是：新增结构化字段，保留现有行为，并逐步让旧自由文本成为结构化模型的派生视图。

### 小步迭代顺序（从易到难）

建议按以下顺序推进，而不是直接跳到设备级 destructive 路径：

1. **阶段 2A：结构化 evidence schema + 内部生成链路**
  - 先把 evidence / risk / action-plan 模型在 API 与内部对象里建出来
  - 仍然只保留现有 human-readable CLI

2. **阶段 2B：`inspect --detail` 分组输出升级**
  - 让人工审查时能直接看到 risk flags、candidate actions、scope、blockers
  - 默认 `inspect` 保持稳定

3. **阶段 2C：可选的 JSON 导出**
  - 只在 2A / 2B 稳定后加入
  - 服务后续自动化验证、报告系统和未来 UI，但当前仍以 CLI 为主

4. **阶段 3：单平台、单协议、受限范围的设备级执行试点**
  - 例如 Linux-first NVMe sanitize review -> execution path
  - 必须复用前面已经稳定的 structured preflight schema

5. **阶段 4：验证与报告**
  - 在真实执行路径落地后，再把状态日志、抽样验证和更正式的报告做成一等能力

### 本阶段验收口径（待批准后实现时使用）

- `inspect` 默认输出不发生破坏性漂移
- `inspect --detail` 能稳定输出新增的 evidence / risk / candidate-action 信息
- 无法可靠确认能力时，系统输出保守结论，不夸大支持范围
- 新增测试不依赖开发机真实磁盘型号或真实设备命令
- 公共 API 以增量扩展为主，不破坏现有调用方式
- `cmake --build build` 通过
- `ctest --test-dir build -C Debug --output-on-failure` 通过
- 若文档同步实现，`python tools/validate_docs_code_links.py` 与 `.venv\Scripts\python -m mkdocs build --strict` 也必须通过

### 审查后建议批准的实现版本

1. 先做“结构化证据 + 预执行计划”这一层，把当前 `inspect` 从自由文本解释升级为正式 preflight artifact。
2. 继续复用 `inspect` 作为唯一入口，不在这一轮引入新的 destructive 子命令。
3. 默认优先人工可读的 `--detail` 输出，JSON 导出放在同一阶段的后半步或下一小步，而不是一开始就把 CLI 重心转成数据导出。
4. 把 `UnderlyingDevice` scope、`blockers`、`confidence` 做成 schema 的硬字段，而不是继续依赖解释性文案。
5. 在这一层稳定之前，不批准真实 ATA / NVMe destructive command 执行进入主线实现。

## 2026-05-21 结构化证据与预执行计划三轮设计审查修订

### 第 1 轮：公共契约与改动面审查

#### 发现的问题

- 上一版方案的目标方向是对的，但 public schema 初稿略偏“大而全”：同时提出 `InspectPreflightPlan`、`CapabilityEvidenceItem`、`ActionCandidate`、多组新枚举和可选 JSON 路线，容易在第一版就把 `include/secure_wipe.h`、CLI、docs 和 tests 的改动面同时放大。
- 若在第一版就引入“新的顶层 preflight 服务对象 + 新的顶层聚合类型 + JSON 导出预埋”，实现成本会明显高于当前系统真实需要。
- 当前系统已经有稳定的 `DeviceCapabilities` 与 `ErasePathAdvice` 两个公共聚合对象；若无必要再新增并行顶层结构，调用方理解成本会上升。

#### 审查结论

- 第一版实现必须坚持**加法式演进**，优先复用现有聚合对象，而不是新增过多并行概念。
- `结构化证据` 与 `预执行计划` 要落地，但应尽量挂载到现有 `DeviceCapabilities` / `ErasePathAdvice` 之下，避免让 `InspectionReport` 在单次迭代里膨胀出过多新层级。
- 当前实现不应把 JSON 导出列为同一阶段的硬交付；它是自然扩展点，但不是第一批必须实现的核心价值。

#### 修改后的设计决策

- 保留现有：
  - `DeviceCapabilities::evidence`
  - `ErasePathAdvice::reasons`
- 新增但收敛到现有聚合对象内部：
  - `CapabilityEvidenceItem` 列表，挂在 `DeviceCapabilities` 下
  - `PreflightRisk` 列表，挂在 `ErasePathAdvice` 下
  - `ActionCandidate` 列表，挂在 `ErasePathAdvice` 下
- 不在第一版新增独立的 `InspectPreflightPlan` 顶层公共类型。
- JSON 导出从“当前实现范围”降级为“后续自然扩展点”。

### 第 2 轮：语义可信度与单一事实源审查

#### 发现的问题

- 如果结构化字段和当前 `evidence` / `reasons` 自由文本各自独立维护，后续极易出现一边更新、一边遗漏的双重事实源。
- 当前 docs 反复强调“推断不等于确认”，但上一版方案里对 `Supported`、`Observed`、`Inferred`、`Blocked` 的语义边界还不够紧，第一版若枚举过细，反而更容易让调用方误解它们是设备厂商级确认。
- `risk_flags` 与 `action_candidates.blockers` 若来源不清，CLI 容易把它们打印成漂亮的文案，却没有真正可复核的证据链。

#### 审查结论

- 第一版必须建立**单一事实源**：结构化模型是主数据，自由文本是派生视图，而不是反过来。
- 结构化 schema 需要围绕当前系统已经能可靠产生的语义来设计，而不是预支未来阶段才有的精度。
- `Observed / Inferred / ConservativeFallback` 这类可信度级别是有价值的，但第一版不要扩成更复杂的证据等级体系。

#### 修改后的设计决策

- 结构化 evidence 字段采用最小可用集合：
  - `EvidenceSubject`
  - `EvidenceSource`
  - `EvidenceConfidence`
  - `summary`
- 不在第一版加入额外的任意 `details` map / JSON payload / 未约束字典字段。
- 通过内部 helper 统一追加结构化 evidence，并同步派生现有 `DeviceCapabilities::evidence` 文本。
- 通过内部 helper 统一追加 action candidate / risk flag，并同步派生现有 `ErasePathAdvice::reasons` 文本中真正需要对人展示的主理由。
- `Supported` 在当前阶段继续只表示“足以进入 review 的支持线索”，不会在任何新增字段里被解释为 destructive command 已确认可执行。

### 第 3 轮：作用域、安全边界与可交付性审查

#### 发现的问题

- 当前 inspect 的输入是一个 `path`，但 `DeviceSanitizeReview` / `CryptoEraseReview` 指向的往往是 `UnderlyingDevice` 级动作。如果 schema 不显式编码 `scope`，用户会自然把“建议 review 整设备路径”误读成“可以直接对当前 path 执行设备级命令”。
- `USB bridge`、`network share`、`virtualized storage`、`platform probe gap` 这些限制信号如果只存在于 warning 文案里，后续很难复用到真实设备级执行阶段做硬性闸门。
- 若第一版同时做 schema、CLI 重排、JSON 导出和 docs 大改，验证成本会过高，不适合当前要求的“小步、谨慎、可频繁 push”节奏。

#### 审查结论

- 第一版的最小可交付版本必须显式区分 `CurrentPath` 与 `UnderlyingDevice` 作用域。
- 风险信号必须进入结构化字段，而不能继续只存在于自然语言 warning 里。
- 当前交付只覆盖：公共类型加法扩展、内部生成链路、`inspect --detail` 分组输出、测试与 docs 同步；不包括 JSON，不包括新的 destructive 子命令，不包括设备标识扩张。

#### 修改后的设计决策

- 新增最小枚举集合：
  - `EvidenceSubject`
  - `EvidenceSource`
  - `EvidenceConfidence`
  - `PreflightRisk`
  - `ActionCandidateState`
  - `ActionTargetScope`
- 新增最小结构集合：
  - `CapabilityEvidenceItem`
  - `ActionCandidate`
- `ActionCandidate` 必带：
  - `method`
  - `state`
  - `target_scope`
  - `summary`
  - `blockers`
- `inspect --detail` 文本输出升级为三组：
  - capability evidence
  - preflight risk
  - action candidate
- 默认 `inspect` 输出保持稳定；不新增 `inspect --json`；不新增新的执行命令；不输出完整 model / serial / raw device path。

### 三轮审查后的批准实现版本

本任务进入实现阶段时，批准的范围收敛为：

1. 在 `include/secure_wipe.h` 中以加法方式新增最小结构化 schema：`CapabilityEvidenceItem`、`ActionCandidate` 及相关最小枚举。
2. 在 `DeviceCapabilities` 下新增结构化 evidence 列表，在 `ErasePathAdvice` 下新增 `risk_flags` 与 `action_candidates`。
3. 在 `src/` 中通过统一 helper 生成结构化 evidence / risk / action-candidate，并由这些结构化字段派生现有自由文本视图，避免双重事实源。
4. 在 `src/cli_application.cpp` 中升级 `inspect --detail` 的文本呈现，使其显式输出 evidence、risk 和 action-candidate 分组，但不破坏默认 `inspect`。
5. 在 `tests/` 中补齐 API、advisor 和 CLI 的结构化字段断言，且测试不依赖真实设备。
6. 在 `docs/` 中同步更新 requirements、architecture、api、cli、safety 和 algorithm 文档，明确这仍然是 **read-only preflight**，不是设备级 destructive command 执行。

### 本轮设计审查后的刻意不做

- 不在这一轮实现 JSON 导出。
- 不在这一轮新增独立 `InspectPreflightPlan` 顶层公共类型。
- 不在这一轮输出完整敏感设备标识。
- 不在这一轮新增任何 ATA / NVMe / PSID destructive command 执行路径。
- 不在这一轮把 report / certificate 伪装成已经存在的能力。

## 2026-05-21 结构化证据与预执行计划实现检查点

### 本轮已落地的实现范围

- `include/secure_wipe.h` 已以加法方式新增：
  - `EvidenceSubject`
  - `EvidenceSource`
  - `EvidenceConfidence`
  - `PreflightRisk`
  - `ActionCandidateState`
  - `ActionTargetScope`
  - `CapabilityEvidenceItem`
  - `ActionCandidate`
- `DeviceCapabilities` 已新增 `evidence_items`，`ErasePathAdvice` 已新增 `risk_flags` 与 `action_candidates`。
- `DeviceCapabilityInspector` 已把平台探测和 review 状态解释同步写入结构化 evidence。
- `ErasePathAdvisor` 已把 read-only preflight 风险、候选动作、作用域和 blocker 建模到结构化字段中。
- `inspect --detail` 已新增三组输出：
  - `capability-evidence`
  - `preflight-risk`
  - `preflight-action` / `preflight-blocker`
- `tests/capability_inspection_tests.cpp` 已补齐结构化 evidence、risk 和 candidate-action 的断言。
- `docs/` 已同步更新 requirements、architecture、api、cli、safety、algorithm 与术语文档。

### 本轮刻意保持的边界

- 仍然不执行 ATA / NVMe / PSID destructive device command。
- 仍然不引入 JSON 导出。
- 仍然不引入独立顶层 `InspectPreflightPlan` 公共类型。
- 仍然保留现有自由文本 `evidence` / `reasons`，并将结构化字段作为增量扩展。

### 当前验证结果

- `cmake --build build` 通过。
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests` 通过。
- `python tools/validate_docs_code_links.py` 通过。
- `python -m mkdocs build --strict` 通过。

### 下一阶段

进入实现后的三轮审查 / 重构，目标是：

1. 压缩重复逻辑，确保结构化字段生成链路更清晰。
2. 继续保持默认 `inspect` 与 read-only preflight 边界稳定。
3. 每轮均以可执行验证和文档同步收尾，再分别提交与 push。

## 2026-05-21 结构化证据与预执行计划实现后审查 / 重构

### 第 1 轮：evidence 追加链路去重

#### 发现的问题

- `src/device_capability_inspector.cpp` 中 `append_probe_evidence(...)` 与 `append_capability_evidence(...)` 维护了同一段“同时写入自由文本和结构化 evidence”的重复逻辑。
- 这种重复会放大后续漂移风险：如果以后新增 evidence 字段或调整派生顺序，容易只改一处。

#### 本轮修改

- 抽出共享 `append_evidence(...)` helper，统一负责把单条 evidence 同步写入 `evidence_items` 与自由文本 `evidence`。
- 保留原有 `append_probe_evidence(...)` 与 `append_capability_evidence(...)` 作为窄包装，避免扩大调用点改动面。

#### 刻意不做

- 不改变任何 `EvidenceSubject / EvidenceSource / EvidenceConfidence` 的语义。
- 不改变当前平台探测逻辑与 CLI 输出。

#### 验证

- `cmake --build build` 通过。
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests` 通过。

### 第 2 轮：preflight candidate 构造链路收敛

#### 发现的问题

- `src/erase_path_advisor.cpp` 中 direct advice、review advice 和 current-path fallback 都在各自拼装 `ActionCandidate`。
- `current-path` 候选动作的 `method` 与 `summary` 还分散在两个 helper 中，后续很容易出现 method 改了但 summary 没同步的漂移。

#### 本轮修改

- 新增共享 `make_action_candidate(...)` helper，统一候选动作的基础构造方式。
- 把 `current-path` fallback 收敛为单个 `current_path_candidate_spec(...)`，让 method 和 summary 成对返回。
- 让 direct recommendation 与 review-before-wipe 分支都复用同一套 candidate 基础构造逻辑。

#### 刻意不做

- 不改变任何 candidate 的状态、scope、blocker 或输出顺序。
- 不改动 `ErasePathAdvice` 的公共结构和 CLI 渲染格式。

#### 验证

- `cmake --build build` 通过。
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests` 通过。

### 第 3 轮：CLI detail 输出职责拆分

#### 发现的问题

- `print_detailed_inspection_report(...)` 同时负责稳定 detail 字段、structured evidence fallback、risk 输出、candidate 输出和 reason 输出。
- 当前功能虽正确，但如果后续继续扩展 detail 输出，这个函数最容易演变成新的“渲染堆栈入口”。

#### 本轮修改

- 新增 `print_capability_evidence(...)`，专门处理结构化 evidence 与自由文本 fallback。
- 新增 `print_preflight_advice(...)`，专门处理 `risk_flags`、`action_candidates`、`blockers` 与 `reasons` 的输出。
- 让 `print_detailed_inspection_report(...)` 只保留稳定 detail 头字段和这两个窄 helper 的编排职责。

#### 刻意不做

- 不改变任何 detail 字段名称、输出顺序或字符串格式。
- 不引入新的 CLI 开关，也不把文本输出改成 JSON 导向。

#### 验证

- `cmake --build build` 通过。
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests` 通过。

## 2026-05-21 结构化证据与预执行计划 JSON 导出跟进

### 本轮目标

在不改变 read-only preflight 边界的前提下，为现有 `InspectionReport` 增加一个**可选的机器可读导出路径**，避免自动化调用方继续解析 `inspect --detail` 文本输出。

### 本轮已落地的实现范围

- CLI 新增 `inspect --json <path>`。
- JSON 导出直接复用现有 `InspectionReport` 对象图，键名保持 snake_case。
- JSON 中继续保留：
  - 基础 inspect 字段
  - `device_capabilities.evidence`
  - `device_capabilities.evidence_items`
  - `erase_path_advice.reasons`
  - `erase_path_advice.risk_flags`
  - `erase_path_advice.action_candidates`
- `--json` 输出的是完整 inspection result；即使与 `--detail` 同时传入，也仍以 JSON 为唯一输出格式。

### 本轮刻意保持的边界

- 仍然不引入独立顶层 `InspectPreflightPlan` 公共类型。
- 仍然不输出完整敏感设备标识。
- 仍然不进入 ATA / NVMe / PSID destructive command 执行。
- JSON 只是现有 read-only inspection report 的序列化，不是独立执行计划文件。

### 同步更新

- `tests/` 已新增 `inspect --json` 的 schema 级断言。
- `docs/` 已同步更新 CLI、API、requirements、architecture、safety、algorithm 与术语说明。

### 验证口径

- `cmake --build build`
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests`
- `ctest --test-dir build -C Debug --output-on-failure`
- `python tools/validate_docs_code_links.py`
- `.venv\Scripts\python -m mkdocs build --strict`

## 2026-05-22 inspect JSON 第 1 阶段重构检查点

### 本轮已落地的实现范围

- 将 `nlohmann/json` `v3.11.3` 以 vendored header-only 方式引入到 `third_party/`。
- 新增依赖专属许可证文件 `third_party/NLOHMANN-JSON-LICENSE`。
- CMake 现已显式暴露 `nlohmann_json::nlohmann_json` 接口目标，并接入 `securewipe` 与 `securewipe_tests`。
- `inspect --json` 已从手写字符串转义/对象拼装改为基于 `nlohmann::ordered_json` 的原位实现。

### 本轮刻意不做

- 暂不改变 `inspect --json` 的字段名、嵌套 shape 或 read-only 语义。
- 暂不把 JSON 序列化逻辑从 `src/cli_application.cpp` 抽离；该职责重构留到下一阶段。
- 暂不引入新的顶层 JSON schema、版本字段或额外输出格式。

### 当前验证结果

- `cmake --build build` 通过。
- `ctest --test-dir build -C Debug --output-on-failure -R securewipe_tests` 通过。

### 下一阶段

- 将 JSON 序列化从 `src/cli_application.cpp` 抽离到新的私有 formatter/serializer 模块，收窄 CLI 应用层职责。
