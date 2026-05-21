## 2026-05-20 14:24 Modern C++ 全局职责解耦

- 识别到的主要坏味道：`secure_wipe_engine.cpp` 过大且多职责；库层与 `std::cout/std::cerr` 耦合；CLI 解析与错误构造重复；顶层调用缺少清晰的执行上下文抽象。
- 本轮重构目标：按职责拆分引擎实现文件，引入内部报告抽象以隔离库层输出，收敛 CLI 解析与展示逻辑，保持公共 API 与现有行为稳定。
- 实施结果：引擎拆分为 `path_inspector.cpp`、`native_file.cpp`、`file_wiper.cpp`、`directory_wiper.cpp` 与轻量 `secure_wipe_engine.cpp`；新增 `OperationReporter` 抽象；CLI 解析改为更强类型的退出码与统一错误构造；`secure_wipe.cpp` 收敛默认 facade 接线。
- 验证标准：`cmake --build build`、`ctest --test-dir build -C Debug --output-on-failure` 通过，并保留 `inspect`、`wipe`、`wipe-dir --dry-run` 的当前行为。

## 2026-05-20 CLI11 重构 `cli_application.cpp`

### 重构前代码

```cpp
int CommandLineApplication::run(const std::vector<std::string>& args) const {
	const ParseResult parse_result = parse(args);
	if (!parse_result.ok) {
		if (!parse_result.error_message.empty()) {
			error_output_ << parse_result.error_message << "\n\n";
		}
		print_help(error_output_);
		return to_exit_code(parse_result.exit_code);
	}

	switch (parse_result.request.kind) {
	case CommandKind::Help:
		print_help(output_);
		return to_exit_code(ExitCode::Success);
	case CommandKind::Inspect:
		return run_inspect(parse_result.request);
	case CommandKind::WipeFile:
		return run_wipe_file(parse_result.request);
	case CommandKind::WipeDirectory:
		return run_wipe_directory(parse_result.request);
	}

	error_output_ << "Error: unsupported command\n";
	return to_exit_code(ExitCode::Rejected);
}

CommandLineApplication::ParseResult CommandLineApplication::parse(const std::vector<std::string>& args) {
	if (args.empty()) {
		return make_parse_success(CommandRequest{});
	}

	const std::string_view command = args[0];
	if (command == "--help"sv || command == "-h"sv) {
		return make_parse_success(CommandRequest{});
	}

	if (command == "inspect"sv) {
		if (args.size() != 2) {
			return make_parse_error("Error: inspect requires exactly one <path> argument");
		}

		CommandRequest request;
		request.kind = CommandKind::Inspect;
		request.path = args[1];
		return make_parse_success(std::move(request));
	}

	if (command != "wipe"sv && command != "wipe-dir"sv) {
		return make_parse_error("Unknown command: " + std::string(command));
	}

	// ... 手写 `--passes` / `--pattern` / `--dry-run` / `--yes` 分支 ...
}

void CommandLineApplication::print_help(std::ostream& output) {
	output <<
R"(SecureWipe-Cpp

Usage:
  securewipe --help
  securewipe inspect <path>
  securewipe wipe <path> [--passes N] [--pattern zeros|random]
  securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]

Examples:
  securewipe inspect test.txt
  securewipe wipe test.txt --passes 1 --pattern zeros
  securewipe wipe-dir ./tmp --dry-run
  securewipe wipe-dir ./tmp --passes 1 --pattern zeros --yes
)";
}
```

### 重构理由

- 坏味道 1：手写命令行解析分支过多，`parse` 同时承担子命令识别、参数个数校验、类型校验、错误信息拼接和帮助入口判断，职责混杂。
- 坏味道 2：`print_help` 维护一份手写帮助文案，命令结构和帮助文本存在双重事实源，后续扩展参数时容易漂移。
- 坏味道 3：`--passes` 与 `--pattern` 的约束逻辑手写在循环里，没有利用成熟 CLI 库的必选参数、类型检查、枚举转换和自动帮助能力。
- 工程目标：把命令结构交给 CLI11 声明式建模，只保留本项目真正关心的退出码语义与领域执行逻辑。

### 重构方案

- 将 CLI11 `v2.6.2` 的 single-header 与许可证固定到仓库 `third_party/`，避免构建时再依赖网络或 `FetchContent` 临时目录。
- CMake 暴露本地 `CLI11::CLI11` 接口目标，调用端仍以标准第三方库方式链接，不把第三方 include 路径散落到各目标中。
- 用 CLI11 的主命令 + `inspect` / `wipe` / `wipe-dir` 子命令描述 CLI 结构。
- 用 `required()` 约束位置参数 `path`。
- 用 `CLI::PositiveNumber` 校验 `--passes`。
- 用 `CLI::CheckedTransformer` 把 `zeros|random` 转换为 `Pattern` 枚举。
- 删除手写 `print_help`，统一改为 CLI11 自动生成帮助文本，并通过 footer 维护 examples。
- 保留项目既有退出码语义：帮助为 `0`，领域执行失败为 `1`，参数或策略拒绝为 `2`。
- 在 `main.cpp` 中使用 `CLI::App::ensure_utf8(argv)`，改善 Windows 下 UTF-8 参数处理。

### 重构后代码

```cpp
CommandLineApplication::ParseResult CommandLineApplication::parse(const std::vector<std::string>& args) {
	ParseResult result;
	CommandRequest request;

	CLI::App app{"SecureWipe-Cpp"};
	app.name("securewipe");
	app.footer(std::string(kCliFooter));
	app.require_subcommand(0, 1);

	auto* inspect_command = app.add_subcommand("inspect", "Inspect a target and report the recommended wipe strategy.");
	inspect_command->add_option("path", request.path, "Target path")->required();

	auto* wipe_command = app.add_subcommand("wipe", "Best-effort wipe of a single file.");
	configure_shared_wipe_options(*wipe_command, request.path, request.options);

	auto* wipe_directory_command = app.add_subcommand("wipe-dir", "Best-effort recursive wipe of a directory.");
	configure_shared_wipe_options(*wipe_directory_command, request.path, request.options);
	wipe_directory_command->add_flag("--dry-run", request.dry_run, "List files without deleting them");
	wipe_directory_command->add_flag("--yes", request.yes, "Confirm destructive directory wipe");

	if (args.empty()) {
		result.ok = true;
		result.request.kind = CommandKind::Help;
		result.help_text = app.help();
		return result;
	}

	try {
		std::vector<std::string> parse_args(args.rbegin(), args.rend());
		app.parse(parse_args);
	} catch (const CLI::ParseError& error) {
		if (error.get_exit_code() == 0) {
			result.ok = true;
			result.request.kind = CommandKind::Help;
			result.help_text = select_help(app, *inspect_command, *wipe_command, *wipe_directory_command);
			return result;
		}

		result.exit_code = ExitCode::Rejected;
		result.error_message = error.what();
		result.help_text = select_help(app, *inspect_command, *wipe_command, *wipe_directory_command);
		return result;
	}

	result.ok = true;
	result.request = std::move(request);
	if (inspect_command->parsed()) {
		result.request.kind = CommandKind::Inspect;
	} else if (wipe_command->parsed()) {
		result.request.kind = CommandKind::WipeFile;
	} else if (wipe_directory_command->parsed()) {
		result.request.kind = CommandKind::WipeDirectory;
	}

	return result;
}

void configure_shared_wipe_options(CLI::App& command, std::string& path, WipeOptions& options) {
	command.add_option("path", path, "Target path")->required();
	command.add_option("--passes", options.passes, "Overwrite pass count")
		->check(CLI::PositiveNumber)
		->default_val(options.passes);
	command.add_option("--pattern", options.pattern, "Overwrite pattern")
		->transform(CLI::CheckedTransformer(kPatternOptions))
		->default_str("zeros");
}
```

### 验证要点

- `securewipe --help` 由 CLI11 自动生成帮助。
- 无参数调用返回 `0` 并输出帮助。
- `wipe` / `wipe-dir` 的位置参数、正整数 `--passes` 与枚举 `--pattern` 由 CLI11 负责校验。
- 现有 CLI 返回码契约不变，回归测试继续覆盖 inspect 输出标签与危险目录拒绝路径。
- 构建不再依赖运行时下载 CLI11；在离线或网络不稳定环境下也可以直接配置与编译。

## 2026-05-20 STL / 更现代声明式风格函数级重构

### 评估目标

- 逐文件检查 `src/` 下函数是否可以用 STL algorithm 或更现代的 C++ 写法改善可读性与可维护性。
- 标准不是“更短”或“更炫”，而是是否更接近声明式表达、是否更容易理解、修改和扩展。
- 明确避免为了算法而算法；高副作用 I/O 流程优先保持可跟踪的命令式结构。

### 标准选择结论

- 本轮未将项目从 C++17 提升到 C++20。
- 原因不是反对 `ranges`，而是当前仓库已经在 C++17 下具备 `std::find_if`、`std::any_of`、`std::array`、`std::optional` 等足够的现代工具；为了少量纯查找逻辑引入全局标准升级，收益不成比例。

### 已实施重构

#### `src/cli_application.cpp`

- `enum_label_or_unknown(...)`：由手写 `for` 查找改为 `std::find_if`，让意图直接表达为“从标签表中找匹配项，否则返回 unknown”。
- `select_help(...)`：由串行 `if` 链改为在固定子命令集合上做 `find_if` 选择，减少重复分支。
- `parse(...)` 中“哪个子命令被选中”的判定：改为在绑定表上做 `find_if`，避免继续扩展时反复堆叠 `if / else if`。

#### `src/path_inspector.cpp`

- Linux 下 mount 匹配逻辑：`filesystem_hint_for_path(...)` 与 `detect_storage_kind(...)` 之前各自维护一段近似相同的“找最具体 mount point”循环，现已抽成 `find_best_mount_entry(...)`，减少重复和未来漂移风险。
- `is_dangerous_directory(...)`：Windows 和非 Windows 的危险路径判断都改为基于 `std::array + std::any_of` 的声明式检查，替换多段重复的环境变量 / 固定路径比较分支。

### 评估后保留原状的函数与理由

#### `src/directory_wiper.cpp`

- `wipe(...)`：包含 dry-run 输出、副作用统计、失败上报和最终结果聚合。若强行改成 `for_each` 或累计式算法，控制流会更难读。
- `scan(...)`：核心是 `recursive_directory_iterator` 的遍历、递归控制和错误码分支，命令式循环最清晰。
- `remove_empty_directories(...)`：逆序删除目录比算法包装更直观。

#### `src/file_wiper.cpp`

- `wipe(...)`：覆盖写入、分块循环、错误短路和删除流程高度状态化，不适合为了声明式而隐藏控制流。
- `obscure_name_best_effort(...)`：重命名重试属于典型命令式重试逻辑，`find_if` 反而会把失败处理压进 lambda 中，降低可读性。
- `fill_buffer(...)` 已经在随机写分支使用 `std::generate_n`，当前实现已经是合适的现代 STL 用法。

#### `src/native_file.cpp`

- 该文件本质上是跨平台底层 I/O 包装，重点是逐步 guard 和错误返回。用算法不会提升可维护性。

#### `src/secure_wipe.cpp`

- 顶层 facade 转发已经通过 `invoke_with_default_facade(...)` 收敛，当前实现已经足够简洁且清晰。

#### `src/secure_wipe_engine.cpp`

- 当前仅包含轻量 reporter 与 facade 组合代码，没有值得再用 STL algorithm 改写的重复选择逻辑。

#### `src/main.cpp`

- 当前入口函数只负责 `ensure_utf8`、参数装配和应用对象调用，已经是最小且清晰的形式。

### 本轮结论

- 适合算法化 / 声明式重构的，主要是“查找、匹配、去重复筛选”这一类纯逻辑 helper。
- 不适合算法化的，主要是“文件系统遍历、文件覆写、系统 API 调用、失败即返回”的高副作用流程。
- 因此，本轮不是全面把 `for` 改成 STL，而是按可读性收益选择性替换。

### 验证

- `cmake --build build`
- `ctest --test-dir build -C Debug --output-on-failure`
- 结果：构建通过，7 个测试全部通过。

## 2026-05-20 C++20 / `string_view` 类型级重构

### 评估目标

- 逐文件检查 `src/` 下哪些 `std::string` 参数其实只承担“只读视图”语义。
- 逐处评估 `const char*` 是否只是历史遗留，还是仍然被 C/C++ 运行时 API 要求为 null-terminated 输入。
- 在不牺牲路径语义和结果对象所有权语义的前提下，将项目升级到 C++20，并只在有明显收益的地方引入 `std::string_view` 与 `std::ranges`。

### 标准选择结论

- 本轮显式将项目标准从 C++17 提升到 C++20。
- 原因不是为了追新，而是当前需求已经明确要求采用 `>= C++20`，并且本轮确实落地了两类适合 C++20 的改进：
	- 路径与错误前缀这类只读文本参数改用 `std::string_view`
	- 纯查找 / 纯匹配 helper 改用 `std::ranges` 表达意图

### 已实施重构

#### 构建与标准

- `CMakeLists.txt`：`CMAKE_CXX_STANDARD` 与 `target_compile_features` 从 17 升到 20。

#### 公共与内部路径参数

- `include/secure_wipe.h`：顶层 API `inspect_target(...)`、`wipe_file(...)`、`wipe_directory(...)` 的路径参数改为 `std::string_view`。
- `src/internal/secure_wipe_engine.h`：`PathInspector`、`FileWiper`、`DirectoryWiper`、`SecureWipeFacade` 的对应只读路径参数同步改为 `std::string_view`。
- 新增 `path_from_view(...)` 内部 helper，把视图参数在真正进入文件系统逻辑之前统一转换为 `fs::path`。

#### 错误消息与只读文本

- `src/native_file.cpp` / `src/internal/secure_wipe_engine.h`：
	- `NativeFile::open_error()` 改为返回 `std::string_view`
	- `NativeFile::last_error(...)` 的前缀参数改为 `std::string_view`
- `src/file_wiper.cpp`：
	- `validate_options(...)` 改为返回 `std::string_view`，因为它只返回静态错误文案
	- `success_message(...)` 改为返回 `std::string_view`，因为它只在两条固定成功文案之间选择
- `src/directory_wiper.cpp` / `src/file_wiper.cpp`：局部 `make_error_result(...)` 改为接收 `std::string_view`，在结果对象中复制为拥有型 `std::string`

#### C++20 ranges

- `src/cli_application.cpp`：
	- `enum_label_or_unknown(...)` 改为 `std::ranges::find(..., projection)`，直接表达“按枚举值查标签”
	- `select_help(...)` 与 `parse(...)` 中的纯选择逻辑改为 `std::ranges::find_if(...)`
- `src/path_inspector.cpp`：危险目录判定改为 `std::ranges::any_of(...)`

### 明确保留原状的类型与理由

#### 仍保留 `std::string` 的地方

- `InspectionReport` 与 `WipeResult` 的字符串字段：它们是跨函数返回值，必须拥有自身存储，不能暴露悬垂 view 风险。
- `CommandRequest::path`：CLI11 解析过程需要写入一个拥有型字符串，之后再把它以 view 形式传入领域层最合适。
- 任何需要拼接、构造或持久保存错误消息的返回值：最终都继续落在拥有型 `std::string` 上。

#### 仍保留 `const char*` 的地方

- `main(int argc, char* argv[])`：这是 C/C++ 程序入口约定，不应“为了现代化”改变 ABI 语义。
- `PathInspector::environment_value(const char* name)`：底层使用 `_dupenv_s` / `std::getenv`，需要 null-terminated C 字符串。
- 这类位置不是“忘了改成 `string_view`”，而是经过评估后刻意保留。

### 本轮结论

- 适合替换为 `std::string_view` 的，是“只读输入、函数内立即消费、不跨边界持有”的文本参数。
- 不适合替换的，是“结果对象字段、CLI 可变存储、C API null-terminated 输入、文件系统拥有型路径对象”。
- 因此，本轮不是机械地把所有 `std::string` 都换成 view，而是按语义区分“视图”和“所有权”。

### 验证

- `cmake -B build -S .`
- `cmake --build build`
- `ctest --test-dir build -C Debug --output-on-failure`
- 结果：配置通过、完整编译通过、7 个测试全部通过。

## 2026-05-21 设备能力探测链路三轮迭代重构

### 范围与约束

- 目标粒度：模块 / 文件 / 函数级，重点针对新增的设备能力探测与擦除路径解释链路。
- 期望结果：减少重复策略判断、收紧策略选择边界、让平台探测主流程更容易扩展，同时保持行为不变。
- 非协商约束：
	- 保持 `include/secure_wipe.h` 公共 API 不变
	- 不改变 CLI 对外契约
	- 继续遵守当前 C++20 / CMake / CTest 工程基线
	- 每一轮都要在改动后立即通过编译和测试验证

### 第 1 轮：能力分类策略去重

- 识别到的坏味道：`device_capability_inspector.cpp` 中 `device_sanitize_review` 与 `crypto_erase_review` 的分类逻辑重复编码了同一套“network / USB bridge / virtual bus 保守处理”规则，后续新增总线类型时容易出现一边修改、另一边遗漏。
- 采取的重构：
	- 引入 `ReviewKind`
	- 将共享守卫收敛到 `classify_restricted_review_state(...)`
	- 将总线分支收敛到 `classify_review_for_bus(...)`
	- 由统一的 `classify_review_state(...)` 负责生成两种 review 结论
	- 增加测试覆盖 `rotational + unknown bus` 的保守结论
- 刻意不改动的部分：
	- 未改动任何公共枚举值或字段命名
	- 未把当前显式 `switch` 进一步压成表驱动结构，因为当前分支数量有限，显式分支仍更容易审查
	- 未改变现有证据文本
- 验证：`cmake --build build`、`ctest --test-dir build -C Debug --output-on-failure` 通过

### 第 2 轮：`ErasePathAdvisor` 决策与解释解耦

- 识别到的坏味道：`ErasePathAdvisor::advise(...)` 的 `ReviewBeforeWipe` 分支同时承担“选择首选 review 路径”和“追加解释文案”，策略优先级与附加理由混在一起，扩展时容易把主决策和附加原因搅在同一处。
- 采取的重构：
	- 引入 `ReviewSelection`
	- 抽出 `select_review_before_wipe_method(...)` 负责选择主路径
	- 抽出 `append_review_before_wipe_reasons(...)` 负责追加解释文本与限制性说明
	- 增加测试覆盖“device sanitize 不可用时回退到 crypto-erase review”
- 刻意不改动的部分：
	- 未改变现有优先级：`DeviceSanitizeReview` 仍优先于 `CryptoEraseReview`
	- 未调整现有解释文本的对外语义，只是重组生成位置
	- 未把所有 recommendation 都抽成独立策略对象，当前 `switch` 仍是最清晰的入口
- 验证：`cmake --build build`、`ctest --test-dir build -C Debug --output-on-failure` 通过

### 第 3 轮：平台探测主流程收口

- 识别到的坏味道：`SystemDeviceCapabilityProbe::probe(...)` 顶层流程同时承载共享前置守卫和大段 Windows / Linux 平台分支，使得“公共守卫逻辑”和“平台细节实现”交错，后续增加平台分支或证据采集时容易扩大修改面。
- 采取的重构：
	- 抽出 `probe_windows_device_capabilities(...)`
	- 抽出 `probe_linux_device_capabilities(...)`
	- 抽出 `probe_unsupported_platform_capabilities(...)`
	- 让 `SystemDeviceCapabilityProbe::probe(...)` 只保留共享的 `network` 早返回和平台分派
- 刻意不改动的部分：
	- 未再把平台 helper 下沉到新的翻译单元，当前文件体量和内聚性仍然可接受
	- 未新增任何平台能力或探测字段，只做结构整理
	- 未改变 `PathInspector` / `SecureWipeFacade` 的现有职责边界
- 验证：`cmake --build build`、`ctest --test-dir build -C Debug --output-on-failure` 通过

### 本次三轮重构后的结论

- 设备能力探测链路的策略判断、路径建议和平台探测分派边界比改动前更清晰。
- 当前最值得保留的非改动是：
	- 公共 API 保持稳定
	- CLI 输出契约保持稳定
	- 平台分支仍保持显式命令式结构，未为了“更现代”而把副作用流程压成难读的抽象
- 本次重构结束时，代码层验证仍以完整编译与完整测试通过为准。

## 2026-05-21 测试支撑层收口

### 目标与约束

- 目标：把新增能力相关测试从 `tests/test_secure_wipe.cpp` 的单文件堆叠里抽出，形成更清晰的测试支撑层与特性测试边界。
- 约束：
	- 继续保留当前最小自建测试 harness，不引入新的测试框架
	- 不改变现有测试语义与断言口径
	- 仍保证 `securewipe_tests` 单个可执行入口

### 识别到的坏味道

- `tests/test_secure_wipe.cpp` 同时承担测试入口、通用 helper、CLI 回归测试、文件/目录擦除测试，以及新增能力特性测试，职责已经开始混杂。
- 能力特性测试依赖 `FakeDeviceCapabilityProbe`、advisor 断言和 `inspect --detail` 字段检查，这些内容与基础 wipe / inspect 回归不是同一关注点。
- 通用 helper 如临时目录、文本写入、字段提取和断言函数已经形成共享测试支撑，但仍内联在单文件里。

### 采取的重构

- 新增 `tests/test_support.h`，收口：
	- `TempDir`
	- `require(...)`
	- `write_text_file(...)`
	- `read_field_value(...)`
	- `matches_any(...)`
	- `contains(...)`
- 新增 `tests/capability_inspection_tests.h/.cpp`，将以下新增能力相关测试迁出主测试文件：
	- `inspect --detail` 能力字段输出断言
	- `DeviceCapabilityInspector` fake probe 映射断言
	- `rotational + unknown bus` 保守结论断言
	- `ErasePathAdvisor` 的 sanitize / crypto-erase / best-effort 路径断言
- `tests/test_secure_wipe.cpp` 保留测试主入口和通用 CLI / wipe 回归测试，通过 `run_capability_inspection_tests()` 组合能力测试集。
- `tests/CMakeLists.txt` 把能力特性测试作为单独翻译单元编入同一测试可执行文件。

### 刻意不改动的部分

- 未引入 Catch2 / GoogleTest 等外部测试框架，因为当前仓库仍以轻量自建 harness 为主，新增框架会扩大范围。
- 未把所有测试继续细分成更多翻译单元，当前仅先收口新增能力相关测试，避免过度拆分。
- 未改变 `securewipe_tests` 单 executable + 单 main 的运行方式，保持现有 CI / CTest 接线稳定。

### 验证

- `cmake --build build`
- `ctest --test-dir build -C Debug --output-on-failure`
- 结果：完整编译通过、全部测试通过。
