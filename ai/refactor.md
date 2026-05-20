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
