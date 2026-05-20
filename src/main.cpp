#include <CLI/CLI.hpp>

#include <iostream>
#include <vector>

#include "internal/cli_application.h"

int main(int argc, char* argv[]) {
    CLI::App bootstrap;
    argv = bootstrap.ensure_utf8(argv);

    std::vector<std::string> args(argv + 1, argv + argc);

    securewipe::app::CommandLineApplication application(std::cout, std::cerr);
    return application.run(args);
}