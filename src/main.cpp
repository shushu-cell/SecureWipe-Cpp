#include <vector>
#include <iostream>

#include "internal/cli_application.h"

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    securewipe::app::CommandLineApplication application(std::cout, std::cerr);
    return application.run(args);
}