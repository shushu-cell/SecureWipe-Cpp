#include "secure_wipe.h"

#include <iostream>
#include <utility>

#include "internal/secure_wipe_engine.h"

namespace securewipe {

namespace {

template <typename Action>
auto invoke_with_default_facade(Action&& action) {
    detail::StreamOperationReporter reporter(std::cout, std::cerr);
    detail::SecureWipeFacade facade(reporter);
    return std::forward<Action>(action)(facade);
}

} // namespace

InspectionReport inspect_target(const std::string& path) {
    return invoke_with_default_facade([&path](const detail::SecureWipeFacade& facade) {
        return facade.inspect(path);
    });
}

WipeResult wipe_file(const std::string& path, const WipeOptions& opt) {
    return invoke_with_default_facade([&path, &opt](const detail::SecureWipeFacade& facade) {
        return facade.wipe_file(path, opt);
    });
}

WipeResult wipe_directory(const std::string& dir, const WipeOptions& opt, bool dry_run, bool yes) {
    return invoke_with_default_facade([&dir, &opt, dry_run, yes](const detail::SecureWipeFacade& facade) {
        return facade.wipe_directory(dir, opt, dry_run, yes);
    });
}

} // namespace securewipe