#include "secure_wipe.h"

#include <iostream>

#include "internal/secure_wipe_engine.h"

namespace securewipe {

InspectionReport inspect_target(const std::string& path) {
    detail::SecureWipeFacade facade(std::cout, std::cerr);
    return facade.inspect(path);
}

WipeResult wipe_file(const std::string& path, const WipeOptions& opt) {
    detail::SecureWipeFacade facade(std::cout, std::cerr);
    return facade.wipe_file(path, opt);
}

WipeResult wipe_directory(const std::string& dir, const WipeOptions& opt, bool dry_run, bool yes) {
    detail::SecureWipeFacade facade(std::cout, std::cerr);
    return facade.wipe_directory(dir, opt, dry_run, yes);
}

} // namespace securewipe