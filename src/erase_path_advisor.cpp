#include "internal/secure_wipe_engine.h"

namespace securewipe::detail {

namespace {

struct ReviewSelection {
    EraseMethod preferred_method;
    std::string_view primary_reason;
};

void add_reason(std::vector<std::string>& reasons, std::string_view reason) {
    reasons.emplace_back(reason);
}

ReviewSelection select_review_before_wipe_method(const DeviceCapabilities& capabilities) {
    if (capabilities.device_sanitize_review == CapabilityState::Supported) {
        return {
            EraseMethod::DeviceSanitizeReview,
            "Current target appears to live on storage where device-level sanitization should be reviewed before relying on file-level overwrite.",
        };
    }

    if (capabilities.crypto_erase_review == CapabilityState::Supported) {
        return {
            EraseMethod::CryptoEraseReview,
            "Current target appears to live on storage where crypto-erase should be reviewed before relying on file-level overwrite.",
        };
    }

    return {
        EraseMethod::ManualReview,
        "Current target requires additional review before destructive action.",
    };
}

void append_review_before_wipe_reasons(ErasePathAdvice& advice, const DeviceCapabilities& capabilities) {
    const ReviewSelection selection = select_review_before_wipe_method(capabilities);
    advice.preferred_method = selection.preferred_method;
    add_reason(advice.reasons, selection.primary_reason);

    if (capabilities.usb_bridge_suspected) {
        add_reason(advice.reasons, "USB-attached storage can hide the underlying device capabilities from non-destructive inspection.");
    }

    if (capabilities.device_sanitize_review == CapabilityState::Restricted) {
        add_reason(advice.reasons, "Available evidence suggests that direct device-level sanitization may be restricted from this path.");
    }
}

} // namespace

ErasePathAdvice ErasePathAdvisor::advise(const InspectionReport& report) const {
    ErasePathAdvice advice;

    if (!report.ok) {
        add_reason(advice.reasons, "Inspection did not complete successfully, so no erase path can be advised.");
        return advice;
    }

    switch (report.recommendation) {
    case StrategyRecommendation::Refuse:
        advice.preferred_method = EraseMethod::Refuse;
        add_reason(advice.reasons, "Current target should not be processed destructively.");
        break;
    case StrategyRecommendation::BestEffortFileOverwrite:
        advice.preferred_method = EraseMethod::BestEffortFileOverwrite;
        add_reason(advice.reasons, "Current target is best handled with file-level overwrite and delete.");
        break;
    case StrategyRecommendation::BestEffortDirectoryWipe:
        advice.preferred_method = EraseMethod::BestEffortDirectoryWipe;
        add_reason(advice.reasons, "Current target is best handled with directory traversal and file-level overwrite.");
        break;
    case StrategyRecommendation::ReviewBeforeWipe:
        append_review_before_wipe_reasons(advice, report.device_capabilities);
        break;
    case StrategyRecommendation::None:
        advice.preferred_method = EraseMethod::Unknown;
        add_reason(advice.reasons, "No erase path is available because the inspection result did not produce a strategy recommendation.");
        break;
    }

    return advice;
}

} // namespace securewipe::detail