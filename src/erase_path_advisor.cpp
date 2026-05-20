#include "internal/secure_wipe_engine.h"

namespace securewipe::detail {

namespace {

void add_reason(std::vector<std::string>& reasons, std::string_view reason) {
    reasons.emplace_back(reason);
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
        if (report.device_capabilities.device_sanitize_review == CapabilityState::Supported) {
            advice.preferred_method = EraseMethod::DeviceSanitizeReview;
            add_reason(
                advice.reasons,
                "Current target appears to live on storage where device-level sanitization should be reviewed before relying on file-level overwrite.");
        } else if (report.device_capabilities.crypto_erase_review == CapabilityState::Supported) {
            advice.preferred_method = EraseMethod::CryptoEraseReview;
            add_reason(
                advice.reasons,
                "Current target appears to live on storage where crypto-erase should be reviewed before relying on file-level overwrite.");
        } else {
            advice.preferred_method = EraseMethod::ManualReview;
            add_reason(advice.reasons, "Current target requires additional review before destructive action.");
        }

        if (report.device_capabilities.usb_bridge_suspected) {
            add_reason(advice.reasons, "USB-attached storage can hide the underlying device capabilities from non-destructive inspection.");
        }

        if (report.device_capabilities.device_sanitize_review == CapabilityState::Restricted) {
            add_reason(advice.reasons, "Available evidence suggests that direct device-level sanitization may be restricted from this path.");
        }
        break;
    case StrategyRecommendation::None:
        advice.preferred_method = EraseMethod::Unknown;
        add_reason(advice.reasons, "No erase path is available because the inspection result did not produce a strategy recommendation.");
        break;
    }

    return advice;
}

} // namespace securewipe::detail