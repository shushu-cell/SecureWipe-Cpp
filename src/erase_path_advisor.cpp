#include "internal/secure_wipe_engine.h"

#include <array>
#include <ranges>

namespace securewipe::detail {

namespace {

struct DirectAdviceMapping {
    StrategyRecommendation recommendation;
    EraseMethod preferred_method;
    std::string_view primary_reason;
};

struct ReviewSelection {
    EraseMethod preferred_method;
    std::string_view primary_reason;
};

constexpr std::array kDirectAdviceMappings{
    DirectAdviceMapping{
        StrategyRecommendation::Refuse,
        EraseMethod::Refuse,
        "Current target should not be processed destructively.",
    },
    DirectAdviceMapping{
        StrategyRecommendation::BestEffortFileOverwrite,
        EraseMethod::BestEffortFileOverwrite,
        "Current target is best handled with file-level overwrite and delete.",
    },
    DirectAdviceMapping{
        StrategyRecommendation::BestEffortDirectoryWipe,
        EraseMethod::BestEffortDirectoryWipe,
        "Current target is best handled with directory traversal and file-level overwrite.",
    },
    DirectAdviceMapping{
        StrategyRecommendation::None,
        EraseMethod::Unknown,
        "No erase path is available because the inspection result did not produce a strategy recommendation.",
    },
};

void add_reason(std::vector<std::string>& reasons, std::string_view reason) {
    reasons.emplace_back(reason);
}

const DirectAdviceMapping* find_direct_advice_mapping(StrategyRecommendation recommendation) {
    const auto entry = std::ranges::find(
        kDirectAdviceMappings,
        recommendation,
        &DirectAdviceMapping::recommendation);
    return entry != kDirectAdviceMappings.end() ? &*entry : nullptr;
}

void append_direct_recommendation_advice(ErasePathAdvice& advice, StrategyRecommendation recommendation) {
    if (const DirectAdviceMapping* mapping = find_direct_advice_mapping(recommendation); mapping != nullptr) {
        advice.preferred_method = mapping->preferred_method;
        add_reason(advice.reasons, mapping->primary_reason);
    }
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

    if (report.recommendation == StrategyRecommendation::ReviewBeforeWipe) {
        append_review_before_wipe_reasons(advice, report.device_capabilities);
        return advice;
    }

    append_direct_recommendation_advice(advice, report.recommendation);

    return advice;
}

} // namespace securewipe::detail