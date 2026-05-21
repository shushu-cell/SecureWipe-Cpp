#include "internal/secure_wipe_engine.h"

#include <array>
#include <optional>
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

struct CurrentPathCandidateSpec {
    EraseMethod method;
    std::string_view summary;
};

struct ReviewSelectionRule {
    CapabilityState DeviceCapabilities::*review_state;
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

constexpr std::array kReviewSelectionRules{
    ReviewSelectionRule{
        &DeviceCapabilities::device_sanitize_review,
        EraseMethod::DeviceSanitizeReview,
        "Current target appears to live on storage where device-level sanitization should be reviewed before relying on file-level overwrite.",
    },
    ReviewSelectionRule{
        &DeviceCapabilities::crypto_erase_review,
        EraseMethod::CryptoEraseReview,
        "Current target appears to live on storage where crypto-erase should be reviewed before relying on file-level overwrite.",
    },
};

void add_reason(std::vector<std::string>& reasons, std::string_view reason) {
    reasons.emplace_back(reason);
}

void add_risk_flag(ErasePathAdvice& advice, PreflightRisk risk) {
    if (std::ranges::find(advice.risk_flags, risk) == advice.risk_flags.end()) {
        advice.risk_flags.push_back(risk);
    }
}

void add_candidate_blocker(ActionCandidate& candidate, std::string_view blocker) {
    candidate.blockers.emplace_back(blocker);
}

void add_action_candidate(ErasePathAdvice& advice, ActionCandidate candidate) {
    advice.action_candidates.push_back(std::move(candidate));
}

ActionCandidate make_action_candidate(
    EraseMethod method,
    ActionCandidateState state,
    ActionTargetScope target_scope,
    std::string_view summary) {
    return ActionCandidate{
        .method = method,
        .state = state,
        .target_scope = target_scope,
        .summary = std::string(summary),
    };
}

bool has_platform_probe_gap(const DeviceCapabilities& capabilities) {
    return std::ranges::any_of(capabilities.evidence_items, [](const CapabilityEvidenceItem& item) {
        return item.source == EvidenceSource::PlatformFallback;
    }) || (capabilities.bus_kind == DeviceBusKind::Unknown && capabilities.trim_support == CapabilityState::Unknown);
}

void append_common_preflight_risks(ErasePathAdvice& advice, const InspectionReport& report) {
    if (report.storage_kind == StorageKind::NetworkShare ||
        report.device_capabilities.bus_kind == DeviceBusKind::Network) {
        add_risk_flag(advice, PreflightRisk::NetworkBacked);
    }

    if (report.device_capabilities.usb_bridge_suspected) {
        add_risk_flag(advice, PreflightRisk::UsbBridgeSuspected);
    }

    if (report.device_capabilities.bus_kind == DeviceBusKind::Virtual) {
        add_risk_flag(advice, PreflightRisk::VirtualizedStorage);
    }

    if (has_platform_probe_gap(report.device_capabilities)) {
        add_risk_flag(advice, PreflightRisk::PlatformProbeGap);
    }

    if (report.recommendation == StrategyRecommendation::ReviewBeforeWipe) {
        add_risk_flag(advice, PreflightRisk::UnderlyingDeviceReviewRecommended);
    }
}

ActionCandidateState direct_mapping_state(EraseMethod method) noexcept {
    switch (method) {
    case EraseMethod::Refuse:
        return ActionCandidateState::Blocked;
    case EraseMethod::Unknown:
        return ActionCandidateState::Unavailable;
    case EraseMethod::BestEffortFileOverwrite:
    case EraseMethod::BestEffortDirectoryWipe:
    case EraseMethod::DeviceSanitizeReview:
    case EraseMethod::CryptoEraseReview:
    case EraseMethod::ManualReview:
        return ActionCandidateState::Preferred;
    }

    return ActionCandidateState::Unavailable;
}

std::optional<CurrentPathCandidateSpec> current_path_candidate_spec(const InspectionReport& report) {
    switch (report.target_kind) {
    case TargetKind::RegularFile:
        return CurrentPathCandidateSpec{
            EraseMethod::BestEffortFileOverwrite,
            "Best-effort file overwrite remains available for the current path, but media caveats should be reviewed first.",
        };
    case TargetKind::Directory:
        return CurrentPathCandidateSpec{
            EraseMethod::BestEffortDirectoryWipe,
            "Best-effort directory wipe remains available for the current path, but media caveats should be reviewed first.",
        };
    case TargetKind::Missing:
    case TargetKind::Symlink:
    case TargetKind::Other:
        return std::nullopt;
    }

    return std::nullopt;
}

void append_current_path_candidate(ErasePathAdvice& advice, const InspectionReport& report) {
    const auto spec = current_path_candidate_spec(report);
    if (!spec.has_value()) {
        return;
    }

    add_action_candidate(
        advice,
        make_action_candidate(
            spec->method,
            ActionCandidateState::Available,
            ActionTargetScope::CurrentPath,
            spec->summary));
}

const DirectAdviceMapping* find_direct_advice_mapping(StrategyRecommendation recommendation) {
    const auto entry = std::ranges::find(
        kDirectAdviceMappings,
        recommendation,
        &DirectAdviceMapping::recommendation);
    return entry != kDirectAdviceMappings.end() ? &*entry : nullptr;
}

void append_direct_recommendation_advice(ErasePathAdvice& advice, const InspectionReport& report) {
    const StrategyRecommendation recommendation = report.recommendation;
    if (const DirectAdviceMapping* mapping = find_direct_advice_mapping(recommendation); mapping != nullptr) {
        advice.preferred_method = mapping->preferred_method;
        add_reason(advice.reasons, mapping->primary_reason);

        ActionCandidate candidate = make_action_candidate(
            mapping->preferred_method,
            direct_mapping_state(mapping->preferred_method),
            ActionTargetScope::CurrentPath,
            mapping->primary_reason);
        if (candidate.state == ActionCandidateState::Blocked && !report.message.empty()) {
            add_candidate_blocker(candidate, report.message);
        }
        add_action_candidate(advice, std::move(candidate));
    }
}

ReviewSelection select_review_before_wipe_method(const DeviceCapabilities& capabilities) {
    const auto rule = std::ranges::find_if(kReviewSelectionRules, [&capabilities](const ReviewSelectionRule& candidate) {
        return capabilities.*(candidate.review_state) == CapabilityState::Supported;
    });

    if (rule != kReviewSelectionRules.end()) {
        return {
            rule->preferred_method,
            rule->primary_reason,
        };
    }

    return {
        EraseMethod::ManualReview,
        "Current target requires additional review before destructive action.",
    };
}

void append_review_before_wipe_reasons(ErasePathAdvice& advice, const InspectionReport& report) {
    const DeviceCapabilities& capabilities = report.device_capabilities;
    const ReviewSelection selection = select_review_before_wipe_method(capabilities);
    advice.preferred_method = selection.preferred_method;
    add_reason(advice.reasons, selection.primary_reason);

    ActionCandidate device_candidate = make_action_candidate(
        selection.preferred_method,
        ActionCandidateState::Preferred,
        ActionTargetScope::UnderlyingDevice,
        selection.primary_reason);

    if (capabilities.usb_bridge_suspected) {
        const std::string_view blocker = "USB-attached storage can hide the underlying device capabilities from non-destructive inspection.";
        add_reason(advice.reasons, blocker);
        add_candidate_blocker(device_candidate, blocker);
    }

    if (capabilities.device_sanitize_review == CapabilityState::Restricted) {
        const std::string_view blocker = "Available evidence suggests that direct device-level sanitization may be restricted from this path.";
        add_reason(advice.reasons, blocker);
        add_candidate_blocker(device_candidate, blocker);
    }

    if (selection.preferred_method == EraseMethod::ManualReview && device_candidate.blockers.empty()) {
        add_candidate_blocker(
            device_candidate,
            "Available signals are not sufficient to select a concrete underlying-device review path automatically.");
    }

    add_action_candidate(advice, std::move(device_candidate));
    append_current_path_candidate(advice, report);
}

} // namespace

ErasePathAdvice ErasePathAdvisor::advise(const InspectionReport& report) const {
    ErasePathAdvice advice;

    if (!report.ok) {
        add_reason(advice.reasons, "Inspection did not complete successfully, so no erase path can be advised.");
        return advice;
    }

    append_common_preflight_risks(advice, report);

    if (report.recommendation == StrategyRecommendation::ReviewBeforeWipe) {
        append_review_before_wipe_reasons(advice, report);
        return advice;
    }

    append_direct_recommendation_advice(advice, report);

    return advice;
}

} // namespace securewipe::detail