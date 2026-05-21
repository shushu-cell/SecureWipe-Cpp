#include "internal/inspection_report_json_formatter.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <ostream>
#include <string_view>
#include <utility>
#include <vector>

namespace securewipe::app::detail {

using namespace std::literals;

namespace {

template <typename Enum>
struct EnumLabel {
    Enum value;
    std::string_view label;
};

template <typename Enum, std::size_t LabelCount>
constexpr std::string_view enum_label_or_unknown(
    Enum value,
    const std::array<EnumLabel<Enum>, LabelCount>& labels) noexcept {
    const auto entry = std::ranges::find(labels, value, &EnumLabel<Enum>::value);

    return entry != labels.end() ? entry->label : "unknown"sv;
}

constexpr std::array<EnumLabel<TargetKind>, 5> kTargetKindLabels{{
    {TargetKind::Missing, "missing"sv},
    {TargetKind::RegularFile, "regular-file"sv},
    {TargetKind::Directory, "directory"sv},
    {TargetKind::Symlink, "symlink"sv},
    {TargetKind::Other, "other"sv},
}};

constexpr std::array<EnumLabel<StorageKind>, 6> kStorageKindLabels{{
    {StorageKind::Unknown, "unknown"sv},
    {StorageKind::FixedDisk, "fixed-disk"sv},
    {StorageKind::RotationalDisk, "rotational-disk"sv},
    {StorageKind::SolidState, "solid-state"sv},
    {StorageKind::RemovableDisk, "removable-disk"sv},
    {StorageKind::NetworkShare, "network-share"sv},
}};

constexpr std::array<EnumLabel<StrategyRecommendation>, 5> kRecommendationLabels{{
    {StrategyRecommendation::None, "none"sv},
    {StrategyRecommendation::Refuse, "refuse"sv},
    {StrategyRecommendation::BestEffortFileOverwrite, "best-effort-file-overwrite"sv},
    {StrategyRecommendation::BestEffortDirectoryWipe, "best-effort-directory-wipe"sv},
    {StrategyRecommendation::ReviewBeforeWipe, "review-before-wipe"sv},
}};

constexpr std::array<EnumLabel<DeviceBusKind>, 8> kDeviceBusLabels{{
    {DeviceBusKind::Unknown, "unknown"sv},
    {DeviceBusKind::Usb, "usb"sv},
    {DeviceBusKind::Ata, "ata"sv},
    {DeviceBusKind::Sata, "sata"sv},
    {DeviceBusKind::Nvme, "nvme"sv},
    {DeviceBusKind::Scsi, "scsi"sv},
    {DeviceBusKind::Virtual, "virtual"sv},
    {DeviceBusKind::Network, "network"sv},
}};

constexpr std::array<EnumLabel<CapabilityState>, 4> kCapabilityStateLabels{{
    {CapabilityState::Unknown, "unknown"sv},
    {CapabilityState::Unsupported, "unsupported"sv},
    {CapabilityState::Supported, "supported"sv},
    {CapabilityState::Restricted, "restricted"sv},
}};

constexpr std::array<EnumLabel<EraseMethod>, 7> kEraseMethodLabels{{
    {EraseMethod::Unknown, "unknown"sv},
    {EraseMethod::Refuse, "refuse"sv},
    {EraseMethod::BestEffortFileOverwrite, "best-effort-file-overwrite"sv},
    {EraseMethod::BestEffortDirectoryWipe, "best-effort-directory-wipe"sv},
    {EraseMethod::DeviceSanitizeReview, "device-sanitize-review"sv},
    {EraseMethod::CryptoEraseReview, "crypto-erase-review"sv},
    {EraseMethod::ManualReview, "manual-review"sv},
}};

constexpr std::array<EnumLabel<EvidenceSubject>, 5> kEvidenceSubjectLabels{{
    {EvidenceSubject::BusKind, "bus-kind"sv},
    {EvidenceSubject::TrimSupport, "trim-support"sv},
    {EvidenceSubject::DeviceSanitizeReview, "device-sanitize-review"sv},
    {EvidenceSubject::CryptoEraseReview, "crypto-erase-review"sv},
    {EvidenceSubject::Restriction, "restriction"sv},
}};

constexpr std::array<EnumLabel<EvidenceSource>, 6> kEvidenceSourceLabels{{
    {EvidenceSource::PathInspection, "path-inspection"sv},
    {EvidenceSource::WindowsStorageQuery, "windows-storage-query"sv},
    {EvidenceSource::LinuxMountMetadata, "linux-mount-metadata"sv},
    {EvidenceSource::LinuxSysfs, "linux-sysfs"sv},
    {EvidenceSource::HeuristicGuard, "heuristic-guard"sv},
    {EvidenceSource::PlatformFallback, "platform-fallback"sv},
}};

constexpr std::array<EnumLabel<EvidenceConfidence>, 3> kEvidenceConfidenceLabels{{
    {EvidenceConfidence::Observed, "observed"sv},
    {EvidenceConfidence::Inferred, "inferred"sv},
    {EvidenceConfidence::ConservativeFallback, "conservative-fallback"sv},
}};

constexpr std::array<EnumLabel<PreflightRisk>, 5> kPreflightRiskLabels{{
    {PreflightRisk::NetworkBacked, "network-backed"sv},
    {PreflightRisk::UsbBridgeSuspected, "usb-bridge-suspected"sv},
    {PreflightRisk::VirtualizedStorage, "virtualized-storage"sv},
    {PreflightRisk::PlatformProbeGap, "platform-probe-gap"sv},
    {PreflightRisk::UnderlyingDeviceReviewRecommended, "underlying-device-review-recommended"sv},
}};

constexpr std::array<EnumLabel<ActionCandidateState>, 4> kActionCandidateStateLabels{{
    {ActionCandidateState::Preferred, "preferred"sv},
    {ActionCandidateState::Available, "available"sv},
    {ActionCandidateState::Blocked, "blocked"sv},
    {ActionCandidateState::Unavailable, "unavailable"sv},
}};

constexpr std::array<EnumLabel<ActionTargetScope>, 2> kActionTargetScopeLabels{{
    {ActionTargetScope::CurrentPath, "current-path"sv},
    {ActionTargetScope::UnderlyingDevice, "underlying-device"sv},
}};

template <typename Container>
nlohmann::ordered_json string_array(const Container& values) {
    nlohmann::ordered_json array = nlohmann::ordered_json::array();
    for (const auto& value : values) {
        array.push_back(value);
    }

    return array;
}

nlohmann::ordered_json evidence_items_json(const std::vector<CapabilityEvidenceItem>& items) {
    nlohmann::ordered_json array = nlohmann::ordered_json::array();
    for (const auto& item : items) {
        nlohmann::ordered_json object = nlohmann::ordered_json::object();
        object["subject"] = to_string(item.subject);
        object["source"] = to_string(item.source);
        object["confidence"] = to_string(item.confidence);
        object["summary"] = item.summary;
        array.push_back(std::move(object));
    }

    return array;
}

nlohmann::ordered_json action_candidates_json(const std::vector<ActionCandidate>& candidates) {
    nlohmann::ordered_json array = nlohmann::ordered_json::array();
    for (const auto& candidate : candidates) {
        nlohmann::ordered_json object = nlohmann::ordered_json::object();
        object["method"] = to_string(candidate.method);
        object["state"] = to_string(candidate.state);
        object["target_scope"] = to_string(candidate.target_scope);
        object["summary"] = candidate.summary;
        object["blockers"] = string_array(candidate.blockers);
        array.push_back(std::move(object));
    }

    return array;
}

} // namespace

std::string_view to_string(TargetKind kind) noexcept {
    return enum_label_or_unknown(kind, kTargetKindLabels);
}

std::string_view to_string(StorageKind kind) noexcept {
    return enum_label_or_unknown(kind, kStorageKindLabels);
}

std::string_view to_string(StrategyRecommendation recommendation) noexcept {
    return enum_label_or_unknown(recommendation, kRecommendationLabels);
}

std::string_view to_string(DeviceBusKind bus_kind) noexcept {
    return enum_label_or_unknown(bus_kind, kDeviceBusLabels);
}

std::string_view to_string(CapabilityState state) noexcept {
    return enum_label_or_unknown(state, kCapabilityStateLabels);
}

std::string_view to_string(EraseMethod method) noexcept {
    return enum_label_or_unknown(method, kEraseMethodLabels);
}

std::string_view to_string(EvidenceSubject subject) noexcept {
    return enum_label_or_unknown(subject, kEvidenceSubjectLabels);
}

std::string_view to_string(EvidenceSource source) noexcept {
    return enum_label_or_unknown(source, kEvidenceSourceLabels);
}

std::string_view to_string(EvidenceConfidence confidence) noexcept {
    return enum_label_or_unknown(confidence, kEvidenceConfidenceLabels);
}

std::string_view to_string(PreflightRisk risk) noexcept {
    return enum_label_or_unknown(risk, kPreflightRiskLabels);
}

std::string_view to_string(ActionCandidateState state) noexcept {
    return enum_label_or_unknown(state, kActionCandidateStateLabels);
}

std::string_view to_string(ActionTargetScope target_scope) noexcept {
    return enum_label_or_unknown(target_scope, kActionTargetScopeLabels);
}

void write_json_inspection_report(std::ostream& output, const InspectionReport& report) {
    nlohmann::ordered_json device_capabilities = nlohmann::ordered_json::object();
    device_capabilities["bus_kind"] = to_string(report.device_capabilities.bus_kind);
    device_capabilities["trim_support"] = to_string(report.device_capabilities.trim_support);
    device_capabilities["device_sanitize_review"] = to_string(report.device_capabilities.device_sanitize_review);
    device_capabilities["crypto_erase_review"] = to_string(report.device_capabilities.crypto_erase_review);
    device_capabilities["is_removable_media"] = report.device_capabilities.is_removable_media;
    device_capabilities["usb_bridge_suspected"] = report.device_capabilities.usb_bridge_suspected;
    device_capabilities["evidence"] = string_array(report.device_capabilities.evidence);
    device_capabilities["evidence_items"] = evidence_items_json(report.device_capabilities.evidence_items);

    nlohmann::ordered_json erase_path_advice = nlohmann::ordered_json::object();
    erase_path_advice["preferred_method"] = to_string(report.erase_path_advice.preferred_method);
    erase_path_advice["reasons"] = string_array(report.erase_path_advice.reasons);
    erase_path_advice["risk_flags"] = nlohmann::ordered_json::array();
    for (const auto risk : report.erase_path_advice.risk_flags) {
        erase_path_advice["risk_flags"].push_back(to_string(risk));
    }
    erase_path_advice["action_candidates"] = action_candidates_json(report.erase_path_advice.action_candidates);

    nlohmann::ordered_json inspection_report = nlohmann::ordered_json::object();
    inspection_report["ok"] = report.ok;
    inspection_report["dangerous"] = report.dangerous;
    inspection_report["target_kind"] = to_string(report.target_kind);
    inspection_report["storage_kind"] = to_string(report.storage_kind);
    inspection_report["recommendation"] = to_string(report.recommendation);
    inspection_report["device_capabilities"] = std::move(device_capabilities);
    inspection_report["erase_path_advice"] = std::move(erase_path_advice);
    inspection_report["canonical_path"] = report.canonical_path;
    inspection_report["volume_name"] = report.volume_name;
    inspection_report["message"] = report.message;
    inspection_report["warnings"] = string_array(report.warnings);

    output << inspection_report.dump() << '\n';
}

} // namespace securewipe::app::detail