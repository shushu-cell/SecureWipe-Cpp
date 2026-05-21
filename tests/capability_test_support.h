#pragma once

#include <filesystem>

#include "src/internal/secure_wipe_engine.h"
#include "secure_wipe.h"

namespace capability_test_support {

namespace fs = std::filesystem;

class FakeDeviceCapabilityProbe final : public securewipe::detail::DeviceCapabilityProbe {
public:
    securewipe::detail::DeviceProbeSnapshot snapshot;

    securewipe::detail::DeviceProbeSnapshot probe(const fs::path& path, securewipe::StorageKind storage_kind) const override {
        (void)path;
        (void)storage_kind;
        return snapshot;
    }
};

[[nodiscard]] inline securewipe::detail::DeviceInspectionContext make_inspection_context(
    securewipe::StorageKind storage_kind,
    const fs::path& path = "ignored") {
    return {
        .resolved_path = path,
        .storage_kind = storage_kind,
    };
}

[[nodiscard]] inline securewipe::InspectionReport make_report(
    securewipe::StrategyRecommendation recommendation,
    securewipe::StorageKind storage_kind = securewipe::StorageKind::Unknown,
    securewipe::TargetKind target_kind = securewipe::TargetKind::RegularFile) {
    securewipe::InspectionReport report;
    report.ok = true;
    report.target_kind = target_kind;
    report.storage_kind = storage_kind;
    report.recommendation = recommendation;
    return report;
}

[[nodiscard]] inline securewipe::InspectionReport make_review_before_wipe_report(
    securewipe::StorageKind storage_kind,
    securewipe::DeviceBusKind bus_kind = securewipe::DeviceBusKind::Unknown) {
    securewipe::InspectionReport report = make_report(
        securewipe::StrategyRecommendation::ReviewBeforeWipe,
        storage_kind);
    report.device_capabilities.bus_kind = bus_kind;
    return report;
}

} // namespace capability_test_support