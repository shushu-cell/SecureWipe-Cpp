#pragma once

#include <iosfwd>
#include <string_view>

#include "secure_wipe.h"

namespace securewipe::app::detail {

[[nodiscard]] std::string_view to_string(TargetKind kind) noexcept;
[[nodiscard]] std::string_view to_string(StorageKind kind) noexcept;
[[nodiscard]] std::string_view to_string(StrategyRecommendation recommendation) noexcept;
[[nodiscard]] std::string_view to_string(DeviceBusKind bus_kind) noexcept;
[[nodiscard]] std::string_view to_string(CapabilityState state) noexcept;
[[nodiscard]] std::string_view to_string(EraseMethod method) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceSubject subject) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceSource source) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceConfidence confidence) noexcept;
[[nodiscard]] std::string_view to_string(PreflightRisk risk) noexcept;
[[nodiscard]] std::string_view to_string(ActionCandidateState state) noexcept;
[[nodiscard]] std::string_view to_string(ActionTargetScope target_scope) noexcept;

void write_json_inspection_report(std::ostream& output, const InspectionReport& report);

} // namespace securewipe::app::detail