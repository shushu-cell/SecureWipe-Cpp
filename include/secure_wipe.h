#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securewipe {

enum class Pattern {
    Zeros,
    Random
};

struct WipeOptions {
    int passes = 1;                 // overwrite passes
    Pattern pattern = Pattern::Zeros;
    std::size_t block_size = 1 << 20; // 1 MiB
};

enum class TargetKind {
    Missing,
    RegularFile,
    Directory,
    Symlink,
    Other
};

enum class StorageKind {
    Unknown,
    FixedDisk,
    RotationalDisk,
    SolidState,
    RemovableDisk,
    NetworkShare
};

enum class StrategyRecommendation {
    None,
    Refuse,
    BestEffortFileOverwrite,
    BestEffortDirectoryWipe,
    ReviewBeforeWipe
};

enum class DeviceBusKind {
    Unknown,
    Usb,
    Ata,
    Sata,
    Nvme,
    Scsi,
    Virtual,
    Network
};

enum class CapabilityState {
    Unknown,
    Unsupported,
    Supported,
    Restricted
};

enum class EraseMethod {
    Unknown,
    Refuse,
    BestEffortFileOverwrite,
    BestEffortDirectoryWipe,
    DeviceSanitizeReview,
    CryptoEraseReview,
    ManualReview
};

enum class EvidenceSubject {
    BusKind,
    TrimSupport,
    DeviceSanitizeReview,
    CryptoEraseReview,
    Restriction
};

enum class EvidenceSource {
    PathInspection,
    WindowsStorageQuery,
    LinuxMountMetadata,
    LinuxSysfs,
    HeuristicGuard,
    PlatformFallback
};

enum class EvidenceConfidence {
    Observed,
    Inferred,
    ConservativeFallback
};

enum class PreflightRisk {
    NetworkBacked,
    UsbBridgeSuspected,
    VirtualizedStorage,
    PlatformProbeGap,
    UnderlyingDeviceReviewRecommended
};

enum class ActionCandidateState {
    Preferred,
    Available,
    Blocked,
    Unavailable
};

enum class ActionTargetScope {
    CurrentPath,
    UnderlyingDevice
};

struct [[nodiscard]] CapabilityEvidenceItem {
    EvidenceSubject subject = EvidenceSubject::Restriction;
    EvidenceSource source = EvidenceSource::HeuristicGuard;
    EvidenceConfidence confidence = EvidenceConfidence::ConservativeFallback;
    std::string summary;
};

struct [[nodiscard]] ActionCandidate {
    EraseMethod method = EraseMethod::Unknown;
    ActionCandidateState state = ActionCandidateState::Unavailable;
    ActionTargetScope target_scope = ActionTargetScope::CurrentPath;
    std::string summary;
    std::vector<std::string> blockers;
};

struct [[nodiscard]] DeviceCapabilities {
    DeviceBusKind bus_kind = DeviceBusKind::Unknown;
    CapabilityState trim_support = CapabilityState::Unknown;
    CapabilityState device_sanitize_review = CapabilityState::Unknown;
    CapabilityState crypto_erase_review = CapabilityState::Unknown;
    bool is_removable_media = false;
    bool usb_bridge_suspected = false;
    std::vector<std::string> evidence;
    std::vector<CapabilityEvidenceItem> evidence_items;
};

struct [[nodiscard]] ErasePathAdvice {
    EraseMethod preferred_method = EraseMethod::Unknown;
    std::vector<std::string> reasons;
    std::vector<PreflightRisk> risk_flags;
    std::vector<ActionCandidate> action_candidates;
};

struct [[nodiscard]] WipeResult {
    bool ok = false;
    bool dry_run = false;
    std::uint64_t files_total = 0;
    std::uint64_t files_wiped = 0;
    std::uint64_t files_failed = 0;
    std::string message;  // error or info
};

struct [[nodiscard]] InspectionReport {
    bool ok = false;
    bool dangerous = false;
    TargetKind target_kind = TargetKind::Missing;
    StorageKind storage_kind = StorageKind::Unknown;
    StrategyRecommendation recommendation = StrategyRecommendation::None;
    DeviceCapabilities device_capabilities;
    ErasePathAdvice erase_path_advice;
    std::string canonical_path;
    std::string volume_name;
    std::string message;
    std::vector<std::string> warnings;
};

[[nodiscard]] InspectionReport inspect_target(std::string_view path);
[[nodiscard]] WipeResult wipe_file(std::string_view path, const WipeOptions& opt);
[[nodiscard]] WipeResult wipe_directory(std::string_view dir, const WipeOptions& opt, bool dry_run, bool yes);
} // namespace securewipe