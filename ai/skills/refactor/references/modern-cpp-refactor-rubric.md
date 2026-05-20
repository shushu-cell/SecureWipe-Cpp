# Modern C++ Refactor Rubric

Use this rubric when the refactor skill is invoked for C++ code.

## Ownership And Lifetime

Prefer questions like:
- Who owns this object?
- How long must this data remain valid?
- Is this parameter consumed, stored, mutated, or only observed?
- Is this API exposing ownership accidentally?

Typical moves:
- `std::string_view` for non-owning read-only text parameters
- `std::span` for non-owning contiguous ranges
- `std::unique_ptr` for exclusive ownership
- references for non-null borrowed dependencies
- value objects for small immutable state bundles

Do not replace owning types with views if the value is stored, returned, mutated, or forwarded to APIs requiring null termination or stable backing storage.

## Type Design

Prefer:
- `enum class` over weak enums
- explicit state objects over boolean flags when states are more than binary in meaning
- narrow helper types when they clarify invariants
- return types that model absence or failure intentionally

Be cautious with:
- broad utility classes
- opaque flag soups
- `std::variant` where simple branching is clearer
- template abstraction used only once

## Function Design

Refactor when functions show:
- mixed validation, orchestration, formatting, and side effects
- repeated lookup or selection logic
- mutation-heavy setup that obscures the real algorithm
- platform branching mixed into higher-level policy
- duplicated error construction or status propagation

Prefer extracting helpers only when the extracted name genuinely clarifies intent.

## Module And Architecture

Prefer module boundaries that:
- keep public API stable and small
- isolate platform details
- keep CLI/UI/tooling layers out of the core domain
- separate detection, policy, execution, and reporting

For cross-platform systems, prefer introducing seams around:
- device or filesystem probing
- platform-native commands or handles
- reporting/output
- policy selection

## Validation Expectations

For refactors, validation is part of the work, not an optional final step.

Always try to verify with:
- focused tests for touched logic
- full compile
- full relevant test suite
- strict docs checks if contracts or docs changed

If validation is impossible, state exactly why and what remains unverified.
