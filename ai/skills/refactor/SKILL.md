---
name: refactor
description: Plan and execute high-quality code refactors across system, module, file, function, line, and type levels, with emphasis on modern C++ (C++20+), SOLID, maintainability, and safe incremental validation. Use when the user asks to refactor code, modernize C++, improve design, remove code smells, simplify logic, improve extensibility, or make code easier to understand and maintain.
---

# Refactor

## Instructions

For detailed C++-specific heuristics, see `references/modern-cpp-refactor-rubric.md`.

### Step 1: Frame The Refactor
Start by determining the requested refactor scope and the non-negotiable constraints.

Capture:
- the target granularity: system, module, file, function, line, or type
- the expected outcome: cleaner design, safer ownership model, more modern C++, reduced duplication, clearer control flow, stronger abstraction boundaries, better extensibility, or a combination of these
- whether the user expects behavior-preserving refactoring only, or is open to behavior changes
- the project’s current language standard, build/test commands, architecture constraints, public API boundaries, and documentation requirements

Default to behavior-preserving refactoring unless the user explicitly asks for behavior changes.

### Step 2: Read Before Changing
Build context from the most concrete anchor available: the named file, symbol, command, failing behavior, test, or nearby implementation surface.

Prefer to read:
- the owning abstraction, not just a thin wrapper
- neighboring tests or call sites
- the relevant public/private boundary if the refactor might affect API shape
- project docs or existing refactor logs if the repository uses them

Do not start with broad codebase wandering. Gather only enough context to form one falsifiable local hypothesis about what should change and why.

### Step 3: Identify Refactor Candidates
Evaluate the code at the correct granularity.

Typical candidates:
- system-level: layering violations, unstable public boundaries, infrastructure bleeding into domain logic
- module-level: excessive coupling, mixed responsibilities, missing seams for platform-specific behavior, poor dependency direction
- file-level: large translation units, unrelated classes/functions in one file, repeated helper logic, muddled ownership
- function-level: duplicated control flow, hard-to-follow branching, algorithmic boilerplate, repeated validation, hidden invariants
- line-level: noisy temporaries, misleading naming, avoidable casts, lifetime ambiguity, magic constants, needless mutation
- type-level: incorrect ownership semantics, weak enums, stringly typed APIs, raw pointers with unclear lifetime, overuse of owning strings where views are sufficient, value/view confusion, missing strong types

### Step 4: Apply Modern C++ Judgment
Modernize only where it improves clarity, safety, and maintainability.

Prefer:
- value semantics and RAII
- `std::string_view` for non-owning, read-only string parameters that are consumed immediately and not stored
- `std::span` for non-owning contiguous ranges when the project/toolchain supports it cleanly
- `enum class`, strong types, and explicit modeling of state when booleans become ambiguous
- `std::optional`, `std::variant`, and small value objects when they clarify invariants
- standard algorithms and `std::ranges` when they make intent more obvious
- early validation and narrow interfaces
- clear ownership boundaries for strings, paths, buffers, and handles

Do not modernize mechanically.

Keep these distinctions explicit:
- keep owning `std::string` / `std::vector` / `std::filesystem::path` when storage, mutation, or return-value ownership is required
- keep `const char*` or C-compatible forms when required by platform or C APIs
- avoid turning stateful, side-effect-heavy workflows into clever algorithm chains that hide control flow
- avoid template cleverness, abstraction inflation, or policy explosion unless the existing duplication and change pressure clearly justify it

### Step 5: Apply SOLID Pragmatically
Use SOLID as an engineering filter, not as a slogan.

Check:
- Single Responsibility: is this type or function doing more than one reason-to-change worth of work?
- Open/Closed: are new cases forcing edits to unrelated existing code?
- Liskov: do abstractions preserve caller expectations?
- Interface Segregation: are consumers forced to depend on behavior they do not need?
- Dependency Inversion: do high-level policies depend directly on low-level details that should be abstracted behind seams?

Prefer simple seams over speculative frameworks.

### Step 6: Refactor In Small, Verifiable Slices
Make the smallest refactor that meaningfully tests the current hypothesis.

Good first slices:
- extract a cohesive helper
- rename a misleading type or function precisely
- replace repeated lookup/selection logic with a standard algorithm or ranges expression
- split a file along an existing responsibility boundary
- narrow a parameter from owning type to view type
- replace implicit state with an explicit enum or value object

Avoid large multi-surface edits before the first validation step.

### Step 7: Validate Immediately After Each Substantive Edit
After the first substantive edit, the next step must be focused validation when available.

Preferred order:
1. the narrowest behavior check or failing test
2. a focused unit/integration test for the touched slice
3. a narrow build, lint, or typecheck
4. a full build/test pass when wrapping up or when the touched slice is broad

Before ending the task, always ensure:
- there are no syntax errors
- the project fully compiles
- the relevant or full test suite passes

If the repository also has strict docs validation, run it when your refactor changes public API, CLI behavior, architecture docs, or other documented contracts.

### Step 8: Keep Public Contracts And Docs Honest
If the refactor changes public types, signatures, behavior, terminology, build requirements, or architecture boundaries, update the corresponding docs.

If the repository uses a refactor log or plan file, keep it synchronized with:
- the original smell
- the reason for the change
- the chosen approach
- the deliberate non-changes
- the validation results

### Step 9: Explain Non-Changes
A high-quality refactor includes deliberate restraint.

When evaluating candidates, explicitly note why some areas were left unchanged, for example:
- the code is side-effect-heavy and clearer in imperative form
- a view type would create lifetime risk
- the public API should remain stable for now
- the repository is not yet on the language standard required for a proposed feature
- the added abstraction cost outweighs the current duplication

### Step 10: Finish With A Refactor Summary
Summarize:
- what changed
- why those specific refactors were chosen
- what was intentionally left alone
- what validation was run
- any remaining risks, follow-up refactors, or architectural next steps

## Quality Bar
A good refactor should make future change easier.

Reject refactors that mainly:
- compress code without improving comprehension
- replace explicit logic with fashionable abstractions that obscure behavior
- change ownership or lifetimes without a clear need
- widen scope unnecessarily
- skip validation
- leave docs or public contracts stale
