#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
API_DOC_FILE = DOCS_DIR / "engineering" / "api.md"
REPO_GITHUB_URL_RE = re.compile(r"https://github\.com/shushu-cell/SecureWipe-Cpp/(blob|tree)/main/")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

TEXT_REFERENCE_RE = re.compile(
    r"(?<![\w/])("
    r"README\.md|mkdocs\.yml|CMakeLists\.txt|"
    r"(?:include|src|tests|docs|third_party|tools|refs|\.github)/(?:[A-Za-z0-9._/-]+)?|"
    r"[A-Za-z0-9._-]+\.(?:c|cc|cpp|cxx|h|hh|hpp)"
    r")(?![\w/])"
)
INLINE_LINK_RE = re.compile(r"!?\[[^\]]+\]\([^\)]+\)")
INLINE_LINK_TARGET_RE = re.compile(r'!?\[[^\]]+\]\(([^\)\s]+)(?:\s+"[^"]*")?\)')
REFERENCE_LINK_RE = re.compile(r"!?\[[^\]]+\]\[[^\]]*\]")
REFERENCE_DEF_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
URL_RE = re.compile(r"https?://\S+")
FENCE_RE = re.compile(r"^\s*(```|~~~)\s*([^\s`]*)")
MERMAID_NODE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\[(.+)\]\s*$")
MERMAID_CLICK_RE = re.compile(r'^\s*click\s+([A-Za-z][A-Za-z0-9_]*)\s+"([^"]+)"')
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
API_SYMBOLS_REQUIRING_LINKS = {
    "Pattern",
    "WipeOptions",
    "TargetKind",
    "StorageKind",
    "StrategyRecommendation",
    "DeviceBusKind",
    "CapabilityState",
    "EraseMethod",
    "DeviceCapabilities",
    "ErasePathAdvice",
    "InspectionReport",
    "WipeResult",
    "inspect_target(...)",
    "wipe_file(...)",
    "wipe_directory(...)",
    "passes",
    "pattern",
    "block_size",
}


@dataclass(frozen=True)
class Violation:
    file_path: Path
    line_number: int
    message: str


def split_target(target: str) -> tuple[str, str]:
    if "#" not in target:
        return target, ""
    path, fragment = target.split("#", 1)
    return path, fragment


def resolve_local_target(file_path: Path, target: str) -> tuple[Path | None, str]:
    path_part, fragment = split_target(target)
    if not path_part or path_part.startswith("#") or SCHEME_RE.match(path_part):
        return None, fragment

    resolved = (file_path.parent / path_part).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return None, fragment

    return resolved, fragment


def validate_link_target(file_path: Path, line_number: int, target: str) -> list[Violation]:
    violations: list[Violation] = []

    if REPO_GITHUB_URL_RE.search(target):
        violations.append(
            Violation(
                file_path=file_path,
                line_number=line_number,
                message="repository links must use workspace-relative local targets, not GitHub URLs",
            )
        )
        return violations

    resolved, fragment = resolve_local_target(file_path, target)
    if resolved is None:
        return violations

    if not resolved.exists():
        violations.append(
            Violation(
                file_path=file_path,
                line_number=line_number,
                message=f"local link target '{target}' does not exist",
            )
        )
        return violations

    if fragment.startswith("L") and resolved.is_file():
        line_text = fragment[1:]
        if not line_text.isdigit():
            violations.append(
                Violation(
                    file_path=file_path,
                    line_number=line_number,
                    message=f"line fragment '#{fragment}' must use the form '#L<number>'",
                )
            )
            return violations

        target_line = int(line_text)
        line_count = sum(1 for _ in resolved.open("r", encoding="utf-8", errors="ignore"))
        if target_line < 1 or target_line > line_count:
            violations.append(
                Violation(
                    file_path=file_path,
                    line_number=line_number,
                    message=(
                        f"line fragment '#{fragment}' points outside '{resolved.relative_to(ROOT).as_posix()}'"
                    ),
                )
            )

    return violations


def mask_inline_links(line: str) -> str:
    masked = line
    for pattern in (INLINE_LINK_RE, REFERENCE_LINK_RE, URL_RE):
        masked = pattern.sub(lambda match: " " * len(match.group(0)), masked)
    return masked


def scan_text_line(file_path: Path, line_number: int, line: str) -> list[Violation]:
    stripped = line.lstrip()

    violations: list[Violation] = []

    reference_definition = REFERENCE_DEF_RE.match(line)
    if reference_definition:
        violations.extend(validate_link_target(file_path, line_number, reference_definition.group(1)))
        return violations

    masked = mask_inline_links(line)
    for match in TEXT_REFERENCE_RE.finditer(masked):
        violations.append(
            Violation(
                file_path=file_path,
                line_number=line_number,
                message=f"repository reference '{match.group(1)}' must use a Markdown link",
            )
        )

    for match in INLINE_LINK_TARGET_RE.finditer(line):
        violations.extend(validate_link_target(file_path, line_number, match.group(1)))

    if file_path == API_DOC_FILE:
        for match in INLINE_CODE_RE.finditer(masked):
            symbol = match.group(1)
            if symbol not in API_SYMBOLS_REQUIRING_LINKS:
                continue
            violations.append(
                Violation(
                    file_path=file_path,
                    line_number=line_number,
                    message=f"public API symbol '{symbol}' must use a Markdown link",
                )
            )
    return violations


def scan_mermaid_block(file_path: Path, mermaid_lines: list[tuple[int, str]]) -> list[Violation]:
    node_references: dict[str, tuple[int, str]] = {}
    click_targets: set[str] = set()
    violations: list[Violation] = []

    for line_number, line in mermaid_lines:
        click_match = MERMAID_CLICK_RE.match(line)
        if click_match:
            click_targets.add(click_match.group(1))
            violations.extend(validate_link_target(file_path, line_number, click_match.group(2)))
            continue

        node_match = MERMAID_NODE_RE.match(line)
        if not node_match:
            continue

        node_id = node_match.group(1)
        label = node_match.group(2)
        if TEXT_REFERENCE_RE.search(label):
            node_references[node_id] = (line_number, label)

    for node_id, (line_number, label) in sorted(node_references.items()):
        if node_id in click_targets:
            continue
        violations.append(
            Violation(
                file_path=file_path,
                line_number=line_number,
                message=(
                    f"Mermaid node '{node_id}' references '{label}' but is missing a click link"
                ),
            )
        )
    return violations


def scan_markdown_file(file_path: Path) -> list[Violation]:
    violations: list[Violation] = []
    in_fence = False
    fence_delimiter = ""
    fence_info = ""
    mermaid_lines: list[tuple[int, str]] = []

    for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            delimiter = fence_match.group(1)
            info = fence_match.group(2).strip().lower()
            if not in_fence:
                in_fence = True
                fence_delimiter = delimiter
                fence_info = info
                mermaid_lines = []
                continue

            if delimiter == fence_delimiter:
                if fence_info == "mermaid":
                    violations.extend(scan_mermaid_block(file_path, mermaid_lines))
                in_fence = False
                fence_delimiter = ""
                fence_info = ""
                mermaid_lines = []
                continue

        if in_fence:
            if fence_info == "mermaid":
                mermaid_lines.append((line_number, line))
            continue

        violations.extend(scan_text_line(file_path, line_number, line))

    return violations


def main() -> int:
    violations: list[Violation] = []
    for file_path in sorted(DOCS_DIR.rglob("*.md")):
        violations.extend(scan_markdown_file(file_path))

    if not violations:
        print("Docs code-reference link validation passed.")
        return 0

    print("Docs code-reference link validation failed:")
    for violation in violations:
        relative_path = violation.file_path.relative_to(ROOT)
        print(f"- {relative_path}:{violation.line_number}: {violation.message}")
    return 1


if __name__ == "__main__":
    sys.exit(main())