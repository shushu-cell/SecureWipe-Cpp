#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"

TEXT_REFERENCE_RE = re.compile(
    r"(?<![\w/])("
    r"README\.md|mkdocs\.yml|CMakeLists\.txt|"
    r"(?:include|src|tests|docs|third_party|tools|refs|\.github)/(?:[A-Za-z0-9._/-]+)?|"
    r"[A-Za-z0-9._-]+\.(?:c|cc|cpp|cxx|h|hh|hpp)"
    r")(?![\w/])"
)
INLINE_LINK_RE = re.compile(r"!?\[[^\]]+\]\([^\)]+\)")
REFERENCE_LINK_RE = re.compile(r"!?\[[^\]]+\]\[[^\]]*\]")
URL_RE = re.compile(r"https?://\S+")
FENCE_RE = re.compile(r"^\s*(```|~~~)\s*([^\s`]*)")
MERMAID_NODE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\[(.+)\]\s*$")
MERMAID_CLICK_RE = re.compile(r'^\s*click\s+([A-Za-z][A-Za-z0-9_]*)\s+"[^"]+"')


@dataclass(frozen=True)
class Violation:
    file_path: Path
    line_number: int
    message: str


def mask_inline_links(line: str) -> str:
    masked = line
    for pattern in (INLINE_LINK_RE, REFERENCE_LINK_RE, URL_RE):
        masked = pattern.sub(lambda match: " " * len(match.group(0)), masked)
    return masked


def scan_text_line(file_path: Path, line_number: int, line: str) -> list[Violation]:
    stripped = line.lstrip()
    if stripped.startswith("[") and "]:" in stripped:
        return []

    masked = mask_inline_links(line)
    violations: list[Violation] = []
    for match in TEXT_REFERENCE_RE.finditer(masked):
        violations.append(
            Violation(
                file_path=file_path,
                line_number=line_number,
                message=f"repository reference '{match.group(1)}' must use a Markdown link",
            )
        )
    return violations


def scan_mermaid_block(file_path: Path, mermaid_lines: list[tuple[int, str]]) -> list[Violation]:
    node_references: dict[str, tuple[int, str]] = {}
    click_targets: set[str] = set()

    for line_number, line in mermaid_lines:
        click_match = MERMAID_CLICK_RE.match(line)
        if click_match:
            click_targets.add(click_match.group(1))
            continue

        node_match = MERMAID_NODE_RE.match(line)
        if not node_match:
            continue

        node_id = node_match.group(1)
        label = node_match.group(2)
        if TEXT_REFERENCE_RE.search(label):
            node_references[node_id] = (line_number, label)

    violations: list[Violation] = []
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