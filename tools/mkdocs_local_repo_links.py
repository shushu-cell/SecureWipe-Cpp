from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
SOURCE_REF_DEFAULT = "main"
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
FENCE_RE = re.compile(r"^\s*(```|~~~)\s*([^\s`]*)")
REFERENCE_DEF_RE = re.compile(r"^(\s*\[[^\]]+\]:\s*)(\S+)(.*)$")
INLINE_LINK_RE = re.compile(r"(!?\[[^\]]+\]\()([^\)\s]+)(\))")
MERMAID_CLICK_RE = re.compile(r'^(\s*click\s+[A-Za-z][A-Za-z0-9_]*\s+")([^"]+)(".*)$')


def split_target(target: str) -> tuple[str, str]:
    if "#" not in target:
        return target, ""
    path, fragment = target.split("#", 1)
    return path, f"#{fragment}"


def convert_repo_target(target: str, source_path: Path, repo_url: str, source_ref: str) -> str:
    path_part, fragment = split_target(target)
    if not path_part or path_part.startswith("#") or SCHEME_RE.match(path_part):
        return target

    resolved = (source_path.parent / path_part).resolve()
    try:
        repo_relative = resolved.relative_to(ROOT)
    except ValueError:
        return target

    if resolved.is_relative_to(DOCS_DIR):
        return target

    kind = "tree" if resolved.is_dir() or path_part.endswith("/") else "blob"
    encoded_path = quote(repo_relative.as_posix(), safe="/")
    return f"{repo_url.rstrip('/')}/{kind}/{source_ref}/{encoded_path}{fragment}"


def rewrite_reference_definition(line: str, source_path: Path, repo_url: str, source_ref: str) -> str:
    match = REFERENCE_DEF_RE.match(line)
    if not match:
        return line
    prefix, target, suffix = match.groups()
    converted = convert_repo_target(target, source_path, repo_url, source_ref)
    return f"{prefix}{converted}{suffix}"


def rewrite_inline_links(line: str, source_path: Path, repo_url: str, source_ref: str) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix, target, suffix = match.groups()
        converted = convert_repo_target(target, source_path, repo_url, source_ref)
        return f"{prefix}{converted}{suffix}"

    return INLINE_LINK_RE.sub(replace, line)


def rewrite_mermaid_click(line: str, source_path: Path, repo_url: str, source_ref: str) -> str:
    match = MERMAID_CLICK_RE.match(line)
    if not match:
        return line
    prefix, target, suffix = match.groups()
    converted = convert_repo_target(target, source_path, repo_url, source_ref)
    return f"{prefix}{converted}{suffix}"


def on_page_markdown(markdown: str, *, page, config, **kwargs) -> str:
    repo_url = config.get("repo_url")
    if not repo_url:
        return markdown

    source_ref = config.get("extra", {}).get("repo_source_ref", SOURCE_REF_DEFAULT)
    source_path = Path(page.file.abs_src_path)

    output_lines: list[str] = []
    in_fence = False
    fence_delimiter = ""
    fence_info = ""

    for line in markdown.splitlines(keepends=True):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            delimiter = fence_match.group(1)
            info = fence_match.group(2).strip().lower()
            if not in_fence:
                in_fence = True
                fence_delimiter = delimiter
                fence_info = info
            elif delimiter == fence_delimiter:
                in_fence = False
                fence_delimiter = ""
                fence_info = ""
            output_lines.append(line)
            continue

        if not in_fence:
            line = rewrite_reference_definition(line, source_path, repo_url, source_ref)
            line = rewrite_inline_links(line, source_path, repo_url, source_ref)
        elif fence_info == "mermaid":
            line = rewrite_mermaid_click(line, source_path, repo_url, source_ref)

        output_lines.append(line)

    return "".join(output_lines)