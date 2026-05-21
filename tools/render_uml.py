#!/usr/bin/env python3

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
DIAGRAMS_DIR = ROOT / "docs" / "uml" / "diagrams"
OUTPUT_DIR = ROOT / "docs" / "uml" / "rendered"
PLANTUML_JAR_URL = "https://github.com/plantuml/plantuml/releases/latest/download/plantuml.jar"


def cache_dir() -> Path:
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / "SecureWipe-Cpp" / "tools"
    return Path.home() / ".cache" / "securewipe-cpp"


def ensure_plantuml_jar() -> Path:
    jar_path = cache_dir() / "plantuml.jar"
    if jar_path.exists():
        return jar_path

    jar_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading PlantUML CLI from {PLANTUML_JAR_URL} ...")
    urllib.request.urlretrieve(PLANTUML_JAR_URL, jar_path)
    return jar_path


def render_diagrams(jar_path: Path) -> None:
    diagrams = sorted(DIAGRAMS_DIR.glob("*.puml"))
    if not diagrams:
        raise SystemExit(f"No PlantUML source files found in {DIAGRAMS_DIR}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for svg_path in OUTPUT_DIR.glob("*.svg"):
        svg_path.unlink()

    command = [
        "java",
        "-Djava.awt.headless=true",
        "-jar",
        str(jar_path),
        "-charset",
        "UTF-8",
        "-tsvg",
        "-output",
        str(OUTPUT_DIR),
    ] + [str(path) for path in diagrams]

    subprocess.run(command, check=True)


def main() -> int:
    if shutil.which("java") is None:
        raise SystemExit("Java is required to render PlantUML diagrams.")

    if shutil.which("dot") is None:
        raise SystemExit("Graphviz 'dot' is required to render the current UML diagrams.")

    jar_path = ensure_plantuml_jar()
    render_diagrams(jar_path)
    print(f"Rendered PlantUML diagrams into {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())