"""
RepoGuard Parsers Package
Provides a unified dispatcher to parse any discovered manifest file.
"""

from typing import Dict, List
from core.models import Dependency
from parsers.python_parser import PythonParser
from parsers.npm_parser import NpmParser
from parsers.maven_parser import MavenParser
from parsers.go_parser import GoParser

ALL_PARSERS = [
    PythonParser(),
    NpmParser(),
    MavenParser(),
    GoParser(),
]


def parse_manifests(manifest_files: Dict[str, bytes]) -> List[Dependency]:
    """
    Takes a dictionary of {manifest_filepath: content_bytes} and extracts
    all declared dependencies across Python, npm, Maven, and Go ecosystems.
    """
    discovered: List[Dependency] = []
    seen = set()

    for filepath, content in manifest_files.items():
        filename = filepath.split("/")[-1]
        for parser in ALL_PARSERS:
            if parser.can_parse(filename):
                try:
                    deps = parser.parse(content, filepath)
                    for d in deps:
                        key = (d.ecosystem, d.name.lower(), d.version, d.manifest_path)
                        if key not in seen:
                            seen.add(key)
                            discovered.append(d)
                except Exception:
                    pass
                break

    return discovered
