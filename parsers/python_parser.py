"""
RepoGuard Python Dependency Parser
Extracts pinned package dependencies from requirements.txt and similar manifests.
"""

import re
from typing import List
from core.models import Dependency
from parsers.base_parser import BaseParser


class PythonParser(BaseParser):
    def can_parse(self, filename: str) -> bool:
        lower = filename.lower()
        return "requirements" in lower and lower.endswith(".txt")

    def parse(self, content: bytes, filepath: str) -> List[Dependency]:
        dependencies: List[Dependency] = []
        text = content.decode("utf-8", errors="replace")

        # Matches package_name[extra]==version or package_name==version or >= / <=
        pattern = re.compile(
            r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|===|~=)\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
        )

        for line in text.splitlines():
            # Strip inline comments
            line = line.split("#", 1)[0].strip()
            # Strip environment markers (e.g. ; python_version > '3.8')
            line = line.split(";", 1)[0].strip()

            if not line or line.startswith("-r") or line.startswith("-i") or line.startswith("--"):
                continue

            match = pattern.match(line)
            if match:
                raw_name = match.group(1)
                version = match.group(2)
                # Normalize PyPI package name per PEP 503
                pkg_name = re.sub(r"[-_.]+", "-", raw_name).lower()
                dependencies.append(
                    Dependency(
                        ecosystem="PyPI",
                        name=pkg_name,
                        version=version,
                        manifest_path=filepath,
                    )
                )

        return dependencies
