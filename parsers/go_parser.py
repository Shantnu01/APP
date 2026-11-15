"""
RepoGuard Go Modules Dependency Parser
Extracts declared dependencies from go.mod manifests.
"""

import re
from typing import List
from core.models import Dependency
from parsers.base_parser import BaseParser


class GoParser(BaseParser):
    def can_parse(self, filename: str) -> bool:
        lower = filename.lower()
        return lower.endswith("go.mod")

    def parse(self, content: bytes, filepath: str) -> List[Dependency]:
        dependencies: List[Dependency] = []
        text = content.decode("utf-8", errors="replace")

        # In go.mod:
        # require (
        #     github.com/gin-gonic/gin v1.9.1
        # )
        # or require github.com/gin-gonic/gin v1.9.1

        in_require_block = False
        single_req_pattern = re.compile(
            r"^\s*require\s+([A-Za-z0-9_.\-\/]+)\s+v?([A-Za-z0-9_.\-+]+)"
        )
        block_dep_pattern = re.compile(
            r"^\s*([A-Za-z0-9_.\-\/]+)\s+v?([A-Za-z0-9_.\-+]+)"
        )

        for line in text.splitlines():
            line = line.split("//", 1)[0].strip()
            if not line:
                continue

            if line.startswith("require ("):
                in_require_block = True
                continue
            elif in_require_block and line == ")":
                in_require_block = False
                continue

            if in_require_block:
                match = block_dep_pattern.match(line)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2)
                    dependencies.append(
                        Dependency(
                            ecosystem="Go",
                            name=pkg_name,
                            version=version,
                            manifest_path=filepath,
                        )
                    )
            else:
                match = single_req_pattern.match(line)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2)
                    dependencies.append(
                        Dependency(
                            ecosystem="Go",
                            name=pkg_name,
                            version=version,
                            manifest_path=filepath,
                        )
                    )

        return dependencies
