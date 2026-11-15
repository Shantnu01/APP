"""
RepoGuard npm Dependency Parser
Extracts declared dependencies and devDependencies from package.json manifests.
"""

import json
import re
from typing import List
from core.models import Dependency
from parsers.base_parser import BaseParser


class NpmParser(BaseParser):
    def can_parse(self, filename: str) -> bool:
        lower = filename.lower()
        return lower.endswith("package.json") and "node_modules" not in lower

    def parse(self, content: bytes, filepath: str) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            data = json.loads(content.decode("utf-8", errors="replace"))
        except Exception:
            return []

        if not isinstance(data, dict):
            return []

        # Regex for semver strings (allowing optional leading ^, ~, =, v)
        semver_clean = re.compile(
            r"^[~^=v]?\s*(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
        )

        for section in ("dependencies", "devDependencies"):
            deps_dict = data.get(section)
            if not isinstance(deps_dict, dict):
                continue

            for name, raw_ver in deps_dict.items():
                if not isinstance(name, str) or not isinstance(raw_ver, str):
                    continue

                raw_ver = raw_ver.strip()
                match = semver_clean.match(raw_ver)
                if match:
                    clean_version = match.group(1)
                    dependencies.append(
                        Dependency(
                            ecosystem="npm",
                            name=name.strip(),
                            version=clean_version,
                            manifest_path=filepath,
                        )
                    )

        return dependencies
