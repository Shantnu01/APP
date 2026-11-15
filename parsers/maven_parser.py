"""
RepoGuard Maven POM Parser
Integrates with the Java-based RepoScanner engine for high-fidelity Maven XML parsing,
with an integrated secure Python ElementTree fallback for zero-downtime portability.
"""

import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from core.models import Dependency
from parsers.base_parser import BaseParser


class MavenParser(BaseParser):
    def __init__(self):
        self.app_dir = Path(__file__).resolve().parent.parent
        self.java_source = self.app_dir / "java" / "RepoScanner.java"
        self.java_build_dir = self.app_dir / "build" / "classes"

    def can_parse(self, filename: str) -> bool:
        lower = filename.lower()
        return lower.endswith("pom.xml")

    def _ensure_java_ready(self) -> bool:
        """Verifies javac and java are available and compiles RepoScanner if needed."""
        if not shutil.which("javac") or not shutil.which("java"):
            return False

        class_file = self.java_build_dir / "repoguard" / "scanner" / "RepoScanner.class"
        if class_file.exists() and class_file.stat().st_mtime >= self.java_source.stat().st_mtime:
            return True

        self.java_build_dir.mkdir(parents=True, exist_ok=True)
        try:
            res = subprocess.run(
                ["javac", "-encoding", "UTF-8", "-d", str(self.java_build_dir), str(self.java_source)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _parse_with_java(self, content: bytes, filepath: str) -> List[Dependency]:
        with tempfile.NamedTemporaryFile(suffix="-pom.xml", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            res = subprocess.run(
                ["java", "-cp", str(self.java_build_dir), "repoguard.scanner.RepoScanner", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode != 0:
                return []

            dependencies: List[Dependency] = []
            for line in res.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) == 3:
                    group, artifact, version = parts
                    pkg_coord = f"{group}:{artifact}"
                    dependencies.append(
                        Dependency(
                            ecosystem="Maven",
                            name=pkg_coord,
                            version=version,
                            manifest_path=filepath,
                        )
                    )
            return dependencies
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _parse_with_python_fallback(self, content: bytes, filepath: str) -> List[Dependency]:
        """Pure-Python XML fallback parser with property replacement."""
        dependencies: List[Dependency] = []
        try:
            # Strip namespaces for simplified XPath queries
            xml_text = re.sub(r'\sxmlns="[^"]+"', '', content.decode("utf-8", errors="replace"), count=1)
            root = ET.fromstring(xml_text)

            properties = {}
            props_elem = root.find("properties")
            if props_elem is not None:
                for child in props_elem:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    properties[tag] = (child.text or "").strip()

            deps_elem = root.find("dependencies")
            if deps_elem is not None:
                for dep in deps_elem.findall("dependency"):
                    group_el = dep.find("groupId")
                    art_el = dep.find("artifactId")
                    ver_el = dep.find("version")

                    if group_el is not None and art_el is not None and ver_el is not None:
                        group = (group_el.text or "").strip()
                        art = (art_el.text or "").strip()
                        ver = (ver_el.text or "").strip()

                        if ver.startswith("${") and ver.endswith("}"):
                            key = ver[2:-1].strip()
                            ver = properties.get(key, ver)

                        if group and art and ver and "$" not in ver:
                            dependencies.append(
                                Dependency(
                                    ecosystem="Maven",
                                    name=f"{group}:{art}",
                                    version=ver,
                                    manifest_path=filepath,
                                )
                            )
        except Exception:
            pass
        return dependencies

    def parse(self, content: bytes, filepath: str) -> List[Dependency]:
        if self._ensure_java_ready():
            deps = self._parse_with_java(content, filepath)
            if deps:
                return deps
        return self._parse_with_python_fallback(content, filepath)
