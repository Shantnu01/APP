"""
RepoGuard GitHub Engine
Handles URL validation, repository commit resolution, and in-memory archive extraction
with strict size caps and zip-slip path traversal guards.
"""

from __future__ import annotations
import io
import json
import re
import zipfile
from dataclasses import dataclass
from typing import Dict, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


MAX_ARCHIVE_BYTES = 25 * 1024 * 1024       # 25 MB archive limit
MAX_MANIFEST_BYTES = 512 * 1024            # 512 KB per manifest file
MAX_MANIFESTS_PER_TYPE = 25
USER_AGENT = "RepoGuard-Vulnerability-Scanner/2.0 (Academic; Shantnu, Arya Agrawal, Raiyan Kamal)"


class GitHubError(Exception):
    """Raised when repository fetching or parsing encounters an issue."""


@dataclass
class RepoMetadata:
    owner: str
    repo_name: str
    canonical_url: str
    commit_sha: str


class GitHubEngine:
    @staticmethod
    def parse_repo_url(url: str) -> Tuple[str, str, str]:
        """Validates and parses a public GitHub URL into (owner, repo, canonical_url)."""
        clean_url = url.strip()
        try:
            parsed = urlparse(clean_url)
        except Exception as e:
            raise GitHubError(f"Invalid repository URL structure: {e}")

        if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
            raise GitHubError("RepoGuard only scans public repositories on https://github.com.")

        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) < 2:
            raise GitHubError("Please supply a valid repository path (e.g., https://github.com/owner/repo).")

        owner = parts[0]
        repo = parts[1]
        if repo.endswith(".git"):
            repo = repo[:-4]

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
            raise GitHubError("GitHub owner or repository name contains invalid characters.")

        canonical_url = f"https://github.com/{owner}/{repo}"
        return owner, repo, canonical_url

    def get_commit_sha(self, owner: str, repo: str) -> str:
        """Fetches the latest commit SHA of the default branch via GitHub API."""
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD"
        req = Request(
            api_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("sha", "HEAD")
        except HTTPError as e:
            if e.code == 404:
                raise GitHubError(f"Repository {owner}/{repo} not found (or is private).")
            elif e.code == 403:
                raise GitHubError("GitHub API rate limit reached. Please retry in a few moments.")
            raise GitHubError(f"GitHub returned HTTP status {e.code}.")
        except URLError as e:
            raise GitHubError(f"Network error communicating with GitHub: {e.reason}")
        except Exception as e:
            raise GitHubError(f"Failed to inspect repository: {e}")

    def fetch_manifest_files(self, owner: str, repo: str, commit_sha: str) -> Dict[str, bytes]:
        """
        Downloads the repository archive at the pinned commit and extracts supported
        manifest files completely in-memory without unzipping to disk.
        """
        zip_url = f"https://github.com/{owner}/{repo}/archive/{commit_sha}.zip"
        req = Request(zip_url, headers={"User-Agent": USER_AGENT})

        try:
            with urlopen(req, timeout=45) as resp:
                length = resp.headers.get("Content-Length")
                if length and int(length) > MAX_ARCHIVE_BYTES:
                    raise GitHubError(f"Repository archive exceeds maximum limit of 25MB.")
                archive_data = resp.read(MAX_ARCHIVE_BYTES + 1)
        except HTTPError as e:
            raise GitHubError(f"Failed to download repository zip snapshot: HTTP {e.code}")
        except URLError as e:
            raise GitHubError(f"Connection error downloading repository: {e.reason}")

        if len(archive_data) > MAX_ARCHIVE_BYTES:
            raise GitHubError(f"Repository archive exceeds maximum limit of 25MB.")

        manifests: Dict[str, bytes] = {}
        try:
            with zipfile.ZipFile(io.BytesIO(archive_data)) as zf:
                # Count discovered manifests by type to avoid denial-of-service
                counts = {"python": 0, "npm": 0, "maven": 0, "go": 0}

                for member in zf.infolist():
                    if member.is_dir():
                        continue

                    # Defense against zip-slip directory traversal
                    norm_path = member.filename.replace("\\", "/")
                    if ".." in norm_path:
                        continue

                    # Strip top-level root directory name from zip archive
                    path_parts = norm_path.split("/", 1)
                    rel_path = path_parts[1] if len(path_parts) > 1 else path_parts[0]
                    lower_name = rel_path.lower()

                    if member.file_size > MAX_MANIFEST_BYTES:
                        continue

                    is_manifest = False
                    if (lower_name.endswith("requirements.txt") or
                        lower_name.endswith("requirements-dev.txt") or
                        lower_name.endswith("requirements_dev.txt") or
                        lower_name == "requirements/base.txt" or
                        lower_name == "requirements/prod.txt"):
                        if counts["python"] < MAX_MANIFESTS_PER_TYPE:
                            counts["python"] += 1
                            is_manifest = True

                    elif lower_name.endswith("package.json") and "node_modules" not in lower_name:
                        if counts["npm"] < MAX_MANIFESTS_PER_TYPE:
                            counts["npm"] += 1
                            is_manifest = True

                    elif lower_name.endswith("pom.xml"):
                        if counts["maven"] < MAX_MANIFESTS_PER_TYPE:
                            counts["maven"] += 1
                            is_manifest = True

                    elif lower_name.endswith("go.mod"):
                        if counts["go"] < MAX_MANIFESTS_PER_TYPE:
                            counts["go"] += 1
                            is_manifest = True

                    if is_manifest:
                        manifests[rel_path] = zf.read(member)

        except zipfile.BadZipFile:
            raise GitHubError("Downloaded repository archive was corrupted or invalid.")

        return manifests
