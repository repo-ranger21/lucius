"""Dependency parsers for different package managers."""

import asyncio
import hashlib
import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import toml

from shared.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Dependency:
    """Represents a project dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pip, composer
    is_dev: bool = False
    is_direct: bool = True
    source: str | None = None
    dependencies: list["Dependency"] = field(default_factory=list)

    def to_dict(self) -> dict[str, str | bool | None]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "is_dev": self.is_dev,
            "is_direct": self.is_direct,
            "source": self.source,
        }


class BaseParser(ABC):
    """Abstract base class for dependency parsers."""

    ecosystem: str = ""

    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path

    @abstractmethod
    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse dependencies from the project asynchronously."""
        raise NotImplementedError

    def parse(self, include_dev: bool = False):
        """Parse dependencies from the project (sync or async)."""
        coro = self._parse_async(include_dev=include_dev)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        return coro

    @abstractmethod
    def can_parse(self) -> bool:
        """Check if this parser can handle the project."""
        pass


class NPMParser(BaseParser):
    """Parser for npm/Node.js projects."""

    ecosystem = "npm"

    def can_parse(self) -> bool:
        """Check for package.json or package-lock.json."""
        return (self.project_path / "package.json").exists() or (
            self.project_path / "package-lock.json"
        ).exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse npm dependencies."""
        dependencies = []

        # Try package-lock.json first for accurate versions
        lock_file = self.project_path / "package-lock.json"
        if lock_file.exists():
            dependencies = await self._parse_lock_file(lock_file, include_dev)
        else:
            # Fall back to package.json
            package_file = self.project_path / "package.json"
            if package_file.exists():
                dependencies = await self._parse_package_json(package_file, include_dev)

        logger.info(f"Parsed {len(dependencies)} npm dependencies")
        return dependencies

    async def _parse_lock_file(
        self,
        lock_file: Path,
        include_dev: bool,
    ) -> list[Dependency]:
        """Parse package-lock.json for dependencies."""
        dependencies = []

        content = json.loads(lock_file.read_text())
        packages = content.get("packages", {})

        # Get direct dependencies from package.json
        package_json = self.project_path / "package.json"
        direct_deps = set()
        direct_dev_deps = set()

        if package_json.exists():
            pkg_content = json.loads(package_json.read_text())
            direct_deps = set(pkg_content.get("dependencies", {}).keys())
            direct_dev_deps = set(pkg_content.get("devDependencies", {}).keys())

        for pkg_path, pkg_info in packages.items():
            if not pkg_path or pkg_path == "":
                continue

            # Extract package name from path
            name = pkg_path.replace("node_modules/", "")
            if "/" in name and not name.startswith("@"):
                continue  # Skip nested dependencies for now

            is_dev = pkg_info.get("dev", False)
            if is_dev and not include_dev:
                continue

            version = pkg_info.get("version", "")
            if not version:
                continue

            is_direct = name in direct_deps or name in direct_dev_deps

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=self.ecosystem,
                    is_dev=is_dev,
                    is_direct=is_direct,
                    source=str(lock_file),
                )
            )

        return dependencies

    async def _parse_package_json(
        self,
        package_file: Path,
        include_dev: bool,
    ) -> list[Dependency]:
        """Parse package.json for dependencies."""
        dependencies = []

        content = json.loads(package_file.read_text())

        # Production dependencies
        for name, version in content.get("dependencies", {}).items():
            dependencies.append(
                Dependency(
                    name=name,
                    version=self._normalize_version(version),
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(package_file),
                )
            )

        # Dev dependencies
        if include_dev:
            for name, version in content.get("devDependencies", {}).items():
                dependencies.append(
                    Dependency(
                        name=name,
                        version=self._normalize_version(version),
                        ecosystem=self.ecosystem,
                        is_dev=True,
                        is_direct=True,
                        source=str(package_file),
                    )
                )

        return dependencies

    def _normalize_version(self, version: str) -> str:
        """Normalize npm version specifier."""
        # Remove semver prefixes
        return version.lstrip("^~>=<")


class PipParser(BaseParser):
    """Parser for pip/Python projects."""

    ecosystem = "pypi"

    def can_parse(self) -> bool:
        """Check for requirements.txt, Pipfile, or pyproject.toml."""
        return (
            (self.project_path / "requirements.txt").exists()
            or (self.project_path / "requirements-lock.txt").exists()
            or (self.project_path / "Pipfile.lock").exists()
            or (self.project_path / "pyproject.toml").exists()
            or (self.project_path / "poetry.lock").exists()
        )

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Python dependencies."""
        dependencies = []

        # Try different sources in order of preference
        if (self.project_path / "poetry.lock").exists():
            dependencies = await self._parse_poetry_lock(include_dev)
        elif (self.project_path / "Pipfile.lock").exists():
            dependencies = await self._parse_pipfile_lock(include_dev)
        elif (self.project_path / "requirements-lock.txt").exists():
            dependencies = await self._parse_requirements(
                self.project_path / "requirements-lock.txt",
                is_dev=False,
            )
        elif (self.project_path / "requirements.txt").exists():
            dependencies = await self._parse_requirements(
                self.project_path / "requirements.txt",
                is_dev=False,
            )
            if include_dev and (self.project_path / "requirements-dev.txt").exists():
                dev_deps = await self._parse_requirements(
                    self.project_path / "requirements-dev.txt",
                    is_dev=True,
                )
                dependencies.extend(dev_deps)
        elif (self.project_path / "pyproject.toml").exists():
            dependencies = await self._parse_pyproject(include_dev)

        logger.info(f"Parsed {len(dependencies)} pip dependencies")
        return dependencies

    async def _parse_requirements(
        self,
        req_file: Path,
        is_dev: bool,
    ) -> list[Dependency]:
        """Parse requirements.txt file."""
        dependencies = []

        for line in req_file.read_text().splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package==version format
            name, version = self._parse_requirement_line(line)
            if name and version:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem=self.ecosystem,
                        is_dev=is_dev,
                        is_direct=True,
                        source=str(req_file),
                    )
                )

        return dependencies

    def _parse_requirement_line(self, line: str) -> tuple[str | None, str | None]:
        """Parse a single requirements line."""
        # Remove extras
        if "[" in line:
            line = line[: line.index("[")]

        # Handle different operators
        for op in ["==", ">=", "<=", "~=", "!=", ">", "<"]:
            if op in line:
                parts = line.split(op)
                return parts[0].strip(), parts[1].strip().split(",")[0]

        # No version specified
        return line.strip(), "*"

    async def _parse_poetry_lock(self, include_dev: bool) -> list[Dependency]:
        """Parse poetry.lock file."""
        dependencies = []
        lock_file = self.project_path / "poetry.lock"

        content = toml.loads(lock_file.read_text())

        for package in content.get("package", []):
            is_dev = package.get("category", "main") == "dev"
            if is_dev and not include_dev:
                continue

            dependencies.append(
                Dependency(
                    name=package.get("name", ""),
                    version=package.get("version", ""),
                    ecosystem=self.ecosystem,
                    is_dev=is_dev,
                    is_direct=False,  # Can't determine from lock file alone
                    source=str(lock_file),
                )
            )

        return dependencies

    async def _parse_pipfile_lock(self, include_dev: bool) -> list[Dependency]:
        """Parse Pipfile.lock file."""
        dependencies = []
        lock_file = self.project_path / "Pipfile.lock"

        content = json.loads(lock_file.read_text())

        # Default packages
        for name, info in content.get("default", {}).items():
            version = info.get("version", "").removeprefix("==")
            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(lock_file),
                )
            )

        # Dev packages
        if include_dev:
            for name, info in content.get("develop", {}).items():
                version = info.get("version", "").removeprefix("==")
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem=self.ecosystem,
                        is_dev=True,
                        is_direct=True,
                        source=str(lock_file),
                    )
                )

        return dependencies

    async def _parse_pyproject(self, include_dev: bool) -> list[Dependency]:
        """Parse pyproject.toml file."""
        dependencies = []
        pyproject_file = self.project_path / "pyproject.toml"

        content = toml.loads(pyproject_file.read_text())

        # PEP 621 dependencies
        project = content.get("project", {})
        for dep in project.get("dependencies", []):
            name, version = self._parse_requirement_line(dep)
            if name:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version or "*",
                        ecosystem=self.ecosystem,
                        is_dev=False,
                        is_direct=True,
                        source=str(pyproject_file),
                    )
                )

        # Optional dependencies (often includes dev deps)
        if include_dev:
            optional = project.get("optional-dependencies", {})
            for _group, deps in optional.items():
                for dep in deps:
                    name, version = self._parse_requirement_line(dep)
                    if name:
                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version or "*",
                                ecosystem=self.ecosystem,
                                is_dev=True,
                                is_direct=True,
                                source=str(pyproject_file),
                            )
                        )

        # Poetry dependencies
        poetry = content.get("tool", {}).get("poetry", {})
        for name, info in poetry.get("dependencies", {}).items():
            if name == "python":
                continue
            version = info if isinstance(info, str) else info.get("version", "*")
            dependencies.append(
                Dependency(
                    name=name,
                    version=version.lstrip("^~"),
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(pyproject_file),
                )
            )

        if include_dev:
            for name, info in poetry.get("dev-dependencies", {}).items():
                version = info if isinstance(info, str) else info.get("version", "*")
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version.lstrip("^~"),
                        ecosystem=self.ecosystem,
                        is_dev=True,
                        is_direct=True,
                        source=str(pyproject_file),
                    )
                )

        return dependencies


class ComposerParser(BaseParser):
    """Parser for Composer/PHP projects."""

    ecosystem = "packagist"

    def can_parse(self) -> bool:
        """Check for composer.json or composer.lock."""
        return (self.project_path / "composer.json").exists() or (
            self.project_path / "composer.lock"
        ).exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Composer dependencies."""
        include_dev = True
        dependencies = []

        # Try composer.lock first
        lock_file = self.project_path / "composer.lock"
        if lock_file.exists():
            dependencies = await self._parse_lock_file(lock_file, include_dev)
        else:
            # Fall back to composer.json
            composer_file = self.project_path / "composer.json"
            if composer_file.exists():
                dependencies = await self._parse_composer_json(composer_file, include_dev)

        logger.info(f"Parsed {len(dependencies)} composer dependencies")
        return dependencies

    async def _parse_lock_file(
        self,
        lock_file: Path,
        include_dev: bool,
    ) -> list[Dependency]:
        """Parse composer.lock file."""
        dependencies = []

        content = json.loads(lock_file.read_text())

        # Production packages
        for package in content.get("packages", []):
            dependencies.append(
                Dependency(
                    name=package.get("name", ""),
                    version=package.get("version", "").lstrip("v"),
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(lock_file),
                )
            )

        # Dev packages
        if include_dev:
            for package in content.get("packages-dev", []):
                dependencies.append(
                    Dependency(
                        name=package.get("name", ""),
                        version=package.get("version", "").lstrip("v"),
                        ecosystem=self.ecosystem,
                        is_dev=True,
                        is_direct=True,
                        source=str(lock_file),
                    )
                )

        return dependencies

    async def _parse_composer_json(
        self,
        composer_file: Path,
        include_dev: bool,
    ) -> list[Dependency]:
        """Parse composer.json file."""
        dependencies = []

        content = json.loads(composer_file.read_text())

        # Production dependencies
        for name, version in content.get("require", {}).items():
            if name.startswith("php") or name.startswith("ext-"):
                continue
            dependencies.append(
                Dependency(
                    name=name,
                    version=version.lstrip("^~>=<"),
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(composer_file),
                )
            )

        # Dev dependencies
        if include_dev:
            for name, version in content.get("require-dev", {}).items():
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version.lstrip("^~>=<"),
                        ecosystem=self.ecosystem,
                        is_dev=True,
                        is_direct=True,
                        source=str(composer_file),
                    )
                )

        return dependencies


class IncrementalScanCache:
    """Manages incremental scanning using file hashes."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the cache manager.

        Args:
            cache_dir: Directory for cache files (defaults to .lucius_cache)
        """
        self.cache_dir = cache_dir or Path(".lucius_cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.manifest_file = self.cache_dir / "manifest.json"

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _load_manifest(self) -> dict:
        """Load the cache manifest."""
        if self.manifest_file.exists():
            return json.loads(self.manifest_file.read_text())
        return {}

    def _save_manifest(self, manifest: dict) -> None:
        """Save the cache manifest."""
        self.manifest_file.write_text(json.dumps(manifest, indent=2))

    def has_changed(self, file_path: Path) -> bool:
        """
        Check if a file has changed since the last scan.

        Args:
            file_path: Path to the file to check

        Returns:
            True if file has changed or is new, False if unchanged
        """
        if not file_path.exists():
            return False

        current_hash = self._compute_file_hash(file_path)
        manifest = self._load_manifest()

        file_key = str(file_path.resolve())
        cached_hash = manifest.get(file_key)

        if cached_hash is None or cached_hash != current_hash:
            # Update the manifest
            manifest[file_key] = current_hash
            self._save_manifest(manifest)
            return True

        return False


class RubyGemParser(BaseParser):
    """Parser for Ruby Bundler projects."""

    ecosystem = "ruby"

    def can_parse(self) -> bool:
        """Check for Gemfile or Gemfile.lock."""
        return (self.project_path / "Gemfile.lock").exists() or (
            self.project_path / "Gemfile"
        ).exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Ruby gem dependencies from Gemfile.lock."""
        dependencies = []

        lock_file = self.project_path / "Gemfile.lock"
        if not lock_file.exists():
            logger.warning("Gemfile.lock not found; cannot parse Ruby dependencies")
            return dependencies

        lines = lock_file.read_text().splitlines()
        i = 0
        in_specs = False

        while i < len(lines):
            line = lines[i]

            # Look for the specs: section
            if line.strip().startswith("specs:"):
                in_specs = True
                i += 1
                continue

            # End of specs section (non-indented line that's not empty)
            if in_specs and line and not line.startswith(" "):
                break

            # Parse gem entries (indented with 4 spaces: "    name (version)")
            if in_specs and line.startswith("    ") and not line.startswith("      "):
                line_stripped = line.strip()
                if "(" in line_stripped and ")" in line_stripped:
                    parts = line_stripped.split("(")
                    if len(parts) == 2:
                        name = parts[0].strip()
                        version = parts[1].rstrip(")").strip()
                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem=self.ecosystem,
                                is_dev=False,
                                is_direct=True,
                                source=str(lock_file),
                            )
                        )

            i += 1

        logger.info(f"Parsed {len(dependencies)} Ruby gem dependencies")
        return dependencies


class JavaMavenParser(BaseParser):
    """Parser for Java Maven projects."""

    ecosystem = "maven"

    def can_parse(self) -> bool:
        """Check for pom.xml."""
        return (self.project_path / "pom.xml").exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Maven dependencies from pom.xml."""
        dependencies = []

        pom_file = self.project_path / "pom.xml"
        if not pom_file.exists():
            return dependencies

        try:
            tree = ET.parse(pom_file)
            root = tree.getroot()

            # Extract namespace from root tag
            namespace = ""
            if "}" in root.tag:
                namespace = root.tag.split("}")[0] + "}"

            # Search for dependencies - try with and without namespace
            for dep_elem in root.findall(f".//{namespace}dependency") or root.findall(
                ".//dependency"
            ):
                group_id_elem = dep_elem.find(f"{namespace}groupId") or dep_elem.find("groupId")
                artifact_id_elem = dep_elem.find(f"{namespace}artifactId") or dep_elem.find(
                    "artifactId"
                )
                version_elem = dep_elem.find(f"{namespace}version") or dep_elem.find("version")
                scope_elem = dep_elem.find(f"{namespace}scope") or dep_elem.find("scope")

                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text or ""
                    artifact_id = artifact_id_elem.text or ""
                    version = version_elem.text or "*" if version_elem is not None else "*"
                    scope = scope_elem.text or "compile" if scope_elem is not None else "compile"

                    is_dev = scope in ("test", "provided")
                    if is_dev and not include_dev:
                        continue

                    name = f"{group_id}:{artifact_id}"
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=self.ecosystem,
                            is_dev=is_dev,
                            is_direct=True,
                            source=str(pom_file),
                        )
                    )

        except ET.ParseError as e:
            logger.error(f"Failed to parse pom.xml: {e}")

        logger.info(f"Parsed {len(dependencies)} Maven dependencies")
        return dependencies


class GoModParser(BaseParser):
    """Parser for Go module projects."""

    ecosystem = "go"

    def can_parse(self) -> bool:
        """Check for go.mod."""
        return (self.project_path / "go.mod").exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Go module dependencies from go.mod."""
        dependencies = []

        go_mod_file = self.project_path / "go.mod"
        if not go_mod_file.exists():
            return dependencies

        lines = go_mod_file.read_text().splitlines()
        in_require = False

        for line in lines:
            line_stripped = line.strip()

            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith("//"):
                continue

            # Detect require blocks
            if line_stripped.startswith("require"):
                if line_stripped == "require":
                    in_require = True
                elif line_stripped.startswith("require ("):
                    in_require = True
                else:
                    # Single-line require
                    parts = line_stripped.split()
                    if len(parts) >= 3:
                        name = parts[1]
                        version = parts[2]
                        is_indirect = len(parts) > 3 and "indirect" in parts[3]
                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem=self.ecosystem,
                                is_dev=False,
                                is_direct=not is_indirect,
                                source=str(go_mod_file),
                            )
                        )
                continue

            # Parse require block
            if in_require:
                if line_stripped == ")":
                    in_require = False
                    continue

                parts = line_stripped.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    is_indirect = len(parts) > 2 and "indirect" in parts[2]
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=self.ecosystem,
                            is_dev=False,
                            is_direct=not is_indirect,
                            source=str(go_mod_file),
                        )
                    )

        logger.info(f"Parsed {len(dependencies)} Go module dependencies")
        return dependencies


class RustCargoParser(BaseParser):
    """Parser for Rust Cargo projects."""

    ecosystem = "rust"

    def can_parse(self) -> bool:
        """Check for Cargo.lock or Cargo.toml."""
        return (self.project_path / "Cargo.lock").exists() or (
            self.project_path / "Cargo.toml"
        ).exists()

    async def _parse_async(self, include_dev: bool = False) -> list[Dependency]:
        """Parse Rust dependencies from Cargo.lock."""
        dependencies = []

        cargo_lock = self.project_path / "Cargo.lock"
        if not cargo_lock.exists():
            logger.warning("Cargo.lock not found; cannot parse Rust dependencies")
            return dependencies

        lines = cargo_lock.read_text().splitlines()
        i = 0
        current_package = None

        while i < len(lines):
            line = lines[i]

            # Parse package entries
            if line.startswith("[[package]]"):
                i += 1
                current_package = {"name": None, "version": None}
                continue

            if current_package is not None:
                if line.startswith("name ="):
                    current_package["name"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("version ="):
                    current_package["version"] = line.split("=")[1].strip().strip('"')

                # If we hit an empty line after capturing a package, add it
                if (
                    not line.strip()
                    and current_package.get("name")
                    and current_package.get("version")
                ):
                    dependencies.append(
                        Dependency(
                            name=current_package["name"],
                            version=current_package["version"],
                            ecosystem=self.ecosystem,
                            is_dev=False,
                            is_direct=True,
                            source=str(cargo_lock),
                        )
                    )
                    current_package = None

            i += 1

        # Add the last package if not added yet
        if current_package and current_package.get("name") and current_package.get("version"):
            dependencies.append(
                Dependency(
                    name=current_package["name"],
                    version=current_package["version"],
                    ecosystem=self.ecosystem,
                    is_dev=False,
                    is_direct=True,
                    source=str(cargo_lock),
                )
            )

        logger.info(f"Parsed {len(dependencies)} Rust dependencies")
        return dependencies


class ParserFactory:
    """Factory for creating dependency parsers."""

    _parsers = [
        NPMParser,
        PipParser,
        ComposerParser,
        RubyGemParser,
        JavaMavenParser,
        GoModParser,
        RustCargoParser,
    ]

    @classmethod
    def create(cls, package_manager: str, project_path: Path) -> BaseParser:
        """
        Create a parser for the given package manager.

        Args:
            package_manager: Package manager type or 'auto'
            project_path: Path to the project

        Returns:
            Appropriate parser instance

        Raises:
            ValueError: If no suitable parser found
        """
        if package_manager == "auto":
            return cls._auto_detect(project_path)

        parser_map = {
            "npm": NPMParser,
            "pip": PipParser,
            "composer": ComposerParser,
            "ruby": RubyGemParser,
            "maven": JavaMavenParser,
            "go": GoModParser,
            "rust": RustCargoParser,
        }

        parser_class = parser_map.get(package_manager)
        if not parser_class:
            raise ValueError(f"Unsupported package manager: {package_manager}")

        return parser_class(project_path)

    @classmethod
    def _auto_detect(cls, project_path: Path) -> BaseParser:
        """Auto-detect the package manager from project files."""
        for parser_class in cls._parsers:
            parser = parser_class(project_path)
            if parser.can_parse():
                logger.info(f"Auto-detected parser: {parser_class.__name__}")
                return parser

        raise ValueError(
            f"Could not auto-detect package manager for {project_path}. "
            "Please specify --package-manager explicitly."
        )
