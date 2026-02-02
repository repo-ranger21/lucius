"""SBOM (Software Bill of Materials) generator."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable

from sentinel.parsers import Dependency
from shared.logging import get_logger

logger = get_logger(__name__)


class SBOMGenerator:
    """Factory for SBOM generators."""

    @staticmethod
    def get_generator(format: str) -> "BaseSBOMGenerator":
        format_key = format.lower().strip()
        if format_key == "cyclonedx":
            return CycloneDXGenerator()
        if format_key == "spdx":
            return SPDXGenerator()
        raise ValueError(f"Unsupported SBOM format: {format}")


class BaseSBOMGenerator:
    """Base class for SBOM generators."""

    def save(
        self,
        *,
        dependencies: Iterable[Dependency],
        project_name: str,
        project_version: str,
        output_path: Path,
    ) -> None:
        sbom = self.generate(
            dependencies=dependencies,
            project_name=project_name,
            project_version=project_version,
        )
        output_path.write_text(json.dumps(sbom, indent=2))

    def _create_purl(self, dep: Dependency) -> str:
        ecosystem = dep.ecosystem.lower()
        name = dep.name
        version = dep.version

        purl_type_map = {
            "npm": "npm",
            "pip": "pypi",
            "pypi": "pypi",
            "composer": "composer",
        }

        purl_type = purl_type_map.get(ecosystem, "generic")

        if purl_type == "npm" and name.startswith("@"):
            namespace, pkg_name = name.split("/", 1)
            return f"pkg:{purl_type}/{namespace}/{pkg_name}@{version}"

        if purl_type == "composer" and "/" in name:
            namespace, pkg_name = name.split("/", 1)
            return f"pkg:{purl_type}/{namespace}/{pkg_name}@{version}"

        return f"pkg:{purl_type}/{name}@{version}"

    def generate(
        self,
        *,
        dependencies: Iterable[Dependency],
        project_name: str,
        project_version: str,
    ) -> dict:
        raise NotImplementedError


class CycloneDXGenerator(BaseSBOMGenerator):
    """Generate CycloneDX SBOMs."""

    def generate(
        self,
        *,
        dependencies: Iterable[Dependency],
        project_name: str,
        project_version: str,
    ) -> dict:
        components: list[dict] = []

        for dep in dependencies:
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": self._create_purl(dep),
            }
            if dep.ecosystem:
                component["properties"] = [{"name": "ecosystem", "value": dep.ecosystem}]
            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "Lucius",
                        "name": "Sentinel",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": project_version,
                },
            },
            "components": components,
        }

        return sbom


class SPDXGenerator(BaseSBOMGenerator):
    """Generate SPDX SBOMs."""

    def generate(
        self,
        *,
        dependencies: Iterable[Dependency],
        project_name: str,
        project_version: str,
    ) -> dict:
        packages: list[dict] = []
        relationships: list[dict] = []

        document_namespace = f"https://lucius.io/spdx/{uuid.uuid4()}"
        document_spdx_id = "SPDXRef-DOCUMENT"
        root_package_id = "SPDXRef-RootPackage"

        for i, dep in enumerate(dependencies):
            pkg_id = f"SPDXRef-Package-{i}"
            packages.append(
                {
                    "SPDXID": pkg_id,
                    "name": dep.name,
                    "versionInfo": dep.version,
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": self._create_purl(dep),
                        }
                    ],
                    "filesAnalyzed": False,
                }
            )
            relationships.append(
                {
                    "spdxElementId": root_package_id,
                    "relatedSpdxElement": pkg_id,
                    "relationshipType": "DEPENDS_ON",
                }
            )

        packages.append(
            {
                "SPDXID": root_package_id,
                "name": project_name,
                "versionInfo": project_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        )

        relationships.append(
            {
                "spdxElementId": document_spdx_id,
                "relatedSpdxElement": root_package_id,
                "relationshipType": "DESCRIBES",
            }
        )

        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": document_spdx_id,
            "name": f"SBOM for {project_name}",
            "documentNamespace": document_namespace,
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: Sentinel-1.0.0"],
            },
            "packages": packages,
            "relationships": relationships,
        }

        return sbom
