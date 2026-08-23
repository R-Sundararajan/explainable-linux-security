from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.mitre_attack import (
    MitreAttackAcquirer,
    MitreAttackNormalizer,
)
from security_reasoning.knowledge.chunking import (
    ChunkingConfig,
    chunk_document,
)
from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.knowledge.sources import get_source


MITRE_ENTERPRISE_VERSION = "19.1"

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/"
    f"enterprise-attack-{MITRE_ENTERPRISE_VERSION}.json"
)


@dataclass(frozen=True)
class MitreCorpusConfig:
    version: str = MITRE_ENTERPRISE_VERSION
    download_url: str = MITRE_ENTERPRISE_URL


def download_mitre_bundle(
    config: MitreCorpusConfig | None = None,
) -> dict:
    """
    Download a pinned MITRE ATT&CK Enterprise STIX bundle.

    Network acquisition is isolated here. Parsing and corpus
    construction happen separately.
    """

    if config is None:
        config = MitreCorpusConfig()

    request = Request(
        config.download_url,
        headers={
            "User-Agent": (
                "explainable-linux-security/"
                "knowledge-corpus-builder"
            )
        },
    )

    with urlopen(request, timeout=60) as response:
        payload = response.read()

    return json.loads(payload)


def filter_attack_patterns(
    bundle: dict,
) -> list[dict]:
    """
    Extract ATT&CK attack-pattern objects from a STIX bundle.

    Revoked and deprecated objects are excluded.
    """

    objects = bundle.get("objects", [])

    return [
        obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]


def build_mitre_corpus(
    bundle: dict,
    chunking_config: ChunkingConfig | None = None,
) -> list[KnowledgeChunk]:
    """
    Convert a MITRE ATT&CK STIX bundle into retrieval-ready
    KnowledgeChunk objects.
    """

    source = get_source("mitre_attack")

    acquirer = MitreAttackAcquirer()
    normalizer = MitreAttackNormalizer()

    chunks: list[KnowledgeChunk] = []

    attack_patterns = filter_attack_patterns(bundle)

    for obj in attack_patterns:
        document_id = obj.get("id")

        if not document_id:
            continue

        canonical_url = (
            "https://attack.mitre.org/"
        )

        acquired = acquirer.acquire(
            source=source,
            document_id=document_id,
            content=json.dumps(
                obj,
                ensure_ascii=False,
                sort_keys=True,
            ),
            canonical_url=canonical_url,
        )

        document = normalizer.normalize(acquired)

        document.metadata["mitre_version"] = (
            MITRE_ENTERPRISE_VERSION
        )

        chunks.extend(
            chunk_document(
                document,
                chunking_config,
            )
        )

    return chunks


def write_corpus(
    chunks: list[KnowledgeChunk],
    output_path: Path,
) -> None:
    """
    Write a deterministic JSON corpus artifact.
    """

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = [
        chunk.model_dump(mode="json")
        for chunk in chunks
    ]

    output_path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )