from __future__ import annotations

import json
from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.cisa import (
    CISA_KEV_URL,
    CISAAcquirer,
    CISANormalizer,
)
from security_reasoning.knowledge.chunking import (
    chunk_document,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


def fetch_kev() -> dict:
    request = Request(
        CISA_KEV_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": (
                "Mozilla/5.0 "
                "(X11; Linux x86_64) "
                "AppleWebKit/537.36 "
                "explainable-linux-security"
            ),
        },
    )

    with urlopen(
        request,
        timeout=60,
    ) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


def main() -> None:
    source = get_source("cisa")

    print("=" * 72)
    print("CISA KEV smoke test")
    print("=" * 72)

    payload = fetch_kev()

    print(
        f"Source       : {source.name}"
    )

    print(
        f"Endpoint     : {CISA_KEV_URL}"
    )

    if not isinstance(payload, dict):
        raise RuntimeError(
            "CISA KEV response is not a JSON object"
        )

    print(
        f"Top-level keys: "
        f"{list(payload.keys())}"
    )

    vulnerabilities = payload.get(
        "vulnerabilities"
    )

    if not isinstance(
        vulnerabilities,
        list,
    ):
        raise RuntimeError(
            "CISA KEV JSON does not contain "
            "a vulnerabilities list"
        )

    print(
        f"Vulnerabilities: "
        f"{len(vulnerabilities)}"
    )

    if not vulnerabilities:
        raise RuntimeError(
            "CISA KEV catalog is empty"
        )

    record = vulnerabilities[0]

    if not isinstance(record, dict):
        raise RuntimeError(
            "First KEV record is not an object"
        )

    cve_id = record.get(
        "cveID"
    )

    if not cve_id:
        raise RuntimeError(
            "First KEV record has no cveID"
        )

    print(
        f"Sample CVE   : {cve_id}"
    )

    acquired = CISAAcquirer().acquire(
        source=source,
        document_id=cve_id,
        content=json.dumps(record),
        canonical_url=CISA_KEV_URL,
        metadata={
            "kev_record": record,
        },
    )

    document = CISANormalizer().normalize(
        acquired
    )

    chunks = chunk_document(
        document
    )

    print(
        f"Title        : {document.title}"
    )

    print(
        f"Sections     : "
        f"{len(document.sections)}"
    )

    print(
        f"Chunks       : "
        f"{len(chunks)}"
    )

    print(
        f"Date added   : "
        f"{document.published_at}"
    )

    if not chunks:
        raise RuntimeError(
            "CISA KEV record produced "
            "zero chunks"
        )

    print(
        "\nSmoke test completed successfully."
    )


if __name__ == "__main__":
    main()