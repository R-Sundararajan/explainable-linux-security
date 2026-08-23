from __future__ import annotations

import json
from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.debian_tracker import (
    DebianTrackerAcquirer,
    DebianTrackerNormalizer,
)
from security_reasoning.knowledge.chunking import chunk_document
from security_reasoning.knowledge.sources import get_source


CVE_ID = "CVE-2024-3094"

TRACKER_JSON_URL = (
    "https://security-tracker.debian.org/"
    "tracker/data/json"
)

TRACKER_PAGE_URL = (
    "https://security-tracker.debian.org/"
    f"tracker/{CVE_ID}"
)


def fetch_tracker_data() -> str:
    """
    Fetch the Debian Security Tracker bulk JSON export.
    """

    request = Request(
        TRACKER_JSON_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": (
                "explainable-linux-security/"
                "debian-tracker-smoke-test"
            ),
        },
    )

    with urlopen(
        request,
        timeout=60,
    ) as response:
        return response.read().decode("utf-8")


def extract_record(
    payload: dict,
    cve_id: str,
) -> tuple[str, dict]:
    """
    Locate a CVE record in the Debian Security Tracker
    bulk JSON export.

    The export is structured as:

        package -> CVE -> record
    """

    for package_name, package_records in payload.items():
        if not isinstance(package_records, dict):
            continue

        record = package_records.get(cve_id)

        if isinstance(record, dict):
            return package_name, record

    raise KeyError(
        f"{cve_id} was not found in Debian "
        "Security Tracker JSON export"
    )


def main() -> None:
    source = get_source(
        "debian_security_tracker"
    )

    print("=" * 72)
    print("Debian Security Tracker smoke test")
    print("=" * 72)

    raw_content = fetch_tracker_data()

    print(f"Source       : {source.name}")
    print(f"Document     : {CVE_ID}")
    print(
        "Raw bytes    : "
        f"{len(raw_content.encode('utf-8'))}"
    )

    payload = json.loads(
        raw_content
    )

    print("\nJSON structure inspection")
    print(f"Top-level type: {type(payload).__name__}")

    if isinstance(payload, dict):
        print(
            "Top-level keys:",
            list(payload.keys())[:20],
        )

    elif isinstance(payload, list):
        print(
            "List length:",
            len(payload),
        )

        if payload:
            print(
                "First record keys:",
                list(payload[0].keys())
                if isinstance(payload[0], dict)
                else type(payload[0]).__name__,
            )

    print()

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Debian Tracker JSON export must "
            "contain a JSON object"
        )

    print(
        f"Tracker records: {len(payload)}"
    )

    package_name,record = extract_record(
        payload,
        CVE_ID,
    )

    print(
        f"Selected record: {CVE_ID}"
    )
    print(
        f"Package name: {package_name}"
    )

    record["package"] = package_name

    acquired_content = json.dumps(
        record,
        sort_keys=True,
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id=CVE_ID,
        content=acquired_content,
        canonical_url=TRACKER_PAGE_URL,
    )

    print("\nAcquisition")
    print(
        f"  source_id   : {acquired.source_id}"
    )
    print(
        f"  document_id : {acquired.document_id}"
    )
    print(
        f"  content_type: {acquired.content_type}"
    )

    document = DebianTrackerNormalizer().normalize(
        acquired
    )

    print("\nNormalized document")
    print(
        f"  title       : {document.title}"
    )
    print(
        f"  format      : "
        f"{document.document_format.value}"
    )
    print(
        f"  source_id   : {document.source_id}"
    )
    print(
        f"  sections    : "
        f"{len(document.sections)}"
    )

    print("\nSections")

    for section in document.sections:
        print(
            f"  [{section.order}] "
            f"{section.title}: "
            f"{section.content[:200]}"
        )

    chunks = chunk_document(
        document
    )

    print("\nChunks")
    print(
        f"  count       : {len(chunks)}"
    )

    for chunk in chunks:
        print(
            f"  {chunk.knowledge_id} "
            f"[{chunk.section}] "
            f"{chunk.content[:160]}"
        )

    print("\nProvenance")
    print(
        f"  canonical_url: "
        f"{document.canonical_url}"
    )
    print(
        f"  metadata     : "
        f"{document.metadata}"
    )

    print(
        "\nSmoke test completed successfully."
    )


if __name__ == "__main__":
    main()