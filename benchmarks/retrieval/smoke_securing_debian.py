from __future__ import annotations

from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.securing_debian import (
    MANUAL_URL,
    SecuringDebianAcquirer,
    SecuringDebianNormalizer,
)
from security_reasoning.knowledge.chunking import (
    chunk_document,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


def fetch_manual() -> str:
    request = Request(
        MANUAL_URL,
        headers={
            "User-Agent": (
                "explainable-linux-security/"
                "securing-debian-smoke-test"
            )
        },
    )

    with urlopen(
        request,
        timeout=30,
    ) as response:
        return response.read().decode(
            "utf-8"
        )


def main() -> None:
    source = get_source(
        "securing_debian_manual"
    )

    print("=" * 72)
    print("Securing Debian Manual smoke test")
    print("=" * 72)

    raw_content = fetch_manual()

    print(
        f"Source       : {source.name}"
    )

    print(
        f"Canonical URL: {MANUAL_URL}"
    )

    print(
        f"Raw bytes    : "
        f"{len(raw_content.encode('utf-8'))}"
    )

    if not raw_content.strip():
        raise RuntimeError(
            "Debian manual returned empty content"
        )

    acquired = SecuringDebianAcquirer().acquire(
        source=source,
        document_id="securing-debian-manual-3.19",
        content=raw_content,
        canonical_url=MANUAL_URL,
    )

    document = SecuringDebianNormalizer().normalize(
        acquired
    )

    chunks = chunk_document(
        document
    )

    print(
        f"Document     : {document.title}"
    )

    print(
        f"Version      : {document.version}"
    )

    print(
        f"Sections     : {len(document.sections)}"
    )

    print(
        f"Chunks       : {len(chunks)}"
    )

    print(
        f"Metadata     : {document.metadata}"
    )

    if not chunks:
        raise RuntimeError(
            "Manual produced zero retrieval chunks"
        )

    print("\nFirst sections:")

    for section in document.sections[:5]:
        print(
            f"  [{section.order}] "
            f"{section.title}"
        )

    print("\nFirst chunks:")

    for chunk in chunks[:3]:
        print(
            f"  {chunk.knowledge_id} "
            f"| section={chunk.section!r} "
            f"| chars={len(chunk.content)}"
        )

    print(
        "\nSmoke test completed successfully."
    )


if __name__ == "__main__":
    main()