from __future__ import annotations

from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.nist import (
    NISTAcquirer,
    NISTNormalizer,
)
from security_reasoning.knowledge.chunking import (
    chunk_document,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


PUBLICATION_ID = "NIST.SP.800-207"

CSRC_URL = (
    "https://csrc.nist.gov/pubs/"
    "sp/800/207/final"
)

PDF_URL = (
    "https://nvlpubs.nist.gov/nistpubs/"
    "SpecialPublications/NIST.SP.800-207.pdf"
)


def fetch_publication() -> bytes:
    request = Request(
        PDF_URL,
        headers={
            "User-Agent": (
                "explainable-linux-security/"
                "nist-smoke-test"
            )
        },
    )

    with urlopen(
        request,
        timeout=60,
    ) as response:
        return response.read()


def main() -> None:
    source = get_source(
        "nist_cybersecurity"
    )

    print("=" * 72)
    print("NIST publication smoke test")
    print("=" * 72)

    raw_content = fetch_publication()

    print(
        f"Source       : {source.name}"
    )

    print(
        f"Publication  : {PUBLICATION_ID}"
    )

    print(
        f"CSRC URL     : {CSRC_URL}"
    )

    print(
        f"PDF bytes    : {len(raw_content):,}"
    )

    if not raw_content:
        raise RuntimeError(
            "NIST publication returned empty content"
        )

    # At this stage the acquisition boundary is verified.
    # PDF text extraction is a separate concern and should
    # not be silently faked by decoding arbitrary PDF bytes.
    print(
        "\nNIST PDF acquisition succeeded."
    )

    print(
        "PDF-to-text extraction is the next boundary."
    )


if __name__ == "__main__":
    main()