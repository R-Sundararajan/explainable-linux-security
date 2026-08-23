from __future__ import annotations

from urllib.request import Request, urlopen

from security_reasoning.knowledge.adapters.debian_advisories import (
    DebianAdvisoryAcquirer,
    DebianAdvisoryNormalizer,
)
from security_reasoning.knowledge.chunking import (
    chunk_document,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


DSA_ID = "DSA-6458-1"

RSS_URL = (
    "https://www.debian.org/security/dsa-long"
)

ADVISORY_URL = (
    "https://lists.debian.org/"
    "debian-security-announce/2026/"
)


def fetch_rss() -> str:
    request = Request(
        RSS_URL,
        headers={
            "Accept": (
                "application/rss+xml, "
                "application/xml, text/xml"
            ),
            "User-Agent": (
                "explainable-linux-security/"
                "debian-advisory-smoke-test"
            ),
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
        "debian_security_advisories"
    )

    print("=" * 72)
    print("Debian Security Advisory smoke test")
    print("=" * 72)

    rss = fetch_rss()

    print(
        f"Source       : {source.name}"
    )

    print(
        f"RSS bytes    : "
        f"{len(rss.encode('utf-8'))}"
    )

    if DSA_ID not in rss:
        raise RuntimeError(
            f"{DSA_ID} was not found in "
            "the current Debian DSA RSS feed"
        )

    print(
        f"Found        : {DSA_ID}"
    )

    print(
        "\nRSS discovery succeeded."
    )

    print(
        "\nNext boundary:"
    )

    print(
        "  RSS → individual DSA announcement"
    )

    print(
        "  Individual announcement → "
        "KnowledgeDocument"
    )

    print(
        "\nSmoke test completed."
    )


if __name__ == "__main__":
    main()