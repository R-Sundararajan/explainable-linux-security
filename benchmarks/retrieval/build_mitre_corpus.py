from __future__ import annotations

from pathlib import Path

from security_reasoning.knowledge.mitre_corpus import (
    build_mitre_corpus,
    download_mitre_bundle,
    write_corpus,
)


OUTPUT_PATH = (
    Path(__file__).parent
    / "datasets"
    / "mitre_attack_v19_1.json"
)


def main() -> None:
    print("Downloading MITRE ATT&CK Enterprise v19.1...")

    bundle = download_mitre_bundle()

    print(
        f"STIX objects: "
        f"{len(bundle.get('objects', []))}"
    )

    chunks = build_mitre_corpus(bundle)

    print(f"Generated chunks: {len(chunks)}")

    write_corpus(
        chunks,
        OUTPUT_PATH,
    )

    print(f"Corpus written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()