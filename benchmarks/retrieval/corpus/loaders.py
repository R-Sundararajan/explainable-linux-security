from __future__ import annotations

import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from security_reasoning.knowledge.adapters.cisa import (
    CISA_KEV_URL,
    CISAAcquirer,
    CISANormalizer,
)
from security_reasoning.knowledge.adapters.debian_advisories import (
    DebianAdvisoryAcquirer,
    DebianAdvisoryNormalizer,
)
from security_reasoning.knowledge.adapters.debian_tracker import (
    DebianTrackerAcquirer,
    DebianTrackerNormalizer,
)
from security_reasoning.knowledge.adapters.mitre_attack import (
    MitreAttackAcquirer,
    MitreAttackNormalizer,
)
from security_reasoning.knowledge.adapters.nist import (
    NISTAcquirer,
    NISTNormalizer,
)
from security_reasoning.knowledge.adapters.securing_debian import (
    MANUAL_URL,
    SecuringDebianAcquirer,
    SecuringDebianNormalizer,
)
from security_reasoning.knowledge.mitre_corpus import (
    MITRE_ENTERPRISE_URL,
    MITRE_ENTERPRISE_VERSION,
    download_mitre_bundle,
    filter_attack_patterns,
)
from security_reasoning.knowledge.models import (
    KnowledgeDocument,
)
from security_reasoning.knowledge.sources import (
    get_source,
)

from benchmarks.retrieval.corpus.manifest import (
    CorpusDocumentSpec,
)
from benchmarks.retrieval.corpus.populate import (
    DocumentLoader,
)


TRACKER_JSON_URL = (
    "https://security-tracker.debian.org/"
    "tracker/data/json"
)

TRACKER_PAGE_URL = (
    "https://security-tracker.debian.org/"
    "tracker/"
)

DSA_RSS_URL = (
    "https://www.debian.org/security/dsa-long"
)

DSA_BASE_URL = (
    "https://www.debian.org/security/"
)

NIST_PUBLICATION_ID = (
    "NIST.SP.800-207"
)

NIST_CSRC_URL = (
    "https://csrc.nist.gov/pubs/"
    "sp/800/207/final"
)

NIST_PDF_URL = (
    "https://nvlpubs.nist.gov/nistpubs/"
    "SpecialPublications/"
    "NIST.SP.800-207.pdf"
)


class _TextExtractor(HTMLParser):
    """
    Minimal HTML-to-text conversion.

    HTML transport/parsing is handled here because the
    relevant sources expose HTML documents. The resulting
    text is then passed to the source-specific normalizer.
    """

    _BLOCK_TAGS = {
        "address",
        "article",
        "aside",
        "br",
        "div",
        "dl",
        "dt",
        "dd",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tr",
        "ul",
    }

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs,
    ) -> None:
        if (
            tag.lower()
            in self._BLOCK_TAGS
        ):
            self.parts.append("\n")

    def handle_endtag(
        self,
        tag: str,
    ) -> None:
        if (
            tag.lower()
            in self._BLOCK_TAGS
        ):
            self.parts.append("\n")

    def handle_data(
        self,
        data: str,
    ) -> None:
        self.parts.append(
            data
        )

    def text(self) -> str:
        text = "".join(
            self.parts
        )

        lines: list[str] = []

        for line in text.splitlines():
            line = re.sub(
                r"[ \t]+",
                " ",
                line,
            ).strip()

            if line:
                lines.append(
                    line
                )

        return "\n".join(
            lines
        )


def _html_to_text(
    content: str,
) -> str:
    parser = _TextExtractor()

    parser.feed(content)
    parser.close()

    return parser.text()


def _fetch_bytes(
    url: str,
    timeout: int = 60,
) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": "*/*",
            "User-Agent": (
                "explainable-linux-security/"
                "knowledge-corpus-builder"
            ),
        },
    )

    with urlopen(
        request,
        timeout=timeout,
    ) as response:
        payload = response.read()

    if not payload:
        raise RuntimeError(
            f"Empty response from {url}"
        )

    return payload


def _fetch_text(
    url: str,
    timeout: int = 60,
) -> str:
    return _fetch_bytes(
        url,
        timeout,
    ).decode(
        "utf-8"
    )


def _load_mitre(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    MITRE-specific processing.

    STIX bundle
        -> attack-pattern filtering
        -> MITRE acquisition
        -> MITRE normalization
        -> one KnowledgeDocument per attack pattern
    """

    bundle = download_mitre_bundle()

    attack_patterns = (
        filter_attack_patterns(
            bundle
        )
    )

    if not attack_patterns:
        raise RuntimeError(
            "MITRE ATT&CK bundle produced "
            "zero active attack-pattern objects"
        )

    source = get_source(
        "mitre_attack"
    )

    acquirer = MitreAttackAcquirer()
    normalizer = MitreAttackNormalizer()

    documents: list[
        KnowledgeDocument
    ] = []

    for obj in sorted(
        attack_patterns,
        key=lambda value: str(
            value.get("id", "")
        ),
    ):
        document_id = obj.get(
            "id"
        )

        if not document_id:
            continue

        acquired = acquirer.acquire(
            source=source,
            document_id=str(
                document_id
            ),
            content=json.dumps(
                obj,
                ensure_ascii=False,
                sort_keys=True,
            ),
            canonical_url=(
                "https://attack.mitre.org/"
            ),
        )

        document = normalizer.normalize(
            acquired
        )

        document.metadata[
            "mitre_version"
        ] = MITRE_ENTERPRISE_VERSION

        documents.append(
            document
        )

    if not documents:
        raise RuntimeError(
            "MITRE ATT&CK produced no "
            "normalized documents"
        )

    return documents


def _load_debian_tracker(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    Debian Tracker-specific processing.

    Bulk JSON
        -> package/CVE record selection
        -> TEMP-* exclusion
        -> Debian Tracker normalization
        -> one KnowledgeDocument per usable CVE record
    """

    payload = json.loads(
        _fetch_text(
            TRACKER_JSON_URL,
            timeout=60,
        )
    )

    if not isinstance(
        payload,
        dict,
    ):
        raise RuntimeError(
            "Debian Tracker export is not "
            "a JSON object"
        )

    source = get_source(
        "debian_security_tracker"
    )

    acquirer = DebianTrackerAcquirer()
    normalizer = DebianTrackerNormalizer()

    documents: list[
        KnowledgeDocument
    ] = []

    skipped_temporary = 0

    for package_name in sorted(
        payload
    ):
        package_records = payload[
            package_name
        ]

        if not isinstance(
            package_records,
            dict,
        ):
            continue

        for cve_id in sorted(
            package_records
        ):
            cve_id = str(
                cve_id
            )

            if cve_id.startswith(
                "TEMP-"
            ):
                skipped_temporary += 1
                continue

            record = package_records[
                cve_id
            ]

            if not isinstance(
                record,
                dict,
            ):
                continue

            record = dict(
                record
            )

            record.setdefault(
                "package",
                package_name,
            )

            acquired = acquirer.acquire(
                source=source,
                document_id=cve_id,
                content=json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                canonical_url=(
                    f"{TRACKER_PAGE_URL}"
                    f"{cve_id}"
                ),
            )

            document = normalizer.normalize(
                acquired
            )

            documents.append(
                document
            )

    if not documents:
        raise RuntimeError(
            "Debian Security Tracker produced "
            "no normalized documents"
        )

    return documents


def _discover_dsa_links(
    rss: str,
) -> dict[str, str]:
    """
    Discover DSA identifiers and advisory URLs
    from the official Debian feed.
    """

    discovered: dict[
        str,
        str,
    ] = {}

    try:
        root = ElementTree.fromstring(
            rss
        )

        for element in root.iter():
            if (
                element.tag.rsplit(
                    "}",
                    1,
                )[-1]
                != "item"
            ):
                continue

            link = None
            title = None

            for child in element:
                name = child.tag.rsplit(
                    "}",
                    1,
                )[-1]

                if name == "link":
                    if (
                        child.text
                        and child.text.strip()
                    ):
                        link = (
                            child.text.strip()
                        )

                    elif child.attrib.get(
                        "href"
                    ):
                        link = (
                            child.attrib[
                                "href"
                            ].strip()
                        )

                elif (
                    name == "title"
                    and child.text
                ):
                    title = (
                        child.text.strip()
                    )

            candidate = (
                title
                or link
                or ""
            )

            match = re.search(
                r"DSA-\d+-\d+",
                candidate,
            )

            if not match and link:
                match = re.search(
                    r"dsa-(\d+)-(\d+)",
                    link,
                    flags=re.IGNORECASE,
                )

                if match:
                    dsa_id = (
                        f"DSA-"
                        f"{match.group(1)}-"
                        f"{match.group(2)}"
                    )
                else:
                    continue

            elif match:
                dsa_id = (
                    match.group(0)
                )

            else:
                continue

            if link:
                discovered[
                    dsa_id
                ] = link

    except ElementTree.ParseError:
        pass

    for match in re.finditer(
        r"https?://[^\s\"'<>]+/"
        r"dsa-(\d+)-(\d+)",
        rss,
        flags=re.IGNORECASE,
    ):
        dsa_id = (
            f"DSA-"
            f"{match.group(1)}-"
            f"{match.group(2)}"
        )

        discovered.setdefault(
            dsa_id,
            match.group(0),
        )

    return discovered


def _load_debian_advisories(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    Debian Advisory-specific processing.

    RSS discovery
        -> individual advisory retrieval
        -> HTML/text conversion
        -> Debian advisory normalization
        -> one KnowledgeDocument per DSA
    """

    rss = _fetch_text(
        DSA_RSS_URL,
        timeout=30,
    )

    links = _discover_dsa_links(
        rss
    )

    if not links:
        raise RuntimeError(
            "Debian DSA feed produced "
            "no advisory links"
        )

    source = get_source(
        "debian_security_advisories"
    )

    acquirer = DebianAdvisoryAcquirer()
    normalizer = DebianAdvisoryNormalizer()

    documents: list[
        KnowledgeDocument
    ] = []

    for dsa_id, url in sorted(
        links.items()
    ):
        raw = _fetch_text(
            url,
            timeout=30,
        )

        text = _html_to_text(
            raw
        )

        acquired = acquirer.acquire(
            source=source,
            document_id=dsa_id,
            content=text,
            canonical_url=url,
        )

        documents.append(
            normalizer.normalize(
                acquired
            )
        )

    if not documents:
        raise RuntimeError(
            "Debian Security Advisories produced "
            "no normalized documents"
        )

    return documents


def _load_securing_debian(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    Securing Debian-specific processing.

    HTML manual
        -> HTML text extraction
        -> manual normalization
        -> one KnowledgeDocument
    """

    raw = _fetch_text(
        MANUAL_URL,
        timeout=30,
    )

    text = _html_to_text(
        raw
    )

    source = get_source(
        "securing_debian_manual"
    )

    acquired = SecuringDebianAcquirer().acquire(
        source=source,
        document_id=spec.document_id,
        content=text,
        canonical_url=MANUAL_URL,
    )

    document = (
        SecuringDebianNormalizer().normalize(
            acquired
        )
    )

    return [
        document
    ]


def _extract_pdf_text(
    pdf_bytes: bytes,
) -> str:
    """
    Extract NIST PDF text using pdftotext.

    PDF transport and extraction remain specific to the
    NIST source loader.
    """

    executable = shutil.which(
        "pdftotext"
    )

    if executable is None:
        raise RuntimeError(
            "NIST corpus construction requires "
            "the 'pdftotext' executable"
        )

    completed = subprocess.run(
        [
            executable,
            "-layout",
            "-",
            "-",
        ],
        input=pdf_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        stderr = (
            completed.stderr.decode(
                "utf-8",
                errors="replace",
            ).strip()
        )

        raise RuntimeError(
            "Failed to extract NIST PDF text"
            + (
                f": {stderr}"
                if stderr
                else ""
            )
        )

    text = (
        completed.stdout.decode(
            "utf-8",
            errors="replace",
        ).strip()
    )

    if not text:
        raise RuntimeError(
            "NIST PDF produced no "
            "extractable text"
        )

    return text


def _load_nist(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    NIST-specific processing.

    PDF
        -> PDF text extraction
        -> NIST normalization
        -> KnowledgeDocument
    """

    pdf_bytes = _fetch_bytes(
        NIST_PDF_URL,
        timeout=60,
    )

    text = _extract_pdf_text(
        pdf_bytes
    )

    source = get_source(
        "nist_cybersecurity"
    )

    acquired = NISTAcquirer().acquire(
        source=source,
        document_id=NIST_PUBLICATION_ID,
        content=text,
        canonical_url=NIST_CSRC_URL,
        content_type="application/pdf",
        metadata={
            "title": (
                "Zero Trust Architecture"
            ),
            "publication_number": (
                "SP 800-207"
            ),
            "version": "final",
            "published_at": (
                "August 2020"
            ),
            "pdf_url": NIST_PDF_URL,
        },
    )

    document = NISTNormalizer().normalize(
        acquired
    )

    return [
        document
    ]


def _load_cisa(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    CISA KEV-specific processing.

    KEV JSON
        -> vulnerability record selection
        -> CISA normalization
        -> one KnowledgeDocument per KEV record
    """

    payload = json.loads(
        _fetch_text(
            CISA_KEV_URL,
            timeout=60,
        )
    )

    if not isinstance(
        payload,
        dict,
    ):
        raise RuntimeError(
            "CISA KEV response is not "
            "a JSON object"
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

    source = get_source(
        "cisa"
    )

    acquirer = CISAAcquirer()
    normalizer = CISANormalizer()

    documents: list[
        KnowledgeDocument
    ] = []

    for record in vulnerabilities:
        if not isinstance(
            record,
            dict,
        ):
            continue

        cve_id = record.get(
            "cveID"
        )

        if not cve_id:
            continue

        acquired = acquirer.acquire(
            source=source,
            document_id=str(
                cve_id
            ),
            content=json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
            ),
            canonical_url=CISA_KEV_URL,
            metadata={
                "kev_record": record,
            },
        )

        documents.append(
            normalizer.normalize(
                acquired
            )
        )

    if not documents:
        raise RuntimeError(
            "CISA KEV produced no "
            "normalized documents"
        )

    return documents


SOURCE_LOADERS: dict[
    str,
    DocumentLoader,
] = {
    "mitre_attack": _load_mitre,
    "debian_security_tracker": (
        _load_debian_tracker
    ),
    "debian_security_advisories": (
        _load_debian_advisories
    ),
    "securing_debian_manual": (
        _load_securing_debian
    ),
    "nist_cybersecurity": _load_nist,
    "cisa": _load_cisa,
}


def load_documents(
    spec: CorpusDocumentSpec,
) -> list[KnowledgeDocument]:
    """
    Load normalized documents for one authoritative source.
    """

    loader = SOURCE_LOADERS.get(
        spec.source_id
    )

    if loader is None:
        raise ValueError(
            "No loader registered for source: "
            f"{spec.source_id}"
        )

    return loader(spec)