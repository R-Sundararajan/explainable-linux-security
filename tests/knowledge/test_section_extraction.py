from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
    KnowledgeSection,
)
from security_reasoning.knowledge.section_extraction import (
    ExistingSectionExtractor,
    MarkdownSectionExtractor,
)


def test_existing_section_extractor_preserves_order():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Guidance",
        content="Complete document.",
        document_format=DocumentFormat.TEXT,
        sections=[
            KnowledgeSection(
                section_id="original-002",
                title="Mitigation",
                content="Mitigation guidance.",
                order=1,
            ),
            KnowledgeSection(
                section_id="original-001",
                title="Detection",
                content="Detection guidance.",
                order=0,
            ),
        ],
    )

    extractor = ExistingSectionExtractor()

    sections = extractor.extract(document)

    assert len(sections) == 2
    assert sections[0].title == "Detection"
    assert sections[1].title == "Mitigation"
    assert [section.order for section in sections] == [0, 1]


def test_existing_section_extractor_generates_deterministic_ids():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Guidance",
        content="Complete document.",
        document_format=DocumentFormat.TEXT,
        sections=[
            KnowledgeSection(
                section_id="original-001",
                title="Detection",
                content="Detection guidance.",
                order=0,
            ),
        ],
    )

    extractor = ExistingSectionExtractor()

    first = extractor.extract(document)
    second = extractor.extract(document)

    assert first[0].section_id == second[0].section_id


def test_existing_section_extractor_normalizes_content():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Guidance",
        content="Complete document.",
        document_format=DocumentFormat.TEXT,
        sections=[
            KnowledgeSection(
                section_id="original-001",
                title="  Detection   Guidance ",
                content=" Detection   information\n"
                "from the source. ",
                order=0,
            ),
        ],
    )

    extractor = ExistingSectionExtractor()

    sections = extractor.extract(document)

    assert sections[0].title == "Detection Guidance"
    assert sections[0].content == (
        "Detection information from the source."
    )


def test_existing_section_extractor_returns_empty_without_sections():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Guidance",
        content="Unstructured content.",
        document_format=DocumentFormat.TEXT,
    )

    extractor = ExistingSectionExtractor()

    assert extractor.extract(document) == []


def test_markdown_section_extractor_extracts_sections():
    document = KnowledgeDocument(
        document_id="doc-markdown",
        source_id="cisa",
        title="Security Guidance",
        content=(
            "# Detection\n"
            "Look for unusual process behavior.\n\n"
            "## Mitigation\n"
            "Restrict unnecessary privileges.\n"
        ),
        document_format=DocumentFormat.MARKDOWN,
    )

    extractor = MarkdownSectionExtractor()

    sections = extractor.extract(document)

    assert len(sections) == 2

    assert sections[0].title == "Detection"
    assert sections[0].content == (
        "Look for unusual process behavior."
    )
    assert sections[0].order == 0

    assert sections[1].title == "Mitigation"
    assert sections[1].content == (
        "Restrict unnecessary privileges."
    )
    assert sections[1].order == 1


def test_markdown_section_extractor_generates_deterministic_ids():
    document = KnowledgeDocument(
        document_id="doc-markdown",
        source_id="cisa",
        title="Security Guidance",
        content=(
            "# Detection\n"
            "Look for unusual process behavior."
        ),
        document_format=DocumentFormat.MARKDOWN,
    )

    extractor = MarkdownSectionExtractor()

    first = extractor.extract(document)
    second = extractor.extract(document)

    assert first[0].section_id == second[0].section_id


def test_markdown_section_extractor_ignores_content_before_first_heading():
    document = KnowledgeDocument(
        document_id="doc-markdown",
        source_id="cisa",
        title="Security Guidance",
        content=(
            "Introductory text.\n\n"
            "# Detection\n"
            "Detection guidance."
        ),
        document_format=DocumentFormat.MARKDOWN,
    )

    extractor = MarkdownSectionExtractor()

    sections = extractor.extract(document)

    assert len(sections) == 1
    assert sections[0].title == "Detection"
    assert sections[0].content == "Detection guidance."