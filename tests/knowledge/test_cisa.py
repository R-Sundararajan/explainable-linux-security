import json

import pytest

from security_reasoning.knowledge.adapters.cisa import (
    CISA_KEV_URL,
    CISAAcquirer,
    CISANormalizer,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


KEV_RECORD = {
    "cveID": "CVE-2024-3094",
    "vendorProject": "XZ Utils",
    "product": "XZ Utils",
    "vulnerabilityName": (
        "XZ Utils Backdoor"
    ),
    "dateAdded": "2024-04-11",
    "shortDescription": (
        "Malicious code was discovered in "
        "XZ Utils that could allow unauthorized "
        "access."
    ),
    "requiredAction": (
        "Apply mitigations per vendor instructions."
    ),
    "dueDate": "2024-04-18",
    "knownRansomwareCampaignUse": "Unknown",
    "notes": "Test KEV record.",
    "cwes": [],
}


def _acquire():
    source = get_source("cisa")

    return CISAAcquirer().acquire(
        source=source,
        document_id="CVE-2024-3094",
        content=json.dumps(KEV_RECORD),
        canonical_url=CISA_KEV_URL,
        metadata={
            "kev_record": KEV_RECORD,
        },
    )


def test_acquirer_accepts_cisa_source():
    document = _acquire()

    assert document.source_id == "cisa"
    assert document.document_id == (
        "CVE-2024-3094"
    )


def test_acquirer_rejects_wrong_source():
    source = get_source(
        "mitre_attack"
    )

    with pytest.raises(ValueError):
        CISAAcquirer().acquire(
            source=source,
            document_id="test",
            content="{}",
        )


def test_acquirer_rejects_empty_content():
    source = get_source("cisa")

    with pytest.raises(ValueError):
        CISAAcquirer().acquire(
            source=source,
            document_id="test",
            content="",
        )


def test_normalizer_preserves_cve():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert document.metadata["cve_id"] == (
        "CVE-2024-3094"
    )


def test_normalizer_preserves_vendor():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert (
        document.metadata["vendor_project"]
        == "XZ Utils"
    )


def test_normalizer_preserves_product():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert document.metadata["product"] == (
        "XZ Utils"
    )


def test_normalizer_preserves_date_added():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert document.published_at == (
        "2024-04-11"
    )


def test_normalizer_preserves_due_date():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert document.metadata["dueDate"] == (
        "2024-04-18"
    )


def test_normalizer_preserves_ransomware_status():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert (
        document.metadata[
            "knownRansomwareCampaignUse"
        ]
        == "Unknown"
    )


def test_normalizer_creates_description_section():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert (
        document.sections[0].title
        == "Vulnerability Description"
    )


def test_normalizer_creates_product_section():
    document = CISANormalizer().normalize(
        _acquire()
    )

    titles = [
        section.title
        for section in document.sections
    ]

    assert "Affected Product" in titles


def test_normalizer_creates_action_section():
    document = CISANormalizer().normalize(
        _acquire()
    )

    titles = [
        section.title
        for section in document.sections
    ]

    assert "Required Action" in titles


def test_normalizer_sets_json_format():
    document = CISANormalizer().normalize(
        _acquire()
    )

    assert (
        document.document_format.value
        == "json"
    )