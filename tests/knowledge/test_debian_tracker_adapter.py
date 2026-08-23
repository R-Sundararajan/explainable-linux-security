import json

import pytest

from security_reasoning.knowledge.adapters.debian_tracker import (
    DebianTrackerAcquirer,
    DebianTrackerNormalizer,
)
from security_reasoning.knowledge.sources import get_source


def _tracker_payload() -> str:
    return json.dumps(
        {
            "cve": "CVE-2026-12345",
            "description": (
                "A security vulnerability in an example "
                "Debian package may allow unauthorized "
                "access."
            ),
            "package": "example-package",
            "bug": "123456",
            "urgency": "high",
            "status": "open",
            "scope": "remote",
            "releases": {
                "bookworm": {
                    "status": "vulnerable",
                    "urgency": "high",
                },
                "trixie": {
                    "status": "fixed",
                    "urgency": "high",
                },
            },
            "fixed_versions": {
                "bookworm": "1.2.4-1",
                "trixie": "2.0.1-2",
            },
        }
    )


def _record() -> dict:
    return {
        "cve": "CVE-2026-12345",
        "description": (
            "A security vulnerability in an example "
            "Debian package may allow unauthorized "
            "access."
        ),
        "package": "example-package",
        "bug": "123456",
        "urgency": "high",
        "status": "open",
        "scope": "remote",
        "releases": {
            "bookworm": {
                "status": "vulnerable",
            },
            "trixie": {
                "status": "fixed",
            },
        },
    }


def test_debian_tracker_acquirer_creates_document():
    source = get_source(
        "debian_security_tracker"
    )

    document = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content=_tracker_payload(),
        canonical_url=(
            "https://security-tracker.debian.org/"
            "tracker/CVE-2026-12345"
        ),
    )

    assert document.source_id == (
        "debian_security_tracker"
    )

    assert document.document_id == (
        "CVE-2026-12345"
    )

    assert document.content_type == (
        "application/json"
    )


def test_debian_tracker_acquirer_rejects_wrong_source():
    source = get_source(
        "mitre_attack"
    )

    acquirer = DebianTrackerAcquirer()

    with pytest.raises(ValueError):
        acquirer.acquire(
            source=source,
            document_id="CVE-2026-12345",
            content=_tracker_payload(),
            canonical_url="https://example.com/",
        )


def test_debian_tracker_normalizer_extracts_core_fields():
    source = get_source(
        "debian_security_tracker"
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content=_tracker_payload(),
        canonical_url=(
            "https://security-tracker.debian.org/"
            "tracker/CVE-2026-12345"
        ),
    )

    document = DebianTrackerNormalizer().normalize(
        acquired
    )

    assert document.document_id == (
        "debian_security_tracker:"
        "CVE-2026-12345:"
        "example-package"
    )

    assert document.entity_id == (
        "CVE-2026-12345"
    )

    assert document.source_id == (
        "debian_security_tracker"
    )

    assert document.title == (
        "Debian Security Issue "
        "CVE-2026-12345"
    )

    assert document.document_format.value == "json"


def test_debian_tracker_normalizer_extracts_sections():
    source = get_source(
        "debian_security_tracker"
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content=_tracker_payload(),
        canonical_url="https://example.com/",
    )

    document = DebianTrackerNormalizer().normalize(
        acquired
    )

    titles = {
        section.title
        for section in document.sections
    }

    assert "Description" in titles
    assert "Package" in titles
    assert "Bug" in titles
    assert "Status" in titles
    assert "Urgency" in titles
    assert "Scope" in titles
    assert "Affected Releases" in titles
    assert "Fixed Versions" in titles

    assert "Description" in document.content
    assert "Affected Releases" in document.content
    assert "Fixed Versions" in document.content


def test_debian_tracker_normalizer_preserves_metadata():
    source = get_source(
        "debian_security_tracker"
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content=_tracker_payload(),
        canonical_url="https://example.com/",
    )

    document = DebianTrackerNormalizer().normalize(
        acquired
    )

    assert document.metadata["cve"] == (
        "CVE-2026-12345"
    )

    assert document.metadata["package"] == (
        "example-package"
    )

    assert document.metadata["bug"] == (
        "123456"
    )

    assert document.metadata["urgency"] == "high"

    assert document.metadata["status"] == "open"

    assert document.metadata["scope"] == "remote"


def test_debian_tracker_normalizer_normalize_record():
    document = DebianTrackerNormalizer().normalize_record(
        payload=_record(),
        document_id="CVE-2026-12345",
        canonical_url="https://example.com/",
    )

    assert document.source_id == (
        "debian_security_tracker"
    )

    assert document.metadata["cve"] == (
        "CVE-2026-12345"
    )

    assert document.metadata["package"] == (
        "example-package"
    )


def test_debian_tracker_normalizer_rejects_invalid_json():
    source = get_source(
        "debian_security_tracker"
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content='{"invalid": ',
        canonical_url="https://example.com/",
    )

    normalizer = DebianTrackerNormalizer()

    with pytest.raises(ValueError):
        normalizer.normalize(
            acquired
        )


def test_debian_tracker_normalizer_accepts_missing_description_with_security_state():
    source = get_source(
        "debian_security_tracker"
    )

    payload = json.dumps(
        {
            "cve": "CVE-2026-16566",
            "package": "ansible",
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "7.7.0",
                },
                "forky": {
                    "status": "open",
                    "urgency": "not yet assigned",
                },
                "sid": {
                    "status": "open",
                    "urgency": "not yet assigned",
                },
            },
        }
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-16566",
        content=payload,
        canonical_url="https://example.com/",
    )

    document = DebianTrackerNormalizer().normalize(
        acquired
    )

    titles = {
        section.title
        for section in document.sections
    }

    assert "Description" not in titles
    assert "Package" in titles
    assert "Affected Releases" in titles

    assert (
        document.metadata["has_description"]
        is False
    )

    assert (
        document.metadata["has_security_state"]
        is True
    )

    assert "forky" in document.content
    assert "sid" in document.content
    assert "open" in document.content


def test_debian_tracker_rejects_record_without_description_or_security_state():
    source = get_source(
        "debian_security_tracker"
    )

    payload = json.dumps(
        {
            "cve": "CVE-2026-12345",
            "package": "example-package",
        }
    )

    acquired = DebianTrackerAcquirer().acquire(
        source=source,
        document_id="CVE-2026-12345",
        content=payload,
        canonical_url="https://example.com/",
    )

    normalizer = DebianTrackerNormalizer()

    with pytest.raises(
        ValueError,
        match=(
            "neither a description nor "
            "useful security state"
        ),
    ):
        normalizer.normalize(
            acquired
        )


def test_same_cve_different_packages_have_distinct_document_ids():
    normalizer = DebianTrackerNormalizer()

    base_payload = {
        "cve": "CVE-2021-36489",
        "description": (
            "A vulnerability affecting multiple "
            "Debian packages."
        ),
        "scope": "local",
        "releases": {
            "bookworm": {
                "status": "resolved",
                "urgency": "medium",
            },
        },
    }

    first_payload = {
        **base_payload,
        "package": "allegro4.4",
    }

    second_payload = {
        **base_payload,
        "package": "allegro5",
    }

    first = normalizer.normalize_record(
        payload=first_payload,
        document_id="CVE-2021-36489",
        canonical_url=(
            "https://security-tracker.debian.org/"
            "tracker/CVE-2021-36489"
        ),
    )

    second = normalizer.normalize_record(
        payload=second_payload,
        document_id="CVE-2021-36489",
        canonical_url=(
            "https://security-tracker.debian.org/"
            "tracker/CVE-2021-36489"
        ),
    )

    assert first.entity_id == (
        "CVE-2021-36489"
    )

    assert second.entity_id == (
        "CVE-2021-36489"
    )

    assert first.document_id == (
        "debian_security_tracker:"
        "CVE-2021-36489:"
        "allegro4.4"
    )

    assert second.document_id == (
        "debian_security_tracker:"
        "CVE-2021-36489:"
        "allegro5"
    )

    assert first.document_id != (
        second.document_id
    )