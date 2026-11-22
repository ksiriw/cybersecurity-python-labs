import copy

import pytest

from labs.lab04 import analysis
from labs.lab04.tests.helpers import (
    CVE_ID,
    cve_of,
    cvss_data_of,
    make_metric,
    scores_of,
)

VARIANT = 1
RULE = {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"}


def report_for(payload: dict) -> dict:
    """Пройти обидва етапи аналізу для варіанта 1."""
    record = analysis.extract_record(payload, CVE_ID)
    return analysis.build_report(record, CVE_ID, VARIANT)


def test_sample_gives_full_review_report(sample_payload):
    assert report_for(sample_payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE,
        "observed": "NETWORK",
        "decision": "review",
    }


@pytest.mark.parametrize(
    ("score", "expected"),
    [(6.9, "other"), (7.0, "review"), (7.1, "review"), (10, "review")],
)
def test_threshold_with_network_vector(sample_payload, score, expected):
    cvss_data_of(sample_payload)["baseScore"] = score
    assert report_for(sample_payload)["decision"] == expected


@pytest.mark.parametrize("vector", ["ADJACENT_NETWORK", "LOCAL", "PHYSICAL"])
def test_other_vector_with_high_score_is_other(sample_payload, vector):
    cvss_data_of(sample_payload)["attackVector"] = vector
    report = report_for(sample_payload)
    assert report["decision"] == "other"
    assert report["observed"] == vector
    assert report["score"] == 9.8


def test_not_found_keeps_only_request_fields(sample_payload):
    sample_payload["vulnerabilities"] = []
    assert analysis.extract_record(sample_payload, CVE_ID) is None
    assert report_for(sample_payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 1,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE,
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score(sample_payload):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    report = report_for(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_scores(sample_payload):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    cvss_data_of(sample_payload)["baseScore"] = "broken"
    assert report_for(sample_payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_data(sample_payload):
    del cve_of(sample_payload)["vulnStatus"]
    report = report_for(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize("change", ["no_metrics", "no_v31", "empty_v31"])
def test_missing_score_is_insufficient_data(sample_payload, change):
    cve = cve_of(sample_payload)
    if change == "no_metrics":
        del cve["metrics"]
    elif change == "no_v31":
        cve["metrics"] = {"cvssMetricV2": []}
    else:
        cve["metrics"]["cvssMetricV31"] = []

    report = report_for(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_is_insufficient_data(sample_payload):
    del cvss_data_of(sample_payload)["attackVector"]
    report = report_for(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("value", [None, "network", "", 1, "ANY"])
def test_invalid_variant_field_raises(sample_payload, value):
    cvss_data_of(sample_payload)["attackVector"] = value
    record = analysis.extract_record(sample_payload, CVE_ID)
    with pytest.raises(ValueError):
        analysis.build_report(record, CVE_ID, VARIANT)


@pytest.mark.parametrize(
    "score", ["9.8", True, False, None, float("nan"), float("inf"), -0.1, 10.1]
)
def test_invalid_base_score_raises(sample_payload, score):
    cvss_data_of(sample_payload)["baseScore"] = score
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


def test_missing_base_score_raises(sample_payload):
    del cvss_data_of(sample_payload)["baseScore"]
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{"cve": None}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
    ],
)
def test_broken_structure_raises(payload):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_two_records_raise(sample_payload):
    sample_payload["vulnerabilities"].append(
        copy.deepcopy(sample_payload["vulnerabilities"][0])
    )
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize(
    ("key", "value"),
    [("metrics", None), ("metrics", []), ("vulnStatus", ""), ("vulnStatus", 5)],
)
def test_wrong_type_of_present_field_raises(sample_payload, key, value):
    cve_of(sample_payload)[key] = value
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize("value", [None, {}, "list"])
def test_wrong_type_of_v31_list_raises(sample_payload, value):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = value
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "3.0"), ("version", ""), ("vectorString", ""), ("vectorString", 7)],
)
def test_invalid_report_fields_raise(sample_payload, key, value):
    cvss_data_of(sample_payload)[key] = value
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


def test_missing_optional_score_fields_are_none(sample_payload):
    del cvss_data_of(sample_payload)["version"]
    del cvss_data_of(sample_payload)["vectorString"]
    del scores_of(sample_payload)[0]["source"]
    report = report_for(sample_payload)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "review"


def test_primary_has_priority_over_earlier_secondary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_metric("secondary@example.org", "Secondary", 9.9, "LOCAL"),
        make_metric("primary@example.org", "Primary", 7.5, "NETWORK"),
        make_metric("other@example.org", "Primary", 1.0, "PHYSICAL"),
    ]
    report = report_for(sample_payload)
    assert report["score_source"] == "primary@example.org"
    assert report["score"] == 7.5
    assert report["observed"] == "NETWORK"
    assert report["decision"] == "review"


def test_first_metric_when_no_primary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_metric("first@example.org", "Secondary", 5.0, "NETWORK"),
        make_metric("second@example.org", "Secondary", 9.0, "NETWORK"),
    ]
    report = report_for(sample_payload)
    assert report["score_source"] == "first@example.org"
    assert report["score"] == 5.0
    assert report["decision"] == "other"


def test_description_takes_first_non_empty_english(sample_payload):
    cve_of(sample_payload)["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "Second English text."},
    ]
    assert report_for(sample_payload)["description"] == "Second English text."


def test_description_without_english_is_none(sample_payload):
    cve_of(sample_payload)["descriptions"] = [{"lang": "uk", "value": "Опис"}]
    assert report_for(sample_payload)["description"] is None


@pytest.mark.parametrize(
    "descriptions", [None, "text", [{"lang": "en"}], [{"lang": 1, "value": "x"}]]
)
def test_broken_descriptions_raise(sample_payload, descriptions):
    cve_of(sample_payload)["descriptions"] = descriptions
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


def test_payload_is_not_modified(sample_payload):
    original = copy.deepcopy(sample_payload)
    report_for(sample_payload)
    assert sample_payload == original


@pytest.mark.parametrize("variant", [0, 16, True, "1", 1.0])
def test_build_report_rejects_bad_variant(variant):
    with pytest.raises(ValueError):
        analysis.build_report(None, CVE_ID, variant)
