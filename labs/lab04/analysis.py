import math

# Правила варіантів: (поріг, поле cvssData, очікуване значення)
VARIANT_RULES = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

# Допустимі значення полів cvssData, які використовують варіанти
ALLOWED_VALUES = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}

REJECTED_STATUS = "Rejected"


class NvdDataError(ValueError):
    """Відповідь NVD порушує очікувану структуру, типи або допустимі значення."""


def _optional_text(container: dict, key: str) -> str | None:
    """Повернути None для відсутнього поля або непорожній рядок для наявного."""
    if key not in container:
        return None

    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise NvdDataError(f"Поле {key} має бути непорожнім рядком")

    return value


def _english_description(cve: dict) -> str | None:
    """Вибрати перший непорожній англійський опис."""
    if "descriptions" not in cve:
        return None

    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise NvdDataError("Поле descriptions має бути списком")

    for item in descriptions:
        if not isinstance(item, dict):
            raise NvdDataError("Елемент descriptions має бути об'єктом")

        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise NvdDataError("Поля lang і value в описі мають бути рядками")

    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]

    return None


def _select_metric(cve: dict) -> dict | None:
    """Вибрати оцінку CVSS v3.1: першу Primary або перший елемент списку."""
    if "metrics" not in cve:
        return None

    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise NvdDataError("Поле metrics має бути об'єктом")

    if "cvssMetricV31" not in metrics:
        return None

    scores = metrics["cvssMetricV31"]
    if not isinstance(scores, list):
        raise NvdDataError("Поле cvssMetricV31 має бути списком")

    if not scores:
        return None

    if not all(isinstance(item, dict) for item in scores):
        raise NvdDataError("Елементи cvssMetricV31 мають бути об'єктами")

    for item in scores:
        if item.get("type") == "Primary":
            return item

    return scores[0]


def _base_score(cvss_data: dict) -> float:
    """Перевірити, що baseScore є скінченним числом від 0 до 10 і не bool."""
    if "baseScore" not in cvss_data:
        raise NvdDataError("У вибраній оцінці немає baseScore")

    score = cvss_data["baseScore"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise NvdDataError("baseScore має бути числом")

    if not math.isfinite(score) or not 0 <= score <= 10:
        raise NvdDataError("baseScore має бути скінченним числом від 0 до 10")

    return float(score)


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    None означає, що запис не знайдено (порожній список vulnerabilities).
    Інакше повертається словник:

    - ``vuln_status``: статус NVD або None;
    - ``description``: перший непорожній англійський опис або None;
    - ``score``: baseScore вибраної оцінки v3.1 або None, якщо оцінки немає;
    - ``score_source``, ``vector``, ``cvss_version``: поля вибраної оцінки або None;
    - ``cvss_data``: копія cvssData вибраної оцінки або None.

    Для статусу Rejected або відсутнього статусу оцінки не аналізуються,
    тому всі поля оцінки дорівнюють None.
    """
    if not isinstance(payload, dict):
        raise NvdDataError("Відповідь має бути об'єктом JSON")

    if "vulnerabilities" not in payload:
        raise NvdDataError("У відповіді немає поля vulnerabilities")

    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise NvdDataError("Поле vulnerabilities має бути списком")

    if not vulnerabilities:
        return None

    if len(vulnerabilities) > 1:
        raise NvdDataError(
            "Для одного ідентифікатора очікується не більше одного запису"
        )

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise NvdDataError("Елемент vulnerabilities має містити об'єкт cve")

    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise NvdDataError("Ідентифікатор у відповіді не збігається із запитаним")

    record = {
        "vuln_status": _optional_text(cve, "vulnStatus"),
        "description": _english_description(cve),
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_version": None,
        "cvss_data": None,
    }

    if record["vuln_status"] in (None, REJECTED_STATUS):
        return record

    metric = _select_metric(cve)
    if metric is None:
        return record

    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise NvdDataError("Поле cvssData має бути об'єктом")

    version = _optional_text(cvss_data, "version")
    if version is not None and version != "3.1":
        raise NvdDataError("Поле version у cvssMetricV31 має дорівнювати 3.1")

    record.update(
        {
            "score": _base_score(cvss_data),
            "score_source": _optional_text(metric, "source"),
            "vector": _optional_text(cvss_data, "vectorString"),
            "cvss_version": version,
            "cvss_data": dict(cvss_data),
        }
    )
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосувати правило варіанта до запису та повернути словник звіту."""
    if (
        not isinstance(variant, int)
        or isinstance(variant, bool)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15")

    threshold, field, expected = VARIANT_RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == REJECTED_STATUS:
        report["decision"] = "rejected"
        return report

    if record["vuln_status"] is None or record["cvss_data"] is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = record["cvss_version"]
    report["score"] = record["score"]
    report["score_source"] = record["score_source"]
    report["vector"] = record["vector"]

    cvss_data = record["cvss_data"]
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field]
    if observed not in ALLOWED_VALUES[field]:
        raise NvdDataError(f"Недопустиме значення поля {field}")

    report["observed"] = observed
    if record["score"] >= threshold and observed == expected:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
