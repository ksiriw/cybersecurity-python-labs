CVE_ID = "CVE-2099-10001"


def cve_of(payload: dict) -> dict:
    """Повернути об'єкт cve з відповіді."""
    return payload["vulnerabilities"][0]["cve"]


def scores_of(payload: dict) -> list:
    """Повернути список cvssMetricV31 з відповіді."""
    return cve_of(payload)["metrics"]["cvssMetricV31"]


def cvss_data_of(payload: dict) -> dict:
    """Повернути cvssData першої оцінки v3.1."""
    return scores_of(payload)[0]["cvssData"]


def make_metric(
    source: str, metric_type: str, score: float, attack_vector: str
) -> dict:
    """Створити окрему оцінку CVSS v3.1 для тестів вибору."""
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": "3.1",
            "vectorString": f"CVSS:3.1/AV:{attack_vector[0]}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": score,
            "attackVector": attack_vector,
        },
    }
