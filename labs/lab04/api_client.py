import os

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Час на встановлення з'єднання та час очікування між отриманням даних
REQUEST_TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """NVD повернув статус, відмінний від 200, без HTTP-помилки (наприклад, 3xx)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний статус відповіді: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Сформувати заголовки запиту; ключ береться з NVD_API_KEY, якщо він заданий."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()

    if api_key:
        headers["apiKey"] = api_key

    return headers


def fetch_response(cve_id: str) -> object:
    """Виконати один GET-запит до NVD і повернути декодований JSON."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()

    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)

    return response.json()
