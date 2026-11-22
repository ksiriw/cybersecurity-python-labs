from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def make_response(payload=None, status_code: int = 200) -> Mock:
    """Створити двійник успішної відповіді Requests."""
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-test-key")
    fake_get = Mock(return_value=make_response({"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response("CVE-2021-44228")

    headers = fake_get.call_args.kwargs["headers"]
    assert headers == {"Accept": "application/json", "apiKey": "fake-test-key"}
    assert fake_get.call_args.kwargs["params"] == {"cveId": "CVE-2021-44228"}


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_with_blank_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_strip_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_http_error_is_raised(monkeypatch):
    response = make_response()
    response.status_code = 404
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "404 Client Error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.response.status_code == 404
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "exception",
    [requests.exceptions.ConnectTimeout(), requests.exceptions.ConnectionError()],
)
def test_network_errors_are_raised(monkeypatch, exception):
    monkeypatch.setattr(api_client.requests, "get", Mock(side_effect=exception))
    with pytest.raises(type(exception)):
        api_client.fetch_response("CVE-2099-10001")


def test_redirect_status_is_rejected(monkeypatch):
    response = make_response({"vulnerabilities": []}, status_code=301)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.status_code == 301
    response.json.assert_not_called()


def test_invalid_json_is_raised(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_real_network_is_blocked():
    with pytest.raises(AttributeError):
        requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", timeout=1)
