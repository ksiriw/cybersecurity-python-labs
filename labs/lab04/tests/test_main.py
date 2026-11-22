import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04 import main as cli
from labs.lab04.tests.helpers import CVE_ID


def forbid_network(monkeypatch) -> None:
    """Зробити так, щоб будь-яке звернення до клієнта NVD провалило тест."""
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(side_effect=AssertionError("network used"))
    )


def test_local_run_prints_report_without_network(monkeypatch, capsys, sample_path):
    forbid_network(monkeypatch)

    code = cli.main(["--cve", CVE_ID, "--input", str(sample_path)])

    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"
    assert report["variant"] == 1
    assert report["observed"] == "NETWORK"
    assert report["score"] == 9.8


def test_local_not_found_returns_zero(monkeypatch, capsys, tmp_path):
    forbid_network(monkeypatch)
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")

    code = cli.main(["--cve", CVE_ID, "--input", str(path)])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_missing_file_returns_one(monkeypatch, capsys, tmp_path):
    forbid_network(monkeypatch)

    code = cli.main(["--cve", CVE_ID, "--input", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "не знайдено" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_json_file_returns_one(monkeypatch, capsys, tmp_path):
    forbid_network(monkeypatch)
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    code = cli.main(["--cve", CVE_ID, "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "некоректний JSON" in captured.err


def test_wrong_data_returns_one(monkeypatch, capsys, tmp_path, sample_payload):
    forbid_network(monkeypatch)
    path = tmp_path / "other.json"
    path.write_text(json.dumps(sample_payload), encoding="utf-8")

    code = cli.main(["--cve", "CVE-2099-99999", "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "некоректні дані" in captured.err


@pytest.mark.parametrize(
    "cve", ["cve-2021-44228", "CVE-21-44228", "CVE-2021-123", "CVE-2021-44228x", ""]
)
def test_bad_cve_argument_exits_with_two(capsys, cve):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--cve", cve])
    assert exc_info.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_argument_exits_with_two():
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "1", None])
def test_bad_variant_returns_two(monkeypatch, capsys, sample_path, variant):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", variant)

    code = cli.main(["--cve", CVE_ID, "--input", str(sample_path)])

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "VARIANT_NUMBER" in captured.err


def test_other_valid_variant_is_used(monkeypatch, capsys, sample_path):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", 8)

    assert cli.main(["--cve", CVE_ID, "--input", str(sample_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["variant"] == 8
    assert report["decision"] == "other"


def test_network_mode_uses_client(monkeypatch, capsys, sample_payload):
    fake_fetch = Mock(return_value=sample_payload)
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)

    assert cli.main(["--cve", CVE_ID]) == 0
    fake_fetch.assert_called_once_with(CVE_ID)
    assert json.loads(capsys.readouterr().out)["decision"] == "review"


def http_error(status: int) -> requests.exceptions.HTTPError:
    """Створити HTTP-помилку з відповіддю потрібного статусу."""
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.exceptions.HTTPError("secret details", response=response)


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (requests.exceptions.ReadTimeout("secret details"), "таймаут"),
        (requests.exceptions.ConnectionError("secret details"), "з'єднатися"),
        (http_error(404), "статусом 404"),
        (http_error(503), "статусом 503"),
        (api_client.UnexpectedStatusError(301), "статус 301"),
        (requests.exceptions.JSONDecodeError("bad", "{", 1), "не є коректним JSON"),
    ],
)
def test_network_errors_return_one(monkeypatch, capsys, exception, message):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=exception))

    code = cli.main(["--cve", CVE_ID])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert message in captured.err
    assert "secret details" not in captured.err
    assert "fake-secret-key" not in captured.err
    assert "Traceback" not in captured.err
