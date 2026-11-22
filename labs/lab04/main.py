import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id_argument(value: str) -> str:
    """Перевірити повний збіг ідентифікатора з шаблоном CVE."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "очікується ідентифікатор у форматі CVE-РРРР-NNNN, наприклад CVE-2021-44228"
        )
    return value


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Розібрати аргументи командного рядка."""
    parser = argparse.ArgumentParser(
        description="Перегляд запису CVE з NVD та правило відбору за варіантом"
    )
    parser.add_argument(
        "--cve", required=True, type=cve_id_argument, help="Ідентифікатор CVE"
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Локальний JSON-файл із відповіддю NVD (без мережевих запитів)",
    )
    return parser.parse_args(argv)


def is_valid_variant(variant: object) -> bool:
    """Перевірити, що номер варіанта є цілим числом від 1 до 15 і не bool."""
    return (
        isinstance(variant, int)
        and not isinstance(variant, bool)
        and 1 <= variant <= 15
    )


def load_response(path: Path) -> object:
    """Прочитати локальну відповідь NVD з UTF-8 JSON-файла."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def error(message: str) -> None:
    """Вивести повідомлення про помилку в stderr."""
    print(f"Помилка: {message}", file=sys.stderr)


def get_payload(args: argparse.Namespace) -> object | None:
    """Отримати відповідь із файла або з NVD; None означає, що помилку вже виведено."""
    if args.input is not None:
        try:
            return load_response(args.input)
        except FileNotFoundError:
            error(f"файл {args.input} не знайдено")
        except UnicodeDecodeError:
            error(f"файл {args.input} не є текстом у кодуванні UTF-8")
        except json.JSONDecodeError:
            error(f"файл {args.input} містить некоректний JSON")
        except OSError:
            error(f"не вдалося прочитати файл {args.input}")
        return None

    try:
        return api_client.fetch_response(args.cve)
    except requests.exceptions.Timeout:
        error("NVD не відповів вчасно (таймаут)")
    except requests.exceptions.ConnectionError:
        error("не вдалося з'єднатися з NVD")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "невідомий"
        error(f"NVD повернув HTTP-помилку зі статусом {status}")
    except api_client.UnexpectedStatusError as exc:
        error(f"NVD повернув неочікуваний статус {exc.status_code}")
    except requests.exceptions.JSONDecodeError:
        error("відповідь NVD не є коректним JSON")
    except requests.exceptions.RequestException:
        error("запит до NVD не вдалося виконати")
    return None


def main(argv: list[str] | None = None) -> int:
    """Запустити утиліту та повернути код завершення."""
    if not is_valid_variant(VARIANT_NUMBER):
        error("VARIANT_NUMBER у shared/student.py має бути цілим числом від 1 до 15")
        return 2

    args = parse_args(argv)

    payload = get_payload(args)
    if payload is None:
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        error(f"некоректні дані у відповіді: {exc}")
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
