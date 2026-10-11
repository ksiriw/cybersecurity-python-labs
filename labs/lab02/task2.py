import argparse
import csv
import json
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

LOG_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"  # IP-адреса
    r"(?P<ident>\S+)\s+"  # Ident
    r"(?P<user>\S+)\s+"  # User
    r"\[(?P<datetime>[^\]]+)\]\s+"  # Дата та час
    r'"(?P<method>[A-Z]+)\s+'  # HTTP-метод
    r"(?P<uri>[^\s]+)\s+"  # URI
    r'[^"]*"\s+'  # HTTP-протокол
    r"(?P<status>\d{3})\s+"  # Статус-код
    r"(?P<size>\S+)"  # Розмір відповіді
)

ATTACK_SIGNATURES = {
    "SQLi": re.compile(
        r"(union\s+select|or\s+1=1|waitfor\s+delay|drop\s+table)", re.IGNORECASE
    ),
    "Directory Traversal": re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|javascript:|onerror=)", re.IGNORECASE),
}


def parse_access_log(file_path: Path, min_status: int = 400):
    if not file_path.exists():
        logging.error(f"Файл логу не знайдено: {file_path}")  # noqa: LOG015
        return []

    entries = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if match:
                data = match.groupdict()
                status = int(data["status"])

                entry = {
                    "ip": data["ip"],
                    "datetime_str": data["datetime"],
                    "method": data["method"],
                    "uri": data["uri"],
                    "status": status,
                    "raw": line.strip(),
                }
                entries.append(entry)
    return entries


def analyze_logs(
    log_file: str, output_path: str, min_status: int, top_n: int, file_format: str
):
    log_path = Path(log_file)
    out_path = Path(output_path)

    logging.info(f"Loading access log from {log_path}...")  # noqa: LOG015
    entries = parse_access_log(log_path, min_status)

    if not entries:
        logging.warning("Не знайдено жодного валідного запису в лог-файлі.")  # noqa: LOG015
        return

    first_time = entries[0]["datetime_str"]
    last_time = entries[-1]["datetime_str"]
    logging.info(  # noqa: LOG015
        f"Processed {len(entries)} log entries from {first_time} to {last_time}."
    )

    error_ips = Counter()
    ip_error_details = defaultdict(lambda: Counter())

    for entry in entries:
        status = entry["status"]
        if status >= min_status:
            ip = entry["ip"]
            error_ips[ip] += 1
            ip_error_details[ip][status] += 1

    top_error_ips = error_ips.most_common(top_n)

    print(f"\nTop-{top_n} IP Addresses with Error Statuses (>= {min_status})")
    for ip, count in top_error_ips:
        details = ", ".join(
            [f"{code}: {cnt}" for code, cnt in ip_error_details[ip].items()]
        )
        print(f"{ip}\t{count} errors ({details})")

    detected_attacks = []
    print("\nDetected Attack Signatures")
    for entry in entries:
        uri = entry["uri"]
        raw = entry["raw"]
        ip = entry["ip"]

        for attack_type, pattern in ATTACK_SIGNATURES.items():
            if pattern.search(uri) or pattern.search(raw):
                alert_msg = f'Potential {attack_type} attack from {ip}: "{entry["method"]} {uri}"'
                print(f"[ALERT] {alert_msg}")
                detected_attacks.append(
                    {"ip": ip, "attack_type": attack_type, "uri": uri, "raw": raw}
                )
                break

    out_path.parent.mkdir(parents=True, exist_ok=True)

    report_data = {
        "total_entries": len(entries),
        "top_error_ips": [
            {"ip": ip, "total_errors": count, "details": dict(ip_error_details[ip])}
            for ip, count in top_error_ips
        ],
        "detected_attacks": detected_attacks,
    }

    if file_format.lower() == "json":
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
    elif file_format.lower() == "csv":
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Attack_Type", "URI", "Raw_Request"])
            for atk in detected_attacks:
                writer.writerow([atk["ip"], atk["attack_type"], atk["uri"], atk["raw"]])

    logging.info(f"Analysis report saved to {out_path}")  # noqa: LOG015


def main():
    parser = argparse.ArgumentParser(
        description="Аналізатор журналів веб-сервера (Nginx/Apache Access Log)"
    )
    parser.add_argument("--log-file", required=True, help="Шлях до файлу access.log")
    parser.add_argument(
        "--output",
        default="labs/lab02/data/web_analysis_report.json",
        help="Шлях для збереження звіту",
    )
    parser.add_argument(
        "--min-status", type=int, default=400, help="Мінімальний статус-код помилки"
    )
    parser.add_argument("--top", type=int, default=3, help="Кількість топ IP-адрес")
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат звіту (json/csv)",
    )

    args = parser.parse_args()

    analyze_logs(
        log_file=args.log_file,
        output_path=args.output,
        min_status=args.min_status,
        top_n=args.top,
        file_format=args.format,
    )


if __name__ == "__main__":
    main()
