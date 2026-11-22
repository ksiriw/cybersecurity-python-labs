import json
import sqlite3
from contextlib import closing

from pydantic import Field

from labs.lab03.config import BASE_DIR
from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import BaseSchema, CategoryCreate, RecordCreate

SEED_PATH = BASE_DIR / "data" / "seed.json"


class SeedCategory(CategoryCreate):
    """Категорія з початкового набору: її id задано в JSON."""

    id: int = Field(gt=0)


class SeedData(BaseSchema):
    """Початковий набір: три категорії та вісім записів."""

    categories: list[SeedCategory] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


def load_seed_data() -> SeedData:
    """Прочитати та перевірити файл із початковими даними."""
    with SEED_PATH.open("r", encoding="utf-8") as file:
        return SeedData.model_validate(json.load(file))


def seed_database() -> None:
    """Заповнити порожню базу початковими даними в одній транзакції."""
    initialize_database()
    data = load_seed_data()

    with closing(get_connection()) as connection:
        categories_count = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]

        records_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if categories_count > 0 or records_count > 0:
            print("База даних уже містить записи. Повторне заповнення пропущено.")
            return

        with connection:
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(category.id, category.name) for category in data.categories],
            )

            connection.executemany(
                """
                INSERT INTO records
                (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.code,
                        record.title,
                        record.category_id,
                        record.value,
                        record.status,
                    )
                    for record in data.records
                ],
            )

    print("Початкові дані успішно додано!")


def main() -> None:
    """Запустити заповнення та зрозуміло повідомити про помилку."""
    try:
        seed_database()
    except (OSError, ValueError) as error:
        print(f"Файл початкових даних некоректний або недоступний: {error}")
        raise SystemExit(1) from error
    except sqlite3.Error as error:
        print(f"Дані не додано, усі зміни скасовано: {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
