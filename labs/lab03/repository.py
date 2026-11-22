import sqlite3
from contextlib import closing

from labs.lab03.database import get_connection

RECORD_SELECT = """
    SELECT
        records.id,
        records.code,
        records.title,
        records.category_id,
        categories.name AS category_name,
        records.value,
        records.status
    FROM records
    JOIN categories
        ON records.category_id = categories.id
"""


class CategoryNotFoundError(Exception):
    """Запис посилається на категорію, якої немає в базі."""


def _ensure_categories_exist(
    connection: sqlite3.Connection,
    category_ids: set[int],
) -> None:
    """Перевірити, що всі вказані категорії існують."""
    for category_id in category_ids:
        row = connection.execute(
            "SELECT 1 FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()

        if row is None:
            raise CategoryNotFoundError(category_id)


def create_category(name: str) -> dict:
    """Створити нову категорію."""
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)",
                (name,),
            )

        return {
            "id": cursor.lastrowid,
            "name": name,
        }


def get_categories() -> list[dict]:
    """Отримати список усіх категорій."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()

        return [dict(row) for row in rows]


def delete_category(category_id: int) -> bool:
    """Видалити порожню категорію за її ID."""
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM categories WHERE id = ?",
                (category_id,),
            )

        return cursor.rowcount > 0


def create_record(
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict:
    """Створити новий запис."""
    with closing(get_connection()) as connection:
        with connection:
            _ensure_categories_exist(connection, {category_id})

            cursor = connection.execute(
                """
                INSERT INTO records
                (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (code, title, category_id, value, status),
            )

        row = connection.execute(
            RECORD_SELECT + " WHERE records.id = ?",
            (cursor.lastrowid,),
        ).fetchone()

        return dict(row)


def get_record(record_id: int) -> dict | None:
    """Отримати один запис за ID."""
    with closing(get_connection()) as connection:
        row = connection.execute(
            RECORD_SELECT + " WHERE records.id = ?",
            (record_id,),
        ).fetchone()

        return dict(row) if row else None


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Отримати записи з фільтрами та поділом на сторінки."""
    query = RECORD_SELECT

    conditions = []
    parameters = []

    if category_id is not None:
        conditions.append("records.category_id = ?")
        parameters.append(category_id)

    if status is not None:
        conditions.append("records.status = ?")
        parameters.append(status)

    if min_value is not None:
        conditions.append("records.value >= ?")
        parameters.append(min_value)

    if q is not None:
        conditions.append("instr(records.title, ?) > 0")
        parameters.append(q)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY records.id LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    with closing(get_connection()) as connection:
        rows = connection.execute(query, parameters).fetchall()

        return [dict(row) for row in rows]


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict | None:
    """Повністю оновити запис за його ID."""
    with closing(get_connection()) as connection:
        with connection:
            _ensure_categories_exist(connection, {category_id})

            cursor = connection.execute(
                """
                UPDATE records
                SET
                    code = ?,
                    title = ?,
                    category_id = ?,
                    value = ?,
                    status = ?
                WHERE id = ?
                """,
                (code, title, category_id, value, status, record_id),
            )

        if cursor.rowcount == 0:
            return None

        row = connection.execute(
            RECORD_SELECT + " WHERE records.id = ?",
            (record_id,),
        ).fetchone()

        return dict(row)


def delete_record(record_id: int) -> bool:
    """Видалити запис за його ID."""
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM records WHERE id = ?",
                (record_id,),
            )

        return cursor.rowcount > 0


def bulk_create_records(records: list[dict]) -> list[dict]:
    """Додати всі записи пакета в одній транзакції."""
    with closing(get_connection()) as connection:
        with connection:
            _ensure_categories_exist(
                connection,
                {record["category_id"] for record in records},
            )

            connection.executemany(
                """
                INSERT INTO records
                (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        record["code"],
                        record["title"],
                        record["category_id"],
                        record["value"],
                        record["status"],
                    )
                    for record in records
                ],
            )

        result = []

        for record in records:
            row = connection.execute(
                RECORD_SELECT + " WHERE records.code = ?",
                (record["code"],),
            ).fetchone()

            result.append(dict(row))

        return result
