# ЛР №3: Web API для реєстру вразливостей вебзастосунку

Сервіс зберігає знахідки перевірки вебзастосунку (дані варіанта 1).

- `categories`: компоненти застосунку (`web`, `api`, `database`).
- `records`: знахідки аудиту.
- `value`: навчальна оцінка небезпеки від 0 до 10, одиниця вимірювання `score`, поріг `7.0`.
- `status`: стан опрацювання (`new`, `in_progress`, `done`).

Між таблицями зв'язок «один до багатьох». Схема бази описана в `schema.sql`.

## Встановлення

Усі команди виконуються з кореня репозиторію в активованому віртуальному середовищі.

```bash
pip install -r requirements.txt
```

## Початкове заповнення

Команда створює таблиці й додає 3 категорії та 8 записів із `data/seed.json`. Повторний запуск даних не змінює.

```bash
python -m labs.lab03.seed
```

## Запуск API

```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Документація Swagger UI: <http://127.0.0.1:8000/docs>. Схема OpenAPI: <http://127.0.0.1:8000/openapi.json>.

## Маршрути

| Метод і шлях | Призначення | Успішний код |
|---|---|---|
| `GET /ping` | Перевірка доступності | 200 |
| `GET /student` | Дані студента | 200 |
| `GET /categories` | Список категорій | 200 |
| `POST /categories` | Створення категорії | 201 |
| `DELETE /categories/{category_id}` | Видалення порожньої категорії | 204 |
| `GET /records` | Список із фільтрами | 200 |
| `GET /records/{record_id}` | Один запис | 200 |
| `POST /records` | Створення запису | 201 |
| `PUT /records/{record_id}` | Повна заміна полів | 200 |
| `DELETE /records/{record_id}` | Видалення запису | 204 |
| `POST /records/bulk` | Пакет із 1–100 записів в одній транзакції | 201 |

Параметри `GET /records`: `category_id`, `status`, `min_value`, `q`, `limit` (1–100, типово 20), `offset` (типово 0).

Коди помилок: `404` запис або категорія не існує, `409` повторний `code` чи назва категорії або категорія містить записи, `422` некоректні дані.

## Приклади запитів

Команди розраховані на Bash. У Windows ті самі запити зручно виконувати через Swagger UI.

```bash
curl -i "http://127.0.0.1:8000/ping"
```

```bash
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
```

```bash
curl -i -X POST "http://127.0.0.1:8000/records" -H "Content-Type: application/json" -d '{"code":"V01-TEST","title":"Навчальна знахідка","category_id":1,"value":7.5,"status":"new"}'
```

Перевірка скасування пакета. Очікувано `409`, а запис `V01-ROLLBACK` не зберігається:

```bash
curl -i -X POST "http://127.0.0.1:8000/records/bulk" -H "Content-Type: application/json" -d '[{"code":"V01-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V01-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]'
```

## Перевірка стилю

```bash
ruff check labs/lab03
```

```bash
ruff format --check labs/lab03
```
