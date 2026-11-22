import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03.config import (
    DATA_VARIANT,
    VALUE_MAX,
    VALUE_MIN,
    VALUE_THRESHOLD,
    VALUE_UNIT,
)
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Виконати ініціалізацію перед запуском застосунку."""
    initialize_database()
    yield


app = FastAPI(
    title="Web Audit API",
    description=(
        "Реєстр вразливостей вебзастосунку (дані варіанта "
        f"{DATA_VARIANT}). Категорія визначає компонент, value — навчальну "
        f"оцінку небезпеки від {VALUE_MIN} до {VALUE_MAX}, одиниця вимірювання "
        f"— {VALUE_UNIT}, поріг — {VALUE_THRESHOLD}. Status — стан опрацювання."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(RequestValidationError)
def handle_validation_error(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Повернути 422 без вхідних значень: NaN і нескінченність не є JSON."""
    details = [
        {"type": item["type"], "loc": item["loc"], "msg": item["msg"]}
        for item in error.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": details},
    )


@app.exception_handler(sqlite3.Error)
def handle_database_error(request: Request, error: sqlite3.Error) -> JSONResponse:
    """Записати деталі в журнал, а клієнту повернути загальне повідомлення."""
    logger.error("Помилка бази даних", exc_info=error)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Внутрішня помилка сервера"},
    )


@app.get("/ping", summary="Перевірити доступність API")
def ping():
    """Перевірити доступність API."""
    return {"status": "ok"}


@app.get("/student", summary="Отримати дані студента")
def get_student():
    """Отримати інформацію про студента."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
