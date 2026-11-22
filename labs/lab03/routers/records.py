from sqlite3 import IntegrityError
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.config import VALUE_MAX, VALUE_MIN
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, RecordStatus

router = APIRouter(
    prefix="/records",
    tags=["Records"],
)

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]

NOT_FOUND_RESPONSE = {404: {"description": "Запис або категорію не знайдено"}}
WRITE_RESPONSES = {
    **NOT_FOUND_RESPONSE,
    409: {"description": "Запис із таким кодом уже існує"},
}


def category_not_found(error: repository.CategoryNotFoundError) -> HTTPException:
    """Сформувати помилку 404 для неіснуючої категорії."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Категорію з id {error} не знайдено",
    )


def duplicate_code() -> HTTPException:
    """Сформувати помилку 409 для повторного коду запису."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Запис із таким кодом уже існує",
    )


def record_not_found() -> HTTPException:
    """Сформувати помилку 404 для неіснуючого запису."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Запис не знайдено",
    )


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Отримати список записів",
)
def read_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Лише записи цієї категорії"),
    ] = None,
    status_filter: Annotated[
        RecordStatus | None,
        Query(alias="status", description="Лише записи з цим статусом"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="Мінімальне значення value",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Підрядок у title з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Кількість записів"),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Скільки записів пропустити"),
    ] = 0,
):
    """Отримати список записів із фільтрами та поділом на сторінки."""
    return repository.get_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати один запис",
    responses=NOT_FOUND_RESPONSE,
)
def read_record(record_id: RecordId):
    """Отримати один запис за його ID."""
    record = repository.get_record(record_id)

    if record is None:
        raise record_not_found()

    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses=WRITE_RESPONSES,
)
def create_record(record: RecordCreate):
    """Створити новий запис."""
    try:
        return repository.create_record(**record.model_dump())
    except repository.CategoryNotFoundError as error:
        raise category_not_found(error) from error
    except IntegrityError as error:
        raise duplicate_code() from error


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити запис",
    responses=WRITE_RESPONSES,
)
def update_record(record_id: RecordId, record: RecordReplace):
    """Повністю замінити змінювані поля запису."""
    try:
        updated_record = repository.update_record(record_id, **record.model_dump())
    except repository.CategoryNotFoundError as error:
        raise category_not_found(error) from error
    except IntegrityError as error:
        raise duplicate_code() from error

    if updated_record is None:
        raise record_not_found()

    return updated_record


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses=NOT_FOUND_RESPONSE,
)
def delete_record(record_id: RecordId):
    """Видалити запис за його ID."""
    if not repository.delete_record(record_id):
        raise record_not_found()


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Створити пакет записів",
    responses=WRITE_RESPONSES,
)
def bulk_create_records(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
):
    """Додати від 1 до 100 записів: зберігаються всі або жоден."""
    try:
        return repository.bulk_create_records(
            [record.model_dump() for record in records]
        )
    except repository.CategoryNotFoundError as error:
        raise category_not_found(error) from error
    except IntegrityError as error:
        raise duplicate_code() from error
