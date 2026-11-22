from sqlite3 import IntegrityError
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(
    prefix="/categories",
    tags=["Categories"],
)

CategoryId = Annotated[int, Path(gt=0, description="Ідентифікатор категорії")]


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
)
def read_categories():
    """Отримати список усіх категорій за зростанням id."""
    return repository.get_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate):
    """Створити нову категорію."""
    try:
        return repository.create_category(category.name)
    except IntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія з такою назвою вже існує",
        ) from error


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId):
    """Видалити категорію, у якій немає записів."""
    try:
        deleted = repository.delete_category(category_id)
    except IntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Неможливо видалити категорію, оскільки вона містить записи",
        ) from error

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Категорію не знайдено",
        )
