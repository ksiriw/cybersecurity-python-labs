from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN

RecordStatus = Literal["new", "in_progress", "done"]


class BaseSchema(BaseModel):
    """Базова модель для всіх схем."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class CategoryCreate(BaseSchema):
    """Схема для створення категорії."""

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(BaseSchema):
    """Схема для відображення категорії."""

    id: int
    name: str


class RecordCreate(BaseSchema):
    """Схема для створення запису."""

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=VALUE_MIN, le=VALUE_MAX, allow_inf_nan=False)
    status: RecordStatus


class RecordReplace(RecordCreate):
    """Схема для повного оновлення запису."""


class RecordRead(BaseSchema):
    """Схема для відображення запису."""

    id: int
    code: str
    title: str
    category_id: int
    category_name: str
    value: float
    status: RecordStatus
