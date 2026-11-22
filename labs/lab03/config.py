from pathlib import Path

# Шлях до папки лабораторної роботи
BASE_DIR = Path(__file__).resolve().parent

# Папка для зберігання бази даних
DATA_DIR = BASE_DIR / "data"

# Файл бази даних SQLite
DATABASE_PATH = DATA_DIR / "lab3.sqlite3"

# Номер варіанта, за даними якого виконується робота
DATA_VARIANT = 1

# Одиниця вимірювання поля value
VALUE_UNIT = "score"

# Допустимий діапазон поля value (включно)
VALUE_MIN = 0.0
VALUE_MAX = 10.0

# Поріг оцінки небезпеки для варіанта
VALUE_THRESHOLD = 7.0
