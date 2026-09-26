import csv
import datetime
import hashlib
import json
import os
import sys
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 8
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}" 
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль надто короткий. Мінімальна довжина: {MIN_PASSWORD_LENGTH} символів.")
    
    data_to_hash = password + salt
    hash_object = hashlib.sha3_512(data_to_hash.encode('utf-8'))
    return hash_object.hexdigest()

def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get('username', 'unknown')
        status = "success"
        error_msg = ""
        try:
            result = func(*args, **kwargs)
            if not result:
                status = "failed"
            return result
        except Exception as e:
            status = "error"
            error_msg = str(e)
            raise e
        finally:
            log_entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": username,
                "action": "login_attempt",
                "status": status,
                "error": error_msg
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        try:
                            logs = json.load(f)
                        except json.JSONDecodeError:
                            pass
                logs.append(log_entry)
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except Exception as log_e:
                print(f"Помилка запису логу: {log_e}")
    return wrapper

def create_user(username, password):
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)

def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "hash_password"])
        for username, password in users_list:
            try:
                user_record = create_user(username, password)
                writer.writerow(user_record)
            except (ValueError, ValidationError) as e:
                print(f"Відхилено реєстрацію [{username}]: {e}")

users_db = []

def load_db():
    global users_db
    users_db = []
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users_db.append(row)
    
    print(f"\nБаза даних користувачів ({STUDENT_NAME})")
    print(f"{'Логін':<15}  {'Хеш пароля (SHA3-512)':<30}")
    for user in users_db:
        print(f"{user['username']:<15}  {user['hash_password'][:27]}")
        
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")
    
    user_record = next((u for u in users_db if u['username'] == username), None)
    if not user_record:
        return False
    
    expected_hash = generate_hash(password, PERSONAL_SALT)
    return user_record['hash_password'] == expected_hash

def main():
    users_to_register = (
        ("admin", "SuperSecret1!"),
        ("oksana", "MyP@ssword2026"),
        ("user1", "12345678"),
        ("guest", "guestpass12"),
        ("test", "testpass!"),
        ("hacker", "short"), 
        ("empty", ""),       
        ("manager", "ManagerP@ss!"),
        ("dev", "Developer2023"),
        ("analyst", "Analyst_123")
    )

    try:
        print("1. Реєстрація користувачів (створення CSV)")
        create_users(users_to_register)
        
        print("\n2. Читання бази даних...")
        load_db()
        
        print("\n3. Спроби входу (JSON логування)")
        test_logins = [
            ("oksana", "MyP@ssword2026"),  
            ("admin", "WrongPass!"),       
            ("unknown", "pass123"),     
            ("dev", "")                    
        ]
        
        for u, p in test_logins:
            try:
                result = login(u, p)
                status = "УСПІШНО" if result else "ВІДМОВЛЕНО"
                print(f"Вхід [{u}]: {status}")
            except (ValueError, ValidationError) as e:
                print(f"Вхід [{u}]: ПОМИЛКА - {e}")

    except FileNotFoundError as e:
        print(f"Критична помилка: Файл не знайдено - {e}")
    except PermissionError as e:
        print(f"Критична помилка: Немає прав доступу - {e}")
    except OSError as e:
        print(f"Критична помилка вводу/виводу - {e}")
    except Exception as e:
        print(f"Невідома критична помилка - {e}")

if __name__ == "__main__":
    main()
    
    