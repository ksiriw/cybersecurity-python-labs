import random
import sys
import os

# Підключаємо твої персональні дані з файлу student.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані Варіанту 1
passwords = ["password123", "Qwerty!2023", "admin", "MyP@ssword", "123456",
             "SecurePass!", "test", "P@ssword123", "welcome", "StrongP@ss1"]
criteria = {"min_length": 8, "require_digits": True, "require_upper": True, "require_special": True}
forbidden_passwords = {"password", "123456", "admin", "test", "welcome", "qwerty"}

def analyze_passwords():
    # Генерація 3 випадкових індексів і додавання дублікатів
    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords.append(passwords[idx])

    print(f"Аналіз паролів для: {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    
    # Оцінка надійності кожного пароля
    for pwd in passwords:
        is_forbidden = pwd.lower() in forbidden_passwords or len(pwd) < criteria["min_length"]
        
        has_digit = any(c.isdigit() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)
        
        meets_all = has_digit and has_upper and has_special and len(pwd) >= criteria["min_length"]
        is_unique = passwords.count(pwd) == 1
        
        if is_forbidden:
            status = "Заборонений"
        elif meets_all and len(pwd) >= criteria["min_length"] + 4 and is_unique:
            status = "Дуже сильний"
        elif meets_all:
            status = "Сильний"
        elif len(pwd) >= criteria["min_length"] and (has_digit or has_upper or has_special or has_lower):
            status = "Середній"
        else:
            status = "Слабкий"
            
        print(f"Пароль: {pwd:<15}  Статус: {status}")

if __name__ == "__main__":
    analyze_passwords()