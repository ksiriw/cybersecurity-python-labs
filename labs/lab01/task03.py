import hashlib
import datetime
import os
import sys

# Підключаємо твої персональні дані
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

def hash_and_log(data_list):
    print(f"Хешування та логування: {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    
    # Налаштування папки та файлу для логів
    log_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "security_audit.log")
    
    # Відкриваємо файл для додавання записів (режим 'a')
    with open(log_file, "a", encoding="utf-8") as f:
        for data in data_list:
            # Створення SHA-256 хешу
            hash_object = hashlib.sha256(data.encode('utf-8'))
            hex_dig = hash_object.hexdigest()
            
            # Формування запису логу з часовою міткою
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] DATA: {data:<15} | SHA-256: {hex_dig}\n"
            
            # Запис у файл та вивід скороченого хешу на екран
            f.write(log_entry)
            print(f"Дані: {data:<15}  Хеш: {hex_dig[:15]}")
    
    print(f"Логи успішно збережено у файл: labs/lab01/data/security_audit.log")

if __name__ == "__main__":
    # Вхідні дані для Варіанту 1
    test_data = ["admin_pass", "system_config", "user_data_2023", "financial_Q1"]
    hash_and_log(test_data)