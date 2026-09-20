# labs/lab01/task2.py

users = {
    "admin001": {"role": "administrator", "clearance": 4, "department": "IT", "active": True},
    "user123": {"role": "analyst", "clearance": 2, "department": "Security", "active": True},
    "guest789": {"role": "guest", "clearance": 1, "department": "External", "active": True},
    "manager456": {"role": "manager", "clearance": 3, "department": "Operations", "active": True},
    "contractor99": {"role": "contractor", "clearance": 1, "department": "External", "active": False}
}

resources = [
    ("database_backup", 4), ("user_logs", 2), ("public_docs", 1),
    ("financial_reports", 3), ("system_config", 4), ("training_materials", 1),
    ("security_policies", 3), ("audit_logs", 4), ("employee_data", 3),
    ("temp_files", 1)
]

security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user", "suspended_acc"}

def check_access():
    # Вивід списку ресурсів із текстовою назвою рівня
    print("СИСТЕМА КОНТРОЛЮ ДОСТУПУ")
    print("Список ресурсів:")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"- {res_name} (Рівень: {level_name})")

    # Додаємо тестових користувачів (існуючих + заблокованого + неіснуючого)
    test_users = list(users.keys()) + ["temp_user", "unknown_hacker"]
    
    # Перевірка доступу кожного користувача до кожного ресурсу
    for user in test_users:
        for res_name, res_level in resources:
            if user not in users:
                status = "DENY (User not found)"
            elif user in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[user]["active"]:
                status = "DENY (Account inactive)"
            elif users[user]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"
                
            print(f"user=[{user}] resource=[{res_name}] -> {status}")

if __name__ == "__main__":
    check_access()