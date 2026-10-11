import sys

from labs.lab02.task1 import Admin, User, UserAccount


def run_demo():
    print("Демонстрація Завдання 1 (ООП та Безпека)")

    user = User(username="ivan_sec", email="ivan_sec@gmail.com", role="analyst")
    user.set_password("SecureP@ss123")

    account = UserAccount(user=user)

    print("\n[TEST] Спроба входу з невірним паролем:")
    account.login("ivan_sec", "WrongPassword", "192.168.1.50")

    print("\n[TEST] Спроба входу з вірним паролем:")
    account.login("ivan_sec", "SecureP@ss123", "192.168.1.50")
    print(f"Статус автентифікації: {account.is_authenticated()}")

    print("\n[TEST] Зміна email на валідний та невалідний:")
    try:
        user.email = "bad-email"
    except ValueError as e:
        print(f"Очікувана помилка валідації: {e}")
    user.email = "ivan_new@domain.org"
    print(f"Новий email: {user.email}")

    print("\n[TEST] Робота з адміністратором:")
    admin = Admin(
        username="root_admin",
        email="admin@corp.ua",
        permissions=["READ_LOGS", "MODIFY_FIREWALL"],
    )
    print(admin)
    print(f"Чи має право MODIFY_FIREWALL: {admin.has_permission('MODIFY_FIREWALL')}")

    account.logout()
    print("\nЖурнал аудиту (AuditLog)")
    account.audit_log.show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Використовуйте: python -m labs.lab02.main demo")
