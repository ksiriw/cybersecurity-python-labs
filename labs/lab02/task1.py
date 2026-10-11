import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

SESSION_TIMEOUT_SEC = 900
HASH_ITERATIONS = 100_000


class User:
    def __init__(self, username: str, email: str, role: str, active: bool = True):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Неправильний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        if len(password) < 6:
            raise ValueError("Пароль занадто короткий (мінімум 6 символів).")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        eval_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )
        return hmac.compare_digest(eval_hash, self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self) -> str:
        return f"User(username={self.username}, email={self.email}, role={self.role}, active={self.active})"


class Admin(User):
    def __init__(self, username: str, email: str, permissions: list[str] | None = None):
        super().__init__(username, email, role="admin", active=True)
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(self.permissions)
        return f"Admin(username={self.username}, email={self.email}, permissions=[{perms}])"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії має бути додатним числом.")
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed <= timeout_sec


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str):
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self.records.append(record)

    def show_all(self):
        for rec in self.records:
            print(
                f"[{rec.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] User: {rec.username} -> Action: {rec.action}"
            )


class UserAccount:
    def __init__(self, user: User, session: Session = None, audit_log: AuditLog = None):
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if username != self.user.username:
            self.audit_log.add_log(username, "login_failure_unknown_user")
            return False

        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure_inactive")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure_wrong_password")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        else:
            self.session = None
            return False

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення повинно бути екземпляром класу User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення повинно бути екземпляром класу Session.")
            self.session = value
        else:
            raise KeyError(f"Зміна ключа '{key}' заборонена або не існує.")
