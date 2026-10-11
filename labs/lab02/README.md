(`task1.py`):** Реалізація системи управління користувачами (User, Admin), безпечними сесіями (`Session`), хешуванням паролів через `PBKDF2`, журналом аудиту (`AuditLog`) та захищеним обліковим записом (`UserAccount`).
(`task2.py`):** Консольна утиліта для аналізу логів веб-сервера (розбір регулярними виразами, підрахунок топ IP-адрес із помилками `>=400`, пошук сигнатур атак SQLi, XSS, Directory Traversal та експорт у JSON/CSV).

   python -m labs.lab02.main demo
   python -m labs.lab02.task2 --log-file labs/lab02/data/access.log --output labs/lab02/data/web_analysis_report.json --min-status 400 --top 3 --format json