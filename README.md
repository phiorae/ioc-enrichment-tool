# IOC Enrichment Tool
Учебный Python CLI: IP, ASCII-домены и SHA-256; адаптеры VirusTotal v3 и AbuseIPDB v2.
Подтверждаемые навыки: нормализация IOC, API-контракты, обработка ошибок, unit tests.
Это портфолио, не заявление о коммерческом опыте.

## Запуск
Python 3.11+, без зависимостей. Команды из корня репозитория:
~~~sh
python3 enrich.py examples/iocs.txt
python3 -m unittest discover -s tests -v
~~~
Пример: examples/demo-output.json. Все ответы fixtures синтетические; числа не
описывают реальные угрозы. no_fixture означает отсутствие учебного ответа.
queried_at в offline — время запуска, не время наблюдения угрозы.

## Live — только разрешённые несекретные IOC
~~~sh
mkdir -p local
# Создайте local/approved-iocs.txt и задайте ключ в окружении локально.
python3 enrich.py local/approved-iocs.txt --live --allow-external-disclosure --provider virustotal
~~~
Переменные: VT_API_KEY, ABUSEIPDB_API_KEY. .env не загружается автоматически.
Не сохраняйте ключи в коммиты и историю команд. При разработке live-запросы
не выполнялись: проверены mocks и документация, не реальные учётные записи.

| Adapter | Типы | Поля |
|---|---|---|
| VirusTotal | IP, domain, SHA-256 | last_analysis_stats |
| AbuseIPDB | IP | score, totalReports, окно 90 дней |

Запросы GET на фиксированные API-хосты. Timeout 10 s; redirects запрещены;
ответ до 1 MB. URL и email отклоняются, файлы не загружаются. Непубличные IP и
распространённые учебные домены блокируются. Публичный домен тоже может быть
конфиденциальным: флаг разрешения — осознанное раскрытие ввода провайдерам.
VirusTotal предупреждает о включении запрошенных IOC в общедоступный набор.

## Интерпретация
Нет общего risk score: показатели провайдеров имеют разные значения.
Нулевое число срабатываний не доказывает безопасность. 404 = not_found;
401/403 = ошибка доступа; 429 = rate_limited, автоматических повторов нет.
Ошибки одного адаптера не стирают результаты другого. Сырые ответы и ключи
не выводятся; сохраняется минимальная проекция полей.
Exit 1 при ошибке провайдера, 2 при неверном вводе, 0 при обработанном запросе.
unsupported_type, blocked_nonpublic_or_reserved, no_fixture, not_found —
диагностические статусы даже при exit 0. Максимум 100 IOC / 64 KiB.
IDN используйте в punycode.

## Документация API, проверена 2026-11-13
- [VirusTotal IP](https://docs.virustotal.com/reference/ip-info)
- [VirusTotal domain](https://docs.virustotal.com/reference/domain-info)
- [VirusTotal file](https://docs.virustotal.com/reference/file-info)
- [AbuseIPDB check](https://docs.abuseipdb.com/#check-endpoint)

## Ограничения
Нет URL-enrichment, DNS resolution, кеша и автоматической блокировки.
Статистика VT не содержит дату последнего анализа в выходной проекции: не
считайте её свежей на дату запроса. Следующие задачи: timestamp анализа,
cache TTL и разрешённая live-проверка контрактов. CI настроен; удалённый запуск
ещё не подтверждён.
