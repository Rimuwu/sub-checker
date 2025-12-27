# Скрипты для быстрого запуска тестов (checker/scripts)

В этой папке собраны простые bash-скрипты для быстрого запуска разных режимов `checker/main.py`.

Доступные скрипты:

- `run_basic.sh <URL> [OUTPUT]` — базовая проверка (ping + tcp)
- `run_speed.sh <URL> [OUTPUT]` — скорость скачивания (--do-speed). Переменные окружения:
  - `SPEED_URL` — URL для теста (по умолчанию http://speedtest.tele2.net/5MB.zip)
  - `SPEED_DURATION`, `SPEED_CONCURRENCY`
  - `SERVE_SPEED_SIZE` — если >0, будет создан локальный файл указанного размера (MB) и он будет раздаваться локальным HTTP-сервером
- `run_game.sh <URL> <UDP_TARGET> [OUTPUT]` — UDP-симуляция (требует host:port)
- `run_xray.sh <URL> [OUTPUT]` — запустить `xray` и проксировать тесты через него (указать `XRAY_PATH` при необходимости)
- `run_full_test.sh <URL> [UDP_TARGET] [OUTPUT]` — комплексный тест: speed + (опционально game) + start_xray + генерирует HTML отчет
- `serve_speed_file.sh <URL> <MB> [OUTPUT]` — helper: запустить speed тест с локально создаваемым файлом размера MB

Примеры:

```bash
# базовый тест
./run_basic.sh "https://example.com/sub" nodes.json

# тест скорости, используя локально сгенерированный 20MB файл
SERVE_SPEED_SIZE=20 ./run_speed.sh "https://example.com/sub" speed_out.json

# игровой тест
./run_game.sh "https://example.com/sub" "1.2.3.4:27015"

# комплексный тест с HTML отчетом и открытием в браузере
./run_full_test.sh "https://example.com/sub" "1.2.3.4:27015" full_report.json
```

Примечания:
- Скрипты используют `python` из PATH, можно задать `PYTHON` переменную окружения для явного интерпретатора, например `PYTHON=python3`.
- На Windows используйте Git Bash, WSL или адаптируйте команды под PowerShell (скрипты написаны как POSIX bash).
- Сделайте скрипты исполняемыми: `chmod +x *.sh` (если требуется).

Если хотите, могу:
- добавить Windows PowerShell версии скриптов,
- добавить опцию выбора профиля (preset) с конфигами заранее,
- или запустить smoke-тест (если есть пример url).
