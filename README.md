# Aegis - Система мониторинга безопасности контейнеров

Aegis - это инструмент для сканирования Docker-контейнеров на наличие уязвимостей, который работает как независимый Go-бинарь без Docker-контейнеризации.

## Возможности

- **Два компонента**: CLI (aegis) и агент (aegis-agent)
- **Интерактивный TUI режим** с горячими клавишами и модальными окнами
- **Сканирование контейнеров** с использованием Trivy
- **Управление хостами** и контейнерами
- **Пользовательские хуки** для выполнения скриптов при событиях
- **Уведомления** через системные оповещения и Telegram
- **Поддержка баз данных** PostgreSQL и SQLite
- **Рекомендации по устранению уязвимостей**
- **Экспорт отчетов** в JSON и CSV форматах

## Требования

- Go 1.21 или выше
- Trivy для сканирования образов контейнеров
- Docker Engine для работы с контейнерами
- PostgreSQL (опционально) или SQLite (по умолчанию)

## Установка

### Компиляция из исходного кода

```bash
git clone https://github.com/aegis/aegis-cli.git
cd aegis-cli
go mod tidy
go build -o bin/aegis cmd/aegis/main.go
go build -o bin/aegis-agent cmd/agent/main.go
```

### Установка бинарных файлов

```bash
# CLI утилита
sudo cp bin/aegis /usr/local/bin/aegis
sudo chmod +x /usr/local/bin/aegis

# Агент
sudo cp bin/aegis-agent /usr/local/bin/aegis-agent
sudo chmod +x /usr/local/bin/aegis-agent
```

## Настройка агента

1. Создайте каталоги для конфигурации и результатов:

```bash
sudo mkdir -p /etc/aegis-agent
sudo mkdir -p /var/lib/aegis-agent/results
sudo mkdir -p /var/log/aegis-agent
```

2. Создайте файл конфигурации `/etc/aegis-agent/config.yaml`:

```yaml
port: 8080
docker_socket_path: /var/run/docker.sock
scan_concurrency: 2
log_level: info
log_file: /var/log/aegis-agent/agent.log
results_dir: /var/lib/aegis-agent/results
hooks: []
```

## Настройка CLI

1. Создайте конфигурационную директорию:

```bash
mkdir -p ~/.aegis
```

2. Создайте файл конфигурации `~/.aegis/config.yaml`:

```yaml
database_type: sqlite
sqlite_path: ~/.aegis/aegis.db
default_agent_port: 8080
log_level: info
log_file: ~/.aegis/aegis.log
notification:
  enabled: true
  telegram_bot: false
  telegram_token: ""
  telegram_chat_id: ""
```

## Запуск агента как systemd-сервиса

1. Создайте файл сервиса `/etc/systemd/system/aegis-agent.service`:

```ini
[Unit]
Description=Aegis Agent Service
After=network.target

[Service]
ExecStart=/usr/local/bin/aegis-agent
Restart=on-failure
User=root
Group=root
WorkingDirectory=/var/lib/aegis-agent
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=aegis-agent

[Install]
WantedBy=multi-user.target
```

2. Активируйте и запустите сервис:

```bash
sudo systemctl daemon-reload
sudo systemctl enable aegis-agent
sudo systemctl start aegis-agent
```

## Использование CLI

### Управление хостами

```bash
# Список хостов
aegis hosts list

# Добавление хоста
aegis hosts add --name "Production" --address "192.168.1.10" --port 8080

# Удаление хоста
aegis hosts remove HOST_ID

# Обновление информации о хосте
aegis hosts update HOST_ID --name "New Name" --address "192.168.1.20"
```

### Управление контейнерами

```bash
# Список контейнеров на хосте
aegis containers list --host HOST_ID
```

### Сканирование контейнеров

```bash
# Сканирование одного контейнера
aegis scan run --host HOST_ID --container CONTAINER_ID

# Сканирование всех контейнеров на хосте
aegis scan run --host HOST_ID --all

# Просмотр статуса сканирования
aegis scan status SCAN_ID
```

### Управление уязвимостями

```bash
# Список всех уязвимостей
aegis vulnerabilities list

# Список уязвимостей для хоста
aegis vulnerabilities list --host HOST_ID

# Список уязвимостей для контейнера
aegis vulnerabilities list --container CONTAINER_ID
```

### Управление хуками

```bash
# Список всех хуков
aegis hook list

# Добавление хука
aegis hook add --name "Notify on Scan" --event on_scan_complete --script /path/to/script.sh --timeout 30

# Удаление хука
aegis hook remove HOOK_ID

# Обновление хука
aegis hook update HOOK_ID --name "New Name" --timeout 60
```

### Интерактивный режим

```bash
aegis tui
```

Интерактивный режим предоставляет удобный терминальный интерфейс с следующими возможностями:

- Просмотр списка хостов и контейнеров
- Сканирование контейнеров на наличие уязвимостей
- Просмотр и анализ уязвимостей
- Экспорт отчетов в различных форматах
- Просмотр логов операций

#### Основные горячие клавиши

- `F1`: Показать/скрыть справку
- `F2`: Сканировать выбранный контейнер
- `F3`: Экспорт отчета о уязвимостях
- `F4`: Управление хуками и стратегиями исправления
- `F5`: Обновить данные
- `F6`: Настройка Telegram-бота
- `Tab`: Переключение между панелями
- `Esc`: Закрытие модальных окон
- `F10`: Выход

## Пользовательские хуки

Хуки выполняются при наступлении следующих событий:

- `on_scan_start` - при начале сканирования
- `on_scan_complete` - при успешном завершении сканирования
- `on_error` - при возникновении ошибки

Скрипты хуков должны быть исполняемыми и принимать один параметр - ID сканирования.

Пример скрипта хука:

```bash
#!/bin/bash
# Скрипт, который выполняется при завершении сканирования

SCAN_ID=$1
echo "Сканирование $SCAN_ID завершено" >> /var/log/custom-hooks.log
```

## Уведомления в Telegram

Для отправки уведомлений в Telegram:

1. Создайте Telegram бота через BotFather и получите токен
2. Найдите ID чата, в который будут отправляться уведомления
3. Настройте конфигурацию:

```yaml
notification:
  enabled: true
  telegram_bot: true
  telegram_token: "YOUR_BOT_TOKEN"
  telegram_chat_id: "YOUR_CHAT_ID"
```
