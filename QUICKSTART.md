# Быстрый старт с Aegis

Это краткое пошаговое руководство поможет познакомиться с основными возможностями Aegis.

## Шаг 1. Установка CLI и агента

1. Скачайте или соберите бинарные файлы:
   ```bash
   go build -o bin/aegis cmd/aegis/main.go
   go build -o bin/aegis-agent cmd/agent/main.go
   ```
2. Скопируйте их в `/usr/local/bin` и сделайте исполняемыми:
   ```bash
   sudo cp bin/aegis /usr/local/bin/aegis
   sudo cp bin/aegis-agent /usr/local/bin/aegis-agent
   sudo chmod +x /usr/local/bin/aegis /usr/local/bin/aegis-agent
   ```

## Шаг 2. Инициализация CLI

При первом запуске CLI автоматически создаст конфигурацию:
```bash
# Отобразить справку и сгенерировать ~/.aegis/config.yaml
aegis help
```  
Конфигурация будет в `~/.aegis/config.yaml`.

## Шаг 3. Добавление хоста и установка агента

Добавьте хост с запущенным агентом:
```bash
aegis hosts add --name "Мой сервер" --address "192.168.1.100" --port 8080
```  
Команда вернёт `ID` нового хоста.

## Шаг 4. Просмотр хостов

Проверьте список хостов и их статус:
```bash
aegis hosts list
```  
Столбец Status должен быть `online`.

## Шаг 5. Управление контейнерами

Получите список контейнеров на хосте:
```bash
aegis containers list --host <HOST_ID>
```  
Замените `<HOST_ID>` на идентификатор из предыдущего шага.

## Шаг 6. Сканирование контейнеров

- Сканирование одного контейнера:
  ```bash
  aegis scan run --host <HOST_ID> --container <CONTAINER_ID>
  ```
- Сканирование всех контейнеров:
  ```bash
  aegis scan run --host <HOST_ID> --all
  ```

## Шаг 7. Проверка статуса сканирования

Узнайте статус и результат сканирования:
```bash
aegis scan status <SCAN_ID>
```  
Для повторного запроса используйте ту же команду.

## Шаг 8. Просмотр уязвимостей

Выведите список найденных уязвимостей:
```bash
aegis vulnerabilities list --scan <SCAN_ID>
```  
Можно фильтровать по `--host`, `--container` или `--severity`.

## Шаг 9. Интерактивный режим (TUI)

Запустите терминальный интерфейс:
```bash
aegis tui
```  
Используйте F1–F10 и `Tab` для навигации и выполнения команд.

---

Поздравляем! Вы познакомились с основными командами Aegis. Для более подробной информации смотрите полное руководство в `ИНСТРУКЦИЯ.md`. 
