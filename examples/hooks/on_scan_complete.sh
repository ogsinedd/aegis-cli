#!/bin/bash
# Хук для события завершения сканирования

SCAN_ID=$1
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "$TIMESTAMP - Сканирование $SCAN_ID завершено" >> /var/log/aegis-hooks.log

# Пример отправки уведомления через webhook
if [ -n "$WEBHOOK_URL" ]; then
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"text\":\"Сканирование контейнера завершено\", \"scan_id\":\"$SCAN_ID\"}" \
        $WEBHOOK_URL
fi

exit 0 
