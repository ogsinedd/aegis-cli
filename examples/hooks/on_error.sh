#!/bin/bash
# Хук для события ошибки сканирования

SCAN_ID=$1
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "$TIMESTAMP - Ошибка при сканировании $SCAN_ID" >> /var/log/aegis-hooks.log

# Пример отправки уведомления по email
if [ -n "$EMAIL" ]; then
    echo "Произошла ошибка при сканировании контейнера (Scan ID: $SCAN_ID)" | \
    mail -s "Aegis: Ошибка сканирования" $EMAIL
fi

exit 0 
