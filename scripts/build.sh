#!/bin/bash
set -e

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Создание директории для бинарников
mkdir -p bin

echo -e "${YELLOW}Загрузка зависимостей...${NC}"
go mod tidy

echo -e "${YELLOW}Установка обязательных зависимостей...${NC}"
go get github.com/google/uuid
go get github.com/sirupsen/logrus
go get github.com/jroimartin/gocui
go get github.com/lib/pq
go get github.com/spf13/viper
go get github.com/mattn/go-sqlite3
go get github.com/gen2brain/beeep

echo -e "${YELLOW}Сборка CLI (aegis)...${NC}"
go build -o bin/aegis cmd/aegis/main.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Сборка CLI завершена успешно${NC}"
else
    echo -e "${RED}Ошибка сборки CLI${NC}"
    exit 1
fi

echo -e "${YELLOW}Сборка агента (aegis-agent)...${NC}"
go build -o bin/aegis-agent cmd/agent/main.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Сборка агента завершена успешно${NC}"
else
    echo -e "${RED}Ошибка сборки агента${NC}"
    exit 1
fi

# Установка разрешений
chmod +x bin/aegis
chmod +x bin/aegis-agent

echo -e "${GREEN}Бинарные файлы собраны и доступны в директории bin/${NC}"
echo -e "${YELLOW}Для установки выполните:${NC}"
echo -e "sudo cp bin/aegis /usr/local/bin/aegis"
echo -e "sudo cp bin/aegis-agent /usr/local/bin/aegis-agent" 
