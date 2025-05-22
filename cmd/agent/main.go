package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegis/aegis-cli/pkg/api"
	"github.com/aegis/aegis-cli/pkg/config"
	"github.com/aegis/aegis-cli/pkg/hooks"
	"github.com/aegis/aegis-cli/pkg/scanner"
	"github.com/sirupsen/logrus"
)

func main() {
	// Отладочная информация
	fmt.Println("Aegis Agent v0.1.0")
	fmt.Println("Запуск...")
	fmt.Println("Текущая директория:", getCurrentDir())

	// Логирование
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Создаем файл для логирования ошибок
	logFile, err := os.OpenFile("aegis-agent-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logger.SetOutput(logFile)
	} else {
		fmt.Println("Ошибка открытия файла лога:", err)
	}

	logger.SetLevel(logrus.DebugLevel)
	logger.Debug("Начало выполнения агента")

	// Загрузка конфигурации
	cfg, err := config.LoadAgentConfig()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Инициализация сканера
	scannerInstance := scanner.NewScanner(cfg.ScanConcurrency, cfg.DockerSocketPath)

	// Инициализация менеджера хуков
	hookManager := hooks.NewManager(cfg.Hooks)

	// Инициализация API
	apiHandler := api.NewHandler(scannerInstance, hookManager)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: apiHandler,
	}

	// Обработка сигналов для корректного завершения работы
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Получен сигнал завершения, останавливаем сервер...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Ошибка при остановке сервера: %v", err)
		}
	}()

	// Запуск HTTP-сервера
	log.Printf("Запуск Aegis Agent на порту %d...", cfg.Port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Ошибка при запуске сервера: %v", err)
	}

	log.Println("Сервер успешно остановлен")
}

// Вспомогательная функция для получения текущей директории
func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("Ошибка: %v", err)
	}
	return dir
}

// Вспомогательная функция для логирования выхода
func logAndExit(logger *logrus.Logger, code int, message string) {
	logger.Debug(message)
	if logFile, ok := logger.Out.(*os.File); ok {
		logFile.Close()
	}
	os.Exit(code)
}
