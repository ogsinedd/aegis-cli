package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis/aegis-cli/pkg/config"
	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/gen2brain/beeep"
	"github.com/sirupsen/logrus"
)

// NotificationManager управляет отправкой уведомлений
type NotificationManager struct {
	config *config.CliConfig
	logger *logrus.Logger
}

// TelegramMessage представляет сообщение для Telegram API
type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// NewNotificationManager создает новый менеджер уведомлений
func NewNotificationManager(cfg *config.CliConfig, logger *logrus.Logger) *NotificationManager {
	return &NotificationManager{
		config: cfg,
		logger: logger,
	}
}

// SendScanCompletedNotification отправляет уведомление о завершении сканирования
func (n *NotificationManager) SendScanCompletedNotification(
	hostName, containerName string, 
	vulns []models.Vulnerability, 
	scanDuration time.Duration) error {
	
	if !n.config.Notification.Enabled {
		return nil
	}

	// Подготавливаем сообщение
	title := "Aegis: Сканирование завершено"
	message := fmt.Sprintf("Хост: %s\nКонтейнер: %s\nНайдено уязвимостей: %d\nВремя сканирования: %s", 
		hostName, containerName, len(vulns), scanDuration.String())
	
	// Отправляем системное уведомление
	if err := beeep.Notify(title, message, ""); err != nil {
		n.logger.WithError(err).Error("Ошибка отправки системного уведомления")
	}
	
	// Отправляем уведомление в Telegram, если настроено
	if n.config.Notification.TelegramBot && 
		n.config.Notification.TelegramToken != "" && 
		n.config.Notification.TelegramChatID != "" {
		
		// Формируем более подробное сообщение для Telegram
		var telegramMsg string
		telegramMsg = fmt.Sprintf("*%s*\n\n", title)
		telegramMsg += fmt.Sprintf("🖥 *Хост:* %s\n", hostName)
		telegramMsg += fmt.Sprintf("🐳 *Контейнер:* %s\n", containerName)
		telegramMsg += fmt.Sprintf("⏱ *Время сканирования:* %s\n\n", scanDuration.String())
		
		// Добавляем статистику по уязвимостям
		var criticalCount, highCount, mediumCount, lowCount int
		for _, v := range vulns {
			switch v.Severity {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}
		
		telegramMsg += "*Найденные уязвимости:*\n"
		telegramMsg += fmt.Sprintf("🔴 Критических: %d\n", criticalCount)
		telegramMsg += fmt.Sprintf("🟠 Высоких: %d\n", highCount)
		telegramMsg += fmt.Sprintf("🟡 Средних: %d\n", mediumCount)
		telegramMsg += fmt.Sprintf("🟢 Низких: %d\n", lowCount)
		telegramMsg += fmt.Sprintf("*Всего:* %d\n", len(vulns))
		
		// Отправляем сообщение в Telegram
		if err := n.sendTelegramMessage(telegramMsg); err != nil {
			n.logger.WithError(err).Error("Ошибка отправки уведомления в Telegram")
		}
	}
	
	return nil
}

// SendScanErrorNotification отправляет уведомление об ошибке сканирования
func (n *NotificationManager) SendScanErrorNotification(
	hostName, containerName string, 
	errorMsg string) error {
	
	if !n.config.Notification.Enabled {
		return nil
	}

	// Подготавливаем сообщение
	title := "Aegis: Ошибка сканирования"
	message := fmt.Sprintf("Хост: %s\nКонтейнер: %s\nОшибка: %s", 
		hostName, containerName, errorMsg)
	
	// Отправляем системное уведомление
	if err := beeep.Notify(title, message, ""); err != nil {
		n.logger.WithError(err).Error("Ошибка отправки системного уведомления")
	}
	
	// Отправляем уведомление в Telegram, если настроено
	if n.config.Notification.TelegramBot && 
		n.config.Notification.TelegramToken != "" && 
		n.config.Notification.TelegramChatID != "" {
		
		// Формируем более подробное сообщение для Telegram
		var telegramMsg string
		telegramMsg = fmt.Sprintf("*%s*\n\n", title)
		telegramMsg += fmt.Sprintf("🖥 *Хост:* %s\n", hostName)
		telegramMsg += fmt.Sprintf("🐳 *Контейнер:* %s\n", containerName)
		telegramMsg += fmt.Sprintf("❌ *Ошибка:* %s\n", errorMsg)
		
		// Отправляем сообщение в Telegram
		if err := n.sendTelegramMessage(telegramMsg); err != nil {
			n.logger.WithError(err).Error("Ошибка отправки уведомления в Telegram")
		}
	}
	
	return nil
}

// SendTelegramReport отправляет файл отчета в Telegram
func (n *NotificationManager) SendTelegramReport(
	hostName, containerName string, 
	filePath string) error {
	
	if !n.config.Notification.Enabled || 
		!n.config.Notification.TelegramBot || 
		n.config.Notification.TelegramToken == "" || 
		n.config.Notification.TelegramChatID == "" {
		return nil
	}
	
	// Формируем заголовок для сообщения
	caption := fmt.Sprintf("*Отчет о сканировании*\n\n🖥 *Хост:* %s\n🐳 *Контейнер:* %s", 
		hostName, containerName)
	
	// Получаем тип MIME файла
	fileType := "application/json"
	if filepath.Ext(filePath) == ".csv" {
		fileType = "text/csv"
	}
	
	// Отправляем файл в Telegram
	if err := n.sendTelegramFile(filePath, fileType, caption); err != nil {
		n.logger.WithError(err).Error("Ошибка отправки отчета в Telegram")
		return err
	}
	
	return nil
}

// sendTelegramMessage отправляет текстовое сообщение в Telegram
func (n *NotificationManager) sendTelegramMessage(message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", 
		n.config.Notification.TelegramToken)
	
	telegramMsg := TelegramMessage{
		ChatID:    n.config.Notification.TelegramChatID,
		Text:      message,
		ParseMode: "Markdown",
	}
	
	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		return fmt.Errorf("ошибка маршалинга JSON: %w", err)
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("ошибка отправки HTTP запроса: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ошибка API Telegram: %s", string(body))
	}
	
	return nil
}

// sendTelegramFile отправляет файл в Telegram
func (n *NotificationManager) sendTelegramFile(filePath, fileType, caption string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", 
		n.config.Notification.TelegramToken)
	
	// Открываем файл
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer file.Close()
	
	// Создаем буфер для формирования multipart/form-data запроса
	var requestBody bytes.Buffer
	
	// Добавляем chat_id
	requestBody.WriteString("--boundary\r\n")
	requestBody.WriteString("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n")
	requestBody.WriteString(n.config.Notification.TelegramChatID + "\r\n")
	
	// Добавляем caption с Markdown
	requestBody.WriteString("--boundary\r\n")
	requestBody.WriteString("Content-Disposition: form-data; name=\"caption\"\r\n\r\n")
	requestBody.WriteString(caption + "\r\n")
	requestBody.WriteString("--boundary\r\n")
	requestBody.WriteString("Content-Disposition: form-data; name=\"parse_mode\"\r\n\r\n")
	requestBody.WriteString("Markdown\r\n")
	
	// Добавляем файл
	requestBody.WriteString("--boundary\r\n")
	requestBody.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\n", 
		filepath.Base(filePath)))
	requestBody.WriteString(fmt.Sprintf("Content-Type: %s\r\n\r\n", fileType))
	
	// Копируем содержимое файла в буфер
	if _, err := io.Copy(&requestBody, file); err != nil {
		return fmt.Errorf("ошибка копирования файла в буфер: %w", err)
	}
	
	requestBody.WriteString("\r\n--boundary--\r\n")
	
	// Отправляем запрос
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("ошибка создания HTTP запроса: %w", err)
	}
	
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка отправки HTTP запроса: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ошибка API Telegram: %s", string(body))
	}
	
	return nil
} 
