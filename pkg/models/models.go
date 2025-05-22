package models

import (
	"time"
)

// Host представляет хост с агентом
type Host struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Address     string    `json:"address" db:"address"`
	Port        int       `json:"port" db:"port"`
	Status      string    `json:"status" db:"status"` // online, offline
	LastSeen    time.Time `json:"last_seen" db:"last_seen"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	Description string    `json:"description" db:"description"`
}

// Container представляет Docker-контейнер
type Container struct {
	ID        string    `json:"id" db:"id"`
	HostID    string    `json:"host_id" db:"host_id"`
	Name      string    `json:"name" db:"name"`
	Image     string    `json:"image" db:"image"`
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Scan представляет процесс сканирования контейнера
type Scan struct {
	ID          string    `json:"id" db:"id"`
	HostID      string    `json:"host_id" db:"host_id"`
	ContainerID string    `json:"container_id" db:"container_id"`
	Status      string    `json:"status" db:"status"` // pending, running, completed, failed
	StartedAt   time.Time `json:"started_at" db:"started_at"`
	FinishedAt  time.Time `json:"finished_at,omitempty" db:"finished_at"`
	ResultPath  string    `json:"result_path,omitempty" db:"result_path"`
	ErrorMsg    string    `json:"error_msg,omitempty" db:"error_msg"`
}

// Vulnerability представляет найденную уязвимость
type Vulnerability struct {
	ID               string    `json:"id" db:"id"`
	ScanID           string    `json:"scan_id" db:"scan_id"`
	ContainerID      string    `json:"container_id" db:"container_id"`
	HostID           string    `json:"host_id" db:"host_id"`
	VulnerabilityID  string    `json:"vulnerability_id" db:"vulnerability_id"` // CVE-ID
	Severity         string    `json:"severity" db:"severity"`                 // critical, high, medium, low
	Title            string    `json:"title" db:"title"`
	Description      string    `json:"description" db:"description"`
	Package          string    `json:"package" db:"package"`
	InstalledVersion string    `json:"installed_version" db:"installed_version"`
	FixedVersion     string    `json:"fixed_version,omitempty" db:"fixed_version"`
	References       string    `json:"references" db:"references"`
	DiscoveredAt     time.Time `json:"discovered_at" db:"discovered_at"`
}

// Hook представляет пользовательский хук
type Hook struct {
	ID             string    `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	Event          string    `json:"event" db:"event"` // on_scan_start, on_scan_complete, on_error
	ScriptPath     string    `json:"script_path" db:"script_path"`
	TimeoutSeconds int       `json:"timeout_seconds" db:"timeout_seconds"`
	Enabled        bool      `json:"enabled" db:"enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// HookExecution представляет выполнение хука
type HookExecution struct {
	ID         string    `json:"id" db:"id"`
	HookID     string    `json:"hook_id" db:"hook_id"`
	ScanID     string    `json:"scan_id" db:"scan_id"`
	Status     string    `json:"status" db:"status"` // success, failure
	Output     string    `json:"output" db:"output"`
	ErrorMsg   string    `json:"error_msg" db:"error_msg"`
	StartedAt  time.Time `json:"started_at" db:"started_at"`
	FinishedAt time.Time `json:"finished_at" db:"finished_at"`
}

// ScanRequest представляет запрос на сканирование
type ScanRequest struct {
	ContainerID string `json:"container_id"`
}

// ScanResponse представляет ответ на запрос сканирования
type ScanResponse struct {
	ScanID string `json:"scan_id"`
}

// ContainerListResponse представляет ответ на запрос списка контейнеров
type ContainerListResponse struct {
	Containers []Container `json:"containers"`
}

// ScanStatusResponse представляет ответ на запрос статуса сканирования
type ScanStatusResponse struct {
	ScanID          string          `json:"scan_id"`
	Status          string          `json:"status"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	ErrorMsg        string          `json:"error_msg,omitempty"`
}

// RemediationStrategy представляет стратегию исправления уязвимостей
type RemediationStrategy struct {
	ID                string    `json:"id" db:"id"`
	Name              string    `json:"name" db:"name"`
	Type              string    `json:"type" db:"type"` // hot-patch, rolling-update, restart
	EstimatedDowntime string    `json:"estimated_downtime" db:"estimated_downtime"`
	Command           string    `json:"command" db:"command"`
	Description       string    `json:"description" db:"description"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// NotificationConfig представляет конфигурацию уведомлений
type NotificationConfig struct {
	Enabled        bool   `json:"enabled" db:"enabled"`
	TelegramBot    bool   `json:"telegram_bot" db:"telegram_bot"`
	TelegramToken  string `json:"telegram_token,omitempty" db:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id,omitempty" db:"telegram_chat_id"`
}
