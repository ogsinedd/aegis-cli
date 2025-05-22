package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/spf13/viper"
)

// CliConfig представляет конфигурацию CLI-утилиты
type CliConfig struct {
	DatabaseType     string                    `mapstructure:"database_type"`      // postgresql, sqlite
	DatabaseURL      string                    `mapstructure:"database_url"`       // Для PostgreSQL
	SQLitePath       string                    `mapstructure:"sqlite_path"`        // Для SQLite
	DefaultAgentPort int                       `mapstructure:"default_agent_port"` // Порт по умолчанию для новых агентов
	LogLevel         string                    `mapstructure:"log_level"`
	LogFile          string                    `mapstructure:"log_file"`
	Notification     models.NotificationConfig `mapstructure:"notification"`
	TelegramBotToken string                    `mapstructure:"telegram_bot_token"`
	TelegramChatID   string                    `mapstructure:"telegram_chat_id"`
}

// AgentConfig представляет конфигурацию агента
type AgentConfig struct {
	Port             int           `mapstructure:"port"`
	DockerSocketPath string        `mapstructure:"docker_socket_path"`
	ScanConcurrency  int           `mapstructure:"scan_concurrency"`
	LogLevel         string        `mapstructure:"log_level"`
	LogFile          string        `mapstructure:"log_file"`
	ResultsDir       string        `mapstructure:"results_dir"`
	Hooks            []models.Hook `mapstructure:"hooks"`
}

// LoadCliConfig загружает конфигурацию CLI из файла
func LoadCliConfig() (*CliConfig, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Определение путей поиска конфигурации
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("не удалось определить домашний каталог пользователя: %w", err)
	}

	aegisDir := filepath.Join(userHome, ".aegis")
	viper.AddConfigPath(aegisDir)
	viper.AddConfigPath(".")

	// Настройка переменных окружения
	viper.SetEnvPrefix("AEGIS")
	viper.AutomaticEnv()

	// Установка значений по умолчанию
	viper.SetDefault("database_type", "sqlite")
	viper.SetDefault("sqlite_path", filepath.Join(aegisDir, "aegis.db"))
	viper.SetDefault("default_agent_port", 8080)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_file", filepath.Join(aegisDir, "aegis.log"))

	// Загрузка конфигурации
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Создать конфигурацию по умолчанию, если файл не найден
			if err := os.MkdirAll(aegisDir, 0755); err != nil {
				return nil, fmt.Errorf("ошибка создания каталога конфигурации: %w", err)
			}

			// Создаем и используем конфигурацию по умолчанию
			defaultConfig := &CliConfig{
				DatabaseType:     "sqlite",
				SQLitePath:       filepath.Join(aegisDir, "aegis.db"),
				DefaultAgentPort: 8080,
				LogLevel:         "info",
				LogFile:          filepath.Join(aegisDir, "aegis.log"),
				Notification: models.NotificationConfig{
					Enabled:     true,
					TelegramBot: false,
				},
			}

			// Устанавливаем значения Viper из defaultConfig
			viper.Set("database_type", defaultConfig.DatabaseType)
			viper.Set("sqlite_path", defaultConfig.SQLitePath)
			viper.Set("default_agent_port", defaultConfig.DefaultAgentPort)
			viper.Set("log_level", defaultConfig.LogLevel)
			viper.Set("log_file", defaultConfig.LogFile)
			viper.Set("notification.enabled", defaultConfig.Notification.Enabled)
			viper.Set("notification.telegram_bot", defaultConfig.Notification.TelegramBot)

			configPath := filepath.Join(aegisDir, "config.yaml")
			if err := viper.WriteConfigAs(configPath); err != nil {
				return nil, fmt.Errorf("ошибка создания файла конфигурации: %w", err)
			}
		} else {
			return nil, fmt.Errorf("ошибка чтения конфигурации: %w", err)
		}
	}

	var config CliConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("ошибка декодирования конфигурации: %w", err)
	}

	return &config, nil
}

// LoadAgentConfig загружает конфигурацию агента из файла
func LoadAgentConfig() (*AgentConfig, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Определение путей поиска конфигурации
	viper.AddConfigPath("/etc/aegis-agent")
	viper.AddConfigPath(".")

	// Настройка переменных окружения
	viper.SetEnvPrefix("AEGIS_AGENT")
	viper.AutomaticEnv()

	// Установка значений по умолчанию
	viper.SetDefault("port", 8080)
	viper.SetDefault("docker_socket_path", "/var/run/docker.sock")
	viper.SetDefault("scan_concurrency", 2)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_file", "/var/log/aegis-agent/agent.log")
	viper.SetDefault("results_dir", "/var/lib/aegis-agent/results")

	// Загрузка конфигурации
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Создаём конфигурацию по умолчанию
			agentConfigDir := "/etc/aegis-agent"
			resultsDir := "/var/lib/aegis-agent/results"
			logDir := "/var/log/aegis-agent"

			for _, dir := range []string{agentConfigDir, resultsDir, logDir} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return nil, fmt.Errorf("ошибка создания каталога %s: %w", dir, err)
				}
			}

			// Создаем и используем конфигурацию по умолчанию
			defaultConfig := &AgentConfig{
				Port:             8080,
				DockerSocketPath: "/var/run/docker.sock",
				ScanConcurrency:  2,
				LogLevel:         "info",
				LogFile:          "/var/log/aegis-agent/agent.log",
				ResultsDir:       "/var/lib/aegis-agent/results",
				Hooks:            []models.Hook{},
			}

			// Устанавливаем значения Viper из defaultConfig
			viper.Set("port", defaultConfig.Port)
			viper.Set("docker_socket_path", defaultConfig.DockerSocketPath)
			viper.Set("scan_concurrency", defaultConfig.ScanConcurrency)
			viper.Set("log_level", defaultConfig.LogLevel)
			viper.Set("log_file", defaultConfig.LogFile)
			viper.Set("results_dir", defaultConfig.ResultsDir)

			configPath := filepath.Join(agentConfigDir, "config.yaml")
			if err := viper.WriteConfigAs(configPath); err != nil {
				return nil, fmt.Errorf("ошибка создания файла конфигурации: %w", err)
			}
		} else {
			return nil, fmt.Errorf("ошибка чтения конфигурации: %w", err)
		}
	}

	var config AgentConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("ошибка декодирования конфигурации: %w", err)
	}

	return &config, nil
}
