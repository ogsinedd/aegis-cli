package hooks

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Manager представляет менеджер хуков
type Manager struct {
	hooks  []models.Hook
	logger *logrus.Logger
	mu     sync.RWMutex // Мьютекс для безопасного доступа к хукам
}

// NewManager создает новый менеджер хуков
func NewManager(hooks []models.Hook) *Manager {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	return &Manager{
		hooks:  hooks,
		logger: logger,
	}
}

// AddHook добавляет новый хук
func (m *Manager) AddHook(hook models.Hook) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем, существует ли уже хук с таким ID
	for i, h := range m.hooks {
		if h.ID == hook.ID {
			// Обновляем существующий хук
			m.hooks[i] = hook
			m.logger.WithFields(logrus.Fields{
				"hook_id": hook.ID,
				"name":    hook.Name,
				"event":   hook.Event,
			}).Info("Hook updated")
			return
		}
	}

	// Добавляем новый хук
	m.hooks = append(m.hooks, hook)
	m.logger.WithFields(logrus.Fields{
		"hook_id": hook.ID,
		"name":    hook.Name,
		"event":   hook.Event,
	}).Info("Hook added")
}

// RemoveHook удаляет хук по ID
func (m *Manager) RemoveHook(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, hook := range m.hooks {
		if hook.ID == id {
			// Удаляем хук из списка
			m.hooks = append(m.hooks[:i], m.hooks[i+1:]...)
			m.logger.WithField("hook_id", id).Info("Hook removed")
			return nil
		}
	}

	return fmt.Errorf("хук не найден: %s", id)
}

// GetHook возвращает хук по ID
func (m *Manager) GetHook(id string) (*models.Hook, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, hook := range m.hooks {
		if hook.ID == id {
			return &hook, nil
		}
	}

	return nil, fmt.Errorf("хук не найден: %s", id)
}

// ListHooks возвращает список всех хуков
func (m *Manager) ListHooks() []models.Hook {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Создаем копию списка хуков
	hooks := make([]models.Hook, len(m.hooks))
	copy(hooks, m.hooks)

	return hooks
}

// ExecuteHooks выполняет все хуки для указанного события
func (m *Manager) ExecuteHooks(event string, scanID string) {
	m.mu.RLock()
	// Сначала получаем список хуков для выполнения
	var hooksToExecute []models.Hook
	for _, hook := range m.hooks {
		if hook.Event == event && hook.Enabled {
			hooksToExecute = append(hooksToExecute, hook)
		}
	}
	m.mu.RUnlock()

	// Затем выполняем хуки (вне критической секции)
	for _, hook := range hooksToExecute {
		go m.executeHook(hook, scanID)
	}
}

// executeHook выполняет один хук
func (m *Manager) executeHook(hook models.Hook, scanID string) {
	execution := models.HookExecution{
		ID:        uuid.New().String(),
		HookID:    hook.ID,
		ScanID:    scanID,
		StartedAt: time.Now(),
	}

	m.logger.WithFields(logrus.Fields{
		"execution_id": execution.ID,
		"hook_id":      hook.ID,
		"hook_name":    hook.Name,
		"event":        hook.Event,
		"scan_id":      scanID,
	}).Info("Executing hook")

	// Создаем контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(hook.TimeoutSeconds)*time.Second)
	defer cancel()

	// Выполняем скрипт
	cmd := exec.CommandContext(ctx, hook.ScriptPath, scanID)
	output, err := cmd.CombinedOutput()

	execution.FinishedAt = time.Now()
	execution.Output = string(output)

	if err != nil {
		execution.Status = "failure"
		execution.ErrorMsg = err.Error()
		m.logger.WithFields(logrus.Fields{
			"execution_id": execution.ID,
			"hook_id":      hook.ID,
			"hook_name":    hook.Name,
			"error":        err,
			"output":       string(output),
		}).Error("Hook execution failed")
	} else {
		execution.Status = "success"
		m.logger.WithFields(logrus.Fields{
			"execution_id": execution.ID,
			"hook_id":      hook.ID,
			"hook_name":    hook.Name,
			"output":       string(output),
		}).Info("Hook execution succeeded")
	}

	// Здесь можно сохранить результаты выполнения в БД
	// TODO: Реализовать сохранение результатов выполнения хука
}

// ValidateHook проверяет хук на корректность
func (m *Manager) ValidateHook(hook *models.Hook) error {
	if hook.Name == "" {
		return fmt.Errorf("имя хука не может быть пустым")
	}

	if hook.ScriptPath == "" {
		return fmt.Errorf("путь к скрипту не может быть пустым")
	}

	if hook.TimeoutSeconds <= 0 {
		return fmt.Errorf("таймаут должен быть положительным числом")
	}

	// Проверка события
	validEvents := map[string]bool{
		"on_scan_start":    true,
		"on_scan_complete": true,
		"on_error":         true,
	}

	if !validEvents[hook.Event] {
		return fmt.Errorf("недопустимое событие: %s", hook.Event)
	}

	// Проверка доступности скрипта
	_, err := exec.LookPath(hook.ScriptPath)
	if err != nil {
		return fmt.Errorf("скрипт не найден или не исполняемый: %s", hook.ScriptPath)
	}

	return nil
} 
