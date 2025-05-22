package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/aegis/aegis-cli/pkg/config"
	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// Store представляет хранилище данных
type Store struct {
	db     *sqlx.DB
	logger *logrus.Logger
	config *config.CliConfig
}

// NewStore создает новое подключение к базе данных
func NewStore(cfg *config.CliConfig, logger *logrus.Logger) (*Store, error) {
	var db *sqlx.DB
	var err error

	if cfg.DatabaseType == "postgresql" {
		db, err = sqlx.Connect("postgres", cfg.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("ошибка подключения к PostgreSQL: %w", err)
		}
	} else if cfg.DatabaseType == "sqlite" {
		db, err = sqlx.Connect("sqlite3", cfg.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("ошибка подключения к SQLite: %w", err)
		}
	} else {
		return nil, fmt.Errorf("неподдерживаемый тип базы данных: %s", cfg.DatabaseType)
	}

	// Настройка соединения
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	store := &Store{
		db:     db,
		logger: logger,
		config: cfg,
	}

	// Инициализация схемы базы данных
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("ошибка инициализации схемы: %w", err)
	}

	return store, nil
}

// initSchema инициализирует схему базы данных
func (s *Store) initSchema() error {
	// Таблица хостов
	_, err := s.db.Exec(`
    CREATE TABLE IF NOT EXISTS hosts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        port INTEGER NOT NULL,
        status TEXT NOT NULL,
        last_seen TIMESTAMP,
        created_at TIMESTAMP NOT NULL,
        description TEXT
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы hosts: %w", err)
	}

	// Таблица контейнеров
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS containers (
        id TEXT PRIMARY KEY,
        host_id TEXT NOT NULL,
        name TEXT NOT NULL,
        image TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL,
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы containers: %w", err)
	}

	// Таблица сканирований
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        host_id TEXT NOT NULL,
        container_id TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TIMESTAMP NOT NULL,
        finished_at TIMESTAMP,
        result_path TEXT,
        error_msg TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY (container_id) REFERENCES containers(id) ON DELETE CASCADE
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы scans: %w", err)
	}

	// Таблица уязвимостей
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        container_id TEXT NOT NULL,
        host_id TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        package TEXT NOT NULL,
        installed_version TEXT,
        fixed_version TEXT,
        "references" TEXT,
        discovered_at TIMESTAMP NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        FOREIGN KEY (container_id) REFERENCES containers(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы vulnerabilities: %w", err)
	}

	// Таблица хуков
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS hooks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        event TEXT NOT NULL,
        script_path TEXT NOT NULL,
        timeout_seconds INTEGER NOT NULL,
        enabled BOOLEAN NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы hooks: %w", err)
	}

	// Таблица выполнений хуков
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS hook_executions (
        id TEXT PRIMARY KEY,
        hook_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        status TEXT NOT NULL,
        output TEXT,
        error_msg TEXT,
        started_at TIMESTAMP NOT NULL,
        finished_at TIMESTAMP NOT NULL,
        FOREIGN KEY (hook_id) REFERENCES hooks(id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы hook_executions: %w", err)
	}

	// Таблица стратегий восстановления
	_, err = s.db.Exec(`
    CREATE TABLE IF NOT EXISTS remediation_strategies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        estimated_downtime TEXT NOT NULL,
        command TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP NOT NULL
    )
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания таблицы remediation_strategies: %w", err)
	}

	// Добавление начальных стратегий восстановления
	_, err = s.db.Exec(`
    INSERT OR IGNORE INTO remediation_strategies (id, name, type, estimated_downtime, command, description, created_at)
    VALUES 
        ('strategy-1', 'Горячее обновление', 'hot-patch', 'Нет простоя', 'apt-get update && apt-get upgrade -y {{package}}', 'Обновление пакета без перезапуска контейнера', CURRENT_TIMESTAMP),
        ('strategy-2', 'Перезапуск', 'restart', '10-30 секунд', 'docker restart {{container_id}}', 'Перезапуск контейнера после обновления образа', CURRENT_TIMESTAMP),
        ('strategy-3', 'Постепенное обновление', 'rolling-update', '1-5 минут на узел', 'kubectl rollout restart deployment/{{deployment_name}}', 'Постепенное обновление контейнеров в Kubernetes', CURRENT_TIMESTAMP)
    `)
	if err != nil {
		return fmt.Errorf("ошибка создания начальных стратегий восстановления: %w", err)
	}

	return nil
}

// Close закрывает соединение с базой данных
func (s *Store) Close() error {
	return s.db.Close()
}

// Hosts

// AddHost добавляет новый хост
func (s *Store) AddHost(host *models.Host) error {
	_, err := s.db.NamedExec(`
    INSERT INTO hosts (id, name, address, port, status, last_seen, created_at, description)
    VALUES (:id, :name, :address, :port, :status, :last_seen, :created_at, :description)
    `, host)
	return err
}

// GetHost получает хост по ID
func (s *Store) GetHost(id string) (*models.Host, error) {
	var host models.Host
	err := s.db.Get(&host, "SELECT * FROM hosts WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("хост не найден: %s", id)
		}
		return nil, err
	}
	return &host, nil
}

// ListHosts возвращает список всех хостов
func (s *Store) ListHosts() ([]models.Host, error) {
	var hosts []models.Host
	err := s.db.Select(&hosts, "SELECT * FROM hosts ORDER BY created_at DESC")
	return hosts, err
}

// UpdateHost обновляет хост
func (s *Store) UpdateHost(host *models.Host) error {
	_, err := s.db.NamedExec(`
    UPDATE hosts 
    SET name = :name, address = :address, port = :port, status = :status, 
        last_seen = :last_seen, description = :description
    WHERE id = :id
    `, host)
	return err
}

// DeleteHost удаляет хост
func (s *Store) DeleteHost(id string) error {
	_, err := s.db.Exec("DELETE FROM hosts WHERE id = $1", id)
	return err
}

// Containers

// AddContainer добавляет новый контейнер
func (s *Store) AddContainer(container *models.Container) error {
	_, err := s.db.NamedExec(`
    INSERT INTO containers (id, host_id, name, image, status, created_at, updated_at)
    VALUES (:id, :host_id, :name, :image, :status, :created_at, :updated_at)
    `, container)
	return err
}

// GetContainer получает контейнер по ID
func (s *Store) GetContainer(id string) (*models.Container, error) {
	var container models.Container

	// Сначала пробуем найти по точному совпадению ID
	err := s.db.Get(&container, "SELECT * FROM containers WHERE id = $1", id)
	if err == nil {
		return &container, nil
	}

	// Если точное совпадение не найдено, пробуем найти по частичному ID
	if err == sql.ErrNoRows && len(id) >= 3 {
		// Ищем контейнеры с ID, начинающимся с указанной строки
		var containers []models.Container
		err = s.db.Select(&containers, "SELECT * FROM containers WHERE id LIKE $1", id+"%")
		if err != nil {
			return nil, err
		}

		// Проверяем, найден ли ровно один контейнер
		if len(containers) == 0 {
			return nil, fmt.Errorf("контейнер не найден: %s", id)
		}
		if len(containers) > 1 {
			// Возвращаем ошибку с перечислением найденных ID
			var foundIDs []string
			for _, c := range containers {
				// Берем первые 12 символов, чтобы было удобнее
				shortID := c.ID
				if len(c.ID) > 12 {
					shortID = c.ID[:12]
				}
				foundIDs = append(foundIDs, fmt.Sprintf("%s (%s)", shortID, c.Name))
			}
			return nil, fmt.Errorf("найдено несколько контейнеров с ID, начинающимся с %s: %s",
				id, strings.Join(foundIDs, ", "))
		}

		// Найден ровно один контейнер
		return &containers[0], nil
	}

	// Возвращаем исходную ошибку, если поиск не удался
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("контейнер не найден: %s", id)
	}
	return nil, err
}

// ListContainers возвращает список контейнеров для хоста
func (s *Store) ListContainers(hostID string) ([]models.Container, error) {
	var containers []models.Container
	err := s.db.Select(&containers, "SELECT * FROM containers WHERE host_id = $1 ORDER BY created_at DESC", hostID)
	return containers, err
}

// UpdateContainer обновляет контейнер
func (s *Store) UpdateContainer(container *models.Container) error {
	_, err := s.db.NamedExec(`
    UPDATE containers 
    SET name = :name, image = :image, status = :status, updated_at = :updated_at 
    WHERE id = :id
    `, container)
	return err
}

// DeleteContainer удаляет контейнер
func (s *Store) DeleteContainer(id string) error {
	_, err := s.db.Exec("DELETE FROM containers WHERE id = $1", id)
	return err
}

// Scans

// AddScan добавляет новое сканирование
func (s *Store) AddScan(scan *models.Scan) error {
	_, err := s.db.NamedExec(`
    INSERT INTO scans (id, host_id, container_id, status, started_at, finished_at, result_path, error_msg)
    VALUES (:id, :host_id, :container_id, :status, :started_at, :finished_at, :result_path, :error_msg)
    `, scan)
	return err
}

// GetScan получает сканирование по ID
func (s *Store) GetScan(id string) (*models.Scan, error) {
	var scan models.Scan
	err := s.db.Get(&scan, "SELECT * FROM scans WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("сканирование не найдено: %s", id)
		}
		return nil, err
	}
	return &scan, nil
}

// ListScans возвращает список сканирований
func (s *Store) ListScans(hostID, containerID string) ([]models.Scan, error) {
	var query string
	var args []interface{}

	if hostID != "" && containerID != "" {
		query = "SELECT * FROM scans WHERE host_id = $1 AND container_id = $2 ORDER BY started_at DESC"
		args = []interface{}{hostID, containerID}
	} else if hostID != "" {
		query = "SELECT * FROM scans WHERE host_id = $1 ORDER BY started_at DESC"
		args = []interface{}{hostID}
	} else if containerID != "" {
		query = "SELECT * FROM scans WHERE container_id = $1 ORDER BY started_at DESC"
		args = []interface{}{containerID}
	} else {
		query = "SELECT * FROM scans ORDER BY started_at DESC"
	}

	var scans []models.Scan
	err := s.db.Select(&scans, query, args...)
	return scans, err
}

// UpdateScan обновляет сканирование
func (s *Store) UpdateScan(scan *models.Scan) error {
	_, err := s.db.NamedExec(`
    UPDATE scans 
    SET status = :status, finished_at = :finished_at, result_path = :result_path, error_msg = :error_msg
    WHERE id = :id
    `, scan)
	return err
}

// DeleteScan удаляет сканирование
func (s *Store) DeleteScan(id string) error {
	_, err := s.db.Exec("DELETE FROM scans WHERE id = $1", id)
	return err
}

// Vulnerabilities

// AddVulnerability добавляет новую уязвимость
func (s *Store) AddVulnerability(vulnerability *models.Vulnerability) error {
	_, err := s.db.NamedExec(`
    INSERT INTO vulnerabilities (
        id, scan_id, container_id, host_id, vulnerability_id, severity, title, 
        description, package, installed_version, fixed_version, "references", discovered_at
    ) VALUES (
        :id, :scan_id, :container_id, :host_id, :vulnerability_id, :severity, :title, 
        :description, :package, :installed_version, :fixed_version, :references, :discovered_at
    )
    `, vulnerability)
	return err
}

// GetVulnerability получает уязвимость по ID
func (s *Store) GetVulnerability(id string) (*models.Vulnerability, error) {
	var vulnerability models.Vulnerability
	err := s.db.Get(&vulnerability, "SELECT * FROM vulnerabilities WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("уязвимость не найдена: %s", id)
		}
		return nil, err
	}
	return &vulnerability, nil
}

// ListVulnerabilities возвращает список уязвимостей
func (s *Store) ListVulnerabilities(hostID, containerID, scanID string, severity string) ([]models.Vulnerability, error) {
	var query string
	var args []interface{}
	var conditions []string

	if hostID != "" {
		conditions = append(conditions, "host_id = ?")
		args = append(args, hostID)
	}
	if containerID != "" {
		conditions = append(conditions, "container_id = ?")
		args = append(args, containerID)
	}
	if scanID != "" {
		conditions = append(conditions, "scan_id = ?")
		args = append(args, scanID)
	}
	if severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}

	query = "SELECT * FROM vulnerabilities"
	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			query += " AND " + conditions[i]
		}
	}
	query += " ORDER BY discovered_at DESC"

	// Заменяем ? на $1, $2 и т.д. для PostgreSQL
	if s.config.DatabaseType == "postgresql" {
		for i := 1; i <= len(args); i++ {
			query = sqlx.Rebind(sqlx.DOLLAR, query)
		}
	}

	var vulnerabilities []models.Vulnerability
	err := s.db.Select(&vulnerabilities, query, args...)
	return vulnerabilities, err
}

// DeleteVulnerability удаляет уязвимость
func (s *Store) DeleteVulnerability(id string) error {
	_, err := s.db.Exec("DELETE FROM vulnerabilities WHERE id = $1", id)
	return err
}

// Hooks

// AddHook добавляет новый хук
func (s *Store) AddHook(hook *models.Hook) error {
	_, err := s.db.NamedExec(`
    INSERT INTO hooks (id, name, event, script_path, timeout_seconds, enabled, created_at, updated_at)
    VALUES (:id, :name, :event, :script_path, :timeout_seconds, :enabled, :created_at, :updated_at)
    `, hook)
	return err
}

// GetHook получает хук по ID
func (s *Store) GetHook(id string) (*models.Hook, error) {
	var hook models.Hook
	err := s.db.Get(&hook, "SELECT * FROM hooks WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("хук не найден: %s", id)
		}
		return nil, err
	}
	return &hook, nil
}

// ListHooks возвращает список хуков
func (s *Store) ListHooks() ([]models.Hook, error) {
	var hooks []models.Hook
	err := s.db.Select(&hooks, "SELECT * FROM hooks ORDER BY created_at DESC")
	return hooks, err
}

// UpdateHook обновляет хук
func (s *Store) UpdateHook(hook *models.Hook) error {
	_, err := s.db.NamedExec(`
    UPDATE hooks 
    SET name = :name, event = :event, script_path = :script_path, 
        timeout_seconds = :timeout_seconds, enabled = :enabled, updated_at = :updated_at
    WHERE id = :id
    `, hook)
	return err
}

// DeleteHook удаляет хук
func (s *Store) DeleteHook(id string) error {
	_, err := s.db.Exec("DELETE FROM hooks WHERE id = $1", id)
	return err
}

// HookExecutions

// AddHookExecution добавляет новое выполнение хука
func (s *Store) AddHookExecution(execution *models.HookExecution) error {
	_, err := s.db.NamedExec(`
    INSERT INTO hook_executions (id, hook_id, scan_id, status, output, error_msg, started_at, finished_at)
    VALUES (:id, :hook_id, :scan_id, :status, :output, :error_msg, :started_at, :finished_at)
    `, execution)
	return err
}

// GetHookExecution получает выполнение хука по ID
func (s *Store) GetHookExecution(id string) (*models.HookExecution, error) {
	var execution models.HookExecution
	err := s.db.Get(&execution, "SELECT * FROM hook_executions WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("выполнение хука не найдено: %s", id)
		}
		return nil, err
	}
	return &execution, nil
}

// ListHookExecutions возвращает список выполнений хуков
func (s *Store) ListHookExecutions(hookID, scanID string) ([]models.HookExecution, error) {
	var query string
	var args []interface{}

	if hookID != "" && scanID != "" {
		query = "SELECT * FROM hook_executions WHERE hook_id = $1 AND scan_id = $2 ORDER BY started_at DESC"
		args = []interface{}{hookID, scanID}
	} else if hookID != "" {
		query = "SELECT * FROM hook_executions WHERE hook_id = $1 ORDER BY started_at DESC"
		args = []interface{}{hookID}
	} else if scanID != "" {
		query = "SELECT * FROM hook_executions WHERE scan_id = $1 ORDER BY started_at DESC"
		args = []interface{}{scanID}
	} else {
		query = "SELECT * FROM hook_executions ORDER BY started_at DESC"
	}

	var executions []models.HookExecution
	err := s.db.Select(&executions, query, args...)
	return executions, err
}

// RemediationStrategies

// GetRemediationStrategy получает стратегию восстановления по ID
func (s *Store) GetRemediationStrategy(id string) (*models.RemediationStrategy, error) {
	var strategy models.RemediationStrategy
	err := s.db.Get(&strategy, "SELECT * FROM remediation_strategies WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("стратегия восстановления не найдена: %s", id)
		}
		return nil, err
	}
	return &strategy, nil
}

// ListRemediationStrategies возвращает список стратегий восстановления
func (s *Store) ListRemediationStrategies() ([]models.RemediationStrategy, error) {
	var strategies []models.RemediationStrategy
	err := s.db.Select(&strategies, "SELECT * FROM remediation_strategies")
	return strategies, err
}
