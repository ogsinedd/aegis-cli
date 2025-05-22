package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// TrivyVulnerability представляет уязвимость, найденную Trivy
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	PkgID            string   `json:"PkgID,omitempty"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References,omitempty"`
	Layer            struct {
		DiffID string `json:"DiffID"`
	} `json:"Layer,omitempty"`
}

// TrivyResult представляет результат сканирования для одного компонента
type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities,omitempty"`
}

// TrivyReport представляет полный отчет сканирования Trivy
type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      interface{}   `json:"Metadata"`
	Results       []TrivyResult `json:"Results"`
}

// Scanner представляет сканер контейнеров
type Scanner struct {
	dockerClient     *client.Client
	logger           *logrus.Logger
	resultsDir       string
	concurrency      int
	dockerSocketPath string
	sem              chan struct{} // Семафор для ограничения параллелизма
}

// NewScanner создает новый сканер
func NewScanner(concurrency int, dockerSocketPath string) *Scanner {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Настройка Docker клиента
	cli, err := client.NewClientWithOpts(
		client.WithHost(fmt.Sprintf("unix://%s", dockerSocketPath)),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create Docker client")
	}

	// Создаем каталог для результатов сканирования
	resultsDir := "/var/lib/aegis-agent/results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		logger.WithError(err).Fatal("Failed to create results directory")
	}

	return &Scanner{
		dockerClient:     cli,
		logger:           logger,
		resultsDir:       resultsDir,
		concurrency:      concurrency,
		dockerSocketPath: dockerSocketPath,
		sem:              make(chan struct{}, concurrency),
	}
}

// ListContainers возвращает список контейнеров
func (s *Scanner) ListContainers() ([]models.Container, error) {
	ctx := context.Background()
	containers, err := s.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("ошибка получения списка контейнеров: %w", err)
	}

	var result []models.Container
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			// Docker API возвращает имена с префиксом "/", удаляем его
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		container := models.Container{
			ID:        c.ID,
			HostID:    "local", // Временно используем "local" как ID хоста
			Name:      name,
			Image:     c.Image,
			Status:    c.Status,
			CreatedAt: time.Unix(c.Created, 0),
			UpdatedAt: time.Now(),
		}
		result = append(result, container)
	}

	return result, nil
}

// GetContainer возвращает информацию о контейнере по ID
func (s *Scanner) GetContainer(id string) (*models.Container, error) {
	ctx := context.Background()

	// Сначала пробуем найти контейнер по точному ID
	c, err := s.dockerClient.ContainerInspect(ctx, id)
	if err == nil {
		// Контейнер найден, возвращаем информацию
		createdTime, _ := time.Parse(time.RFC3339, c.Created)

		container := &models.Container{
			ID:        c.ID,
			HostID:    "local", // Временно используем "local" как ID хоста
			Name:      strings.TrimPrefix(c.Name, "/"),
			Image:     c.Config.Image,
			Status:    c.State.Status,
			CreatedAt: createdTime,
			UpdatedAt: time.Now(),
		}

		return container, nil
	}

	// Если точное совпадение не найдено, пробуем найти по частичному ID
	// Получаем список всех контейнеров
	containers, err := s.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("ошибка получения списка контейнеров: %w", err)
	}

	// Ищем контейнеры, ID которых начинается с указанного префикса
	var matchingContainers []types.Container
	for _, cont := range containers {
		if strings.HasPrefix(cont.ID, id) {
			matchingContainers = append(matchingContainers, cont)
		}
	}

	// Проверяем результаты поиска
	if len(matchingContainers) == 0 {
		return nil, fmt.Errorf("контейнер не найден: %s", id)
	}

	if len(matchingContainers) > 1 {
		// Найдено несколько совпадений, возвращаем ошибку с перечислением
		var foundIDs []string
		for _, cont := range matchingContainers {
			name := ""
			if len(cont.Names) > 0 {
				name = strings.TrimPrefix(cont.Names[0], "/")
			}
			shortID := cont.ID
			if len(cont.ID) > 12 {
				shortID = cont.ID[:12]
			}
			foundIDs = append(foundIDs, fmt.Sprintf("%s (%s)", shortID, name))
		}
		return nil, fmt.Errorf("найдено несколько контейнеров с ID, начинающимся с %s: %s",
			id, strings.Join(foundIDs, ", "))
	}

	// Найден ровно один контейнер, получаем детальную информацию о нём
	matchedContainer := matchingContainers[0]
	c, err = s.dockerClient.ContainerInspect(ctx, matchedContainer.ID)
	if err != nil {
		return nil, fmt.Errorf("ошибка получения информации о контейнере: %w", err)
	}

	// Преобразуем время создания из строки в time.Time
	createdTime, _ := time.Parse(time.RFC3339, c.Created)

	container := &models.Container{
		ID:        c.ID,
		HostID:    "local", // Временно используем "local" как ID хоста
		Name:      strings.TrimPrefix(c.Name, "/"),
		Image:     c.Config.Image,
		Status:    c.State.Status,
		CreatedAt: createdTime,
		UpdatedAt: time.Now(),
	}

	return container, nil
}

// ScanContainer сканирует контейнер
func (s *Scanner) ScanContainer(container *models.Container) ([]models.Vulnerability, error) {
	// Получаем семафор для ограничения параллелизма
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.logger.WithFields(logrus.Fields{
		"container_id": container.ID,
		"image":        container.Image,
	}).Info("Starting container scan")

	// Генерируем уникальный ID для результатов сканирования
	scanID := uuid.New().String()
	resultsFile := filepath.Join(s.resultsDir, fmt.Sprintf("%s.json", scanID))

	// Запускаем Trivy для сканирования образа контейнера
	cmd := exec.Command("trivy", "image", "--format", "json", "--output", resultsFile, container.Image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"container_id": container.ID,
			"image":        container.Image,
			"error":        err,
			"output":       string(output),
		}).Error("Scan failed")
		return nil, fmt.Errorf("ошибка сканирования: %w: %s", err, string(output))
	}

	// Парсим результаты сканирования
	vulnerabilities, err := s.parseResults(resultsFile, container.ID, container.HostID)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга результатов: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"container_id":    container.ID,
		"image":           container.Image,
		"vulnerabilities": len(vulnerabilities),
		"results_file":    resultsFile,
	}).Info("Scan completed")

	return vulnerabilities, nil
}

// parseResults парсит результаты сканирования Trivy
func (s *Scanner) parseResults(resultsFile, containerID, hostID string) ([]models.Vulnerability, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла результатов: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("ошибка разбора JSON: %w", err)
	}

	var vulnerabilities []models.Vulnerability
	for _, result := range report.Results {
		if result.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			// Пропускаем, если нет ID уязвимости
			if vuln.VulnerabilityID == "" {
				continue
			}

			// Генерируем уникальный ID для записи в БД
			vulnID := uuid.New().String()

			// Определяем имя пакета
			pkgName := vuln.PkgName
			if pkgName == "" && vuln.PkgID != "" {
				parts := strings.Split(vuln.PkgID, "@")
				if len(parts) > 0 {
					pkgName = parts[0]
				}
			}

			// Собираем ссылки в строку с разделителями
			refs := ""
			if len(vuln.References) > 0 {
				refs = strings.Join(vuln.References, ",")
			}

			// Создаем запись об уязвимости
			vulnerability := models.Vulnerability{
				ID:               vulnID,
				ScanID:           filepath.Base(resultsFile[:len(resultsFile)-5]), // Удаляем расширение .json
				ContainerID:      containerID,
				HostID:           hostID,
				VulnerabilityID:  vuln.VulnerabilityID,
				Severity:         vuln.Severity,
				Title:            vuln.Title,
				Description:      vuln.Description,
				Package:          pkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				References:       refs,
				DiscoveredAt:     time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities, nil
}

// ScanAllContainers сканирует все контейнеры на хосте
func (s *Scanner) ScanAllContainers() (map[string][]models.Vulnerability, error) {
	containers, err := s.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения списка контейнеров: %w", err)
	}

	results := make(map[string][]models.Vulnerability)
	var wg sync.WaitGroup
	var mu sync.Mutex // Mutex для защиты доступа к results

	for _, container := range containers {
		wg.Add(1)
		go func(c models.Container) {
			defer wg.Done()

			vulnerabilities, err := s.ScanContainer(&c)
			if err != nil {
				s.logger.WithFields(logrus.Fields{
					"container_id": c.ID,
					"image":        c.Image,
					"error":        err,
				}).Error("Failed to scan container")
				return
			}

			mu.Lock()
			results[c.ID] = vulnerabilities
			mu.Unlock()
		}(container)
	}

	wg.Wait()
	return results, nil
}

// ExportResultsToCSV экспортирует результаты сканирования в CSV
func (s *Scanner) ExportResultsToCSV(vulnerabilities []models.Vulnerability, outputFile string) error {
	// Создаем каталог для файла, если он не существует
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("ошибка создания каталога: %w", err)
	}

	// Открываем файл для записи
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("ошибка создания файла: %w", err)
	}
	defer file.Close()

	// Записываем заголовок CSV
	header := "ID,VulnerabilityID,Severity,Title,Package,InstalledVersion,FixedVersion,Description\n"
	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("ошибка записи заголовка: %w", err)
	}

	// Записываем данные
	for _, v := range vulnerabilities {
		// Экранируем двойные кавычки в полях
		title := strings.ReplaceAll(v.Title, "\"", "\"\"")
		description := strings.ReplaceAll(v.Description, "\"", "\"\"")

		line := fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			v.ID, v.VulnerabilityID, v.Severity, title, v.Package, v.InstalledVersion, v.FixedVersion, description)
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("ошибка записи данных: %w", err)
		}
	}

	return nil
}
