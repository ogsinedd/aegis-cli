package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aegis/aegis-cli/pkg/hooks"
	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/aegis/aegis-cli/pkg/scanner"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Handler представляет HTTP-обработчик API агента
type Handler struct {
	scanner     *scanner.Scanner
	hookManager *hooks.Manager
	router      *mux.Router
	logger      *logrus.Logger
	scans       map[string]*models.ScanStatusResponse
}

// NewHandler создает новый обработчик API
func NewHandler(scanner *scanner.Scanner, hookManager *hooks.Manager) http.Handler {
	h := &Handler{
		scanner:     scanner,
		hookManager: hookManager,
		router:      mux.NewRouter(),
		logger:      logrus.New(),
		scans:       make(map[string]*models.ScanStatusResponse),
	}

	// Настройка логгера
	h.logger.SetFormatter(&logrus.JSONFormatter{})

	// Настройка маршрутов
	h.router.HandleFunc("/containers", h.listContainers).Methods("GET")
	h.router.HandleFunc("/scan", h.startScan).Methods("POST")
	h.router.HandleFunc("/scan/{scan_id}", h.getScanStatus).Methods("GET")
	h.router.HandleFunc("/health", h.healthCheck).Methods("GET")

	// Добавляем middleware для логирования запросов
	h.router.Use(h.loggingMiddleware)

	return h.router
}

// loggingMiddleware добавляет логирование запросов
func (h *Handler) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Добавляем уникальный ID запроса
		requestID := uuid.New().String()
		ctx := r.Context()
		r = r.WithContext(ctx)

		// Логируем запрос
		h.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
		}).Info("Request started")

		next.ServeHTTP(w, r)

		// Логируем завершение запроса
		h.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"duration":   time.Since(start).String(),
		}).Info("Request completed")
	})
}

// listContainers возвращает список контейнеров
func (h *Handler) listContainers(w http.ResponseWriter, r *http.Request) {
	containers, err := h.scanner.ListContainers()
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Ошибка получения списка контейнеров: %v", err))
		return
	}

	response := models.ContainerListResponse{
		Containers: containers,
	}

	h.respondWithJSON(w, http.StatusOK, response)
}

// startScan запускает сканирование контейнера
func (h *Handler) startScan(w http.ResponseWriter, r *http.Request) {
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if req.ContainerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Не указан ID контейнера")
		return
	}

	// Генерируем уникальный ID для сканирования
	scanID := uuid.New().String()

	// Получаем информацию о контейнере
	container, err := h.scanner.GetContainer(req.ContainerID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, fmt.Sprintf("Контейнер не найден: %s", req.ContainerID))
		return
	}

	// Создаем запись о сканировании
	scan := &models.ScanStatusResponse{
		ScanID:    scanID,
		Status:    "pending",
		StartedAt: time.Now(),
	}

	// Сохраняем запись о сканировании
	h.scans[scanID] = scan

	// Запускаем хук on_scan_start
	go h.hookManager.ExecuteHooks("on_scan_start", scanID)

	// Запускаем сканирование в горутине
	go func() {
		scan.Status = "running"

		results, err := h.scanner.ScanContainer(container)
		if err != nil {
			scan.Status = "failed"
			scan.ErrorMsg = err.Error()
			// Запускаем хук on_error
			h.hookManager.ExecuteHooks("on_error", scanID)
			return
		}

		finishedAt := time.Now()
		scan.Status = "completed"
		scan.FinishedAt = &finishedAt
		scan.Vulnerabilities = results

		// Запускаем хук on_scan_complete
		h.hookManager.ExecuteHooks("on_scan_complete", scanID)
	}()

	// Отправляем ID сканирования клиенту
	response := models.ScanResponse{
		ScanID: scanID,
	}

	h.respondWithJSON(w, http.StatusAccepted, response)
}

// getScanStatus возвращает статус сканирования
func (h *Handler) getScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	scan, exists := h.scans[scanID]
	if !exists {
		h.respondWithError(w, http.StatusNotFound, fmt.Sprintf("Сканирование не найдено: %s", scanID))
		return
	}

	h.respondWithJSON(w, http.StatusOK, scan)
}

// healthCheck проверяет работоспособность агента
func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	h.respondWithJSON(w, http.StatusOK, response)
}

// respondWithJSON отправляет JSON-ответ
func (h *Handler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		h.logger.WithError(err).Error("Failed to marshal JSON response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// respondWithError отправляет JSON-ответ с ошибкой
func (h *Handler) respondWithError(w http.ResponseWriter, code int, message string) {
	h.respondWithJSON(w, code, map[string]string{"error": message})
} 
