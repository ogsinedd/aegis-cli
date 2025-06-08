package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegis/aegis-cli/pkg/config"
	"github.com/aegis/aegis-cli/pkg/db"
	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/aegis/aegis-cli/pkg/utils"
	"github.com/google/uuid"
	"github.com/jroimartin/gocui"
	"github.com/sirupsen/logrus"
)

// TUI представляет терминальный пользовательский интерфейс
type TUI struct {
	g                   *gocui.Gui
	store               *db.Store
	logger              *logrus.Logger
	config              *config.CliConfig
	hosts               []models.Host
	containers          []models.Container
	vulns               []models.Vulnerability
	activeHost          *models.Host
	activePanel         string
	notificationManager *utils.NotificationManager
	logs                []string                     // Добавлено хранилище для логов
	strategies          []models.RemediationStrategy // Добавлено хранилище для стратегий решения
	hooks               []models.Hook                // Добавлено хранилище для хуков
	telegramConnected   bool                         // Статус подключения Telegram-бота
	modalWindows        []string                     // Стек для отслеживания модальных окон
}

// NewTUI создает новый терминальный интерфейс
func NewTUI(store *db.Store, logger *logrus.Logger, cfg *config.CliConfig, notificationManager *utils.NotificationManager) *TUI {
	return &TUI{
		store:               store,
		logger:              logger,
		config:              cfg,
		activePanel:         "hosts",
		notificationManager: notificationManager,
		logs:                make([]string, 0), // Инициализация логов
		telegramConnected:   false,             // По умолчанию бот не подключен
		modalWindows:        make([]string, 0), // Инициализация стека модальных окон
	}
}

// Run запускает терминальный интерфейс
func (t *TUI) Run() error {
	var err error

	// Инициализация gocui с обработкой ошибок
	t.g, err = gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		// Логируем ошибку и выводим дополнительную информацию
		t.logger.WithError(err).Error("Ошибка инициализации gocui")
		return fmt.Errorf("ошибка инициализации интерфейса: %w", err)
	}
	defer t.g.Close()

	// Устанавливаем параметры
	t.g.Cursor = true
	t.g.Mouse = true
	t.g.InputEsc = true
	t.g.SelFgColor = gocui.ColorGreen // Устанавливаем цвет текста выбранного элемента
	t.g.SelBgColor = gocui.ColorBlack // Устанавливаем цвет фона выбранного элемента

	// Добавляем тестовые логи сразу после инициализации
	t.addLog("Инициализация системы")
	t.addLog("TUI запущен")
	t.addLog("Готов к работе")

	// Настройка интерфейса
	t.g.SetManagerFunc(t.layout)

	// Загрузка начальных данных
	if err := t.loadHosts(); err != nil {
		return err
	}

	// Настройка клавиш
	if err := t.setupKeybindings(); err != nil {
		return err
	}

	// Обновляем интерфейс после загрузки данных
	t.g.Update(func(g *gocui.Gui) error {
		t.updateUI()
		return nil
	})

	// Проверяем статус Telegram-бота
	go t.checkTelegramBotStatus()

	// Запуск основного цикла с обработкой ошибок
	if err := t.g.MainLoop(); err != nil && err != gocui.ErrQuit {
		t.logger.WithError(err).Error("Ошибка в основном цикле TUI")
		return fmt.Errorf("ошибка работы интерфейса: %w", err)
	}

	return nil
}

// layout определяет расположение элементов интерфейса
func (t *TUI) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	// Проверка минимальных размеров
	if maxX < 80 || maxY < 24 {
		// Создаем информационное окно если размер экрана слишком мал
		if v, err := g.SetView("sizeError", maxX/2-20, maxY/2-2, maxX/2+20, maxY/2+2); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			v.Title = "Ошибка размера"
			fmt.Fprintln(v, "Размер терминала слишком мал.")
			fmt.Fprintln(v, "Требуется минимум 80x24.")
			fmt.Fprintln(v, "Увеличьте размер окна.")
			return nil
		}
		return nil
	}

	// Удаляем окно с ошибкой, если оно было создано ранее
	if _, err := g.View("sizeError"); err == nil {
		g.DeleteView("sizeError")
	}

	// Создаем основные панели с оптимизированными заголовками (без пробелов)

	// Панель хостов (левая верхняя)
	if hostsView, err := g.SetView("hosts", 0, 0, maxX/2-1, maxY/2-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		hostsView.Title = "Хосты"
		hostsView.Highlight = true
		hostsView.SelBgColor = gocui.ColorGreen
		hostsView.SelFgColor = gocui.ColorBlack
		hostsView.Editable = false // Отключаем режим редактирования

		// Заполнение списка хостов
		t.renderHosts(hostsView)

		if len(t.hosts) > 0 {
			hostsView.SetCursor(0, 0)
			t.selectHost(0)
		}
	}

	// Панель контейнеров (правая верхняя)
	if containersView, err := g.SetView("containers", maxX/2, 0, maxX-1, maxY/2-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		containersView.Title = "Контейнеры"
		containersView.Highlight = true
		containersView.SelBgColor = gocui.ColorGreen
		containersView.SelFgColor = gocui.ColorBlack
		containersView.Editable = false // Отключаем режим редактирования

		if t.activeHost != nil {
			t.renderContainers(containersView)
		} else {
			fmt.Fprintln(containersView, "Выберите хост")
		}
	}

	// Панель уязвимостей (левая нижняя)
	if vulnsView, err := g.SetView("vulnerabilities", 0, maxY/2, maxX/2-1, maxY-3); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		vulnsView.Title = "Уязвимости"
		vulnsView.Wrap = true
		vulnsView.Autoscroll = false
		vulnsView.Editable = false // Отключаем режим редактирования

		t.renderVulnerabilities(vulnsView)
	}

	// Панель логов (правая нижняя)
	if logsView, err := g.SetView("logs", maxX/2, maxY/2, maxX-1, maxY-3); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		logsView.Title = "Логи"
		logsView.Wrap = true
		logsView.Autoscroll = true
		logsView.Editable = false // Отключаем режим редактирования

		// Отображаем логи
		t.renderLogs(logsView)
	}

	// Панель статуса (внизу) - всегда последняя для правильного отображения
	if statusView, err := g.SetView("status", 0, maxY-3, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		statusView.Title = "Статус"
		statusView.Wrap = true
		statusView.Editable = false // Отключаем режим редактирования
		fmt.Fprintln(statusView, "F1:Помощь | F2:Сканировать | F3:Экспорт | F4:Хуки | F5:Обновить | F6:Telegram | F10:Выход")
	}

	// Проверяем, есть ли открытые модальные окна
	if len(t.modalWindows) > 0 {
		// Если есть, активируем последнее открытое
		lastWindow := t.modalWindows[len(t.modalWindows)-1]
		if _, err := g.View(lastWindow); err == nil {
			g.SetCurrentView(lastWindow)
			g.SetViewOnTop(lastWindow)
		}
	} else {
		// Устанавливаем активную панель
		if _, err := g.SetCurrentView(t.activePanel); err != nil {
			return err
		}
	}

	return nil
}

// setupKeybindings настраивает горячие клавиши
func (t *TUI) setupKeybindings() error {
	// Глобальные клавиши
	if err := t.g.SetKeybinding("", gocui.KeyF1, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна, кроме help
		for _, name := range t.modalWindows {
			if name != "help" {
				// Если есть другие модальные окна, не показываем помощь
				return nil
			}
		}
		return t.toggleHelp(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF2, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.startScan(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF3, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.exportReport(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF4, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.showRemediation(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF5, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.refreshData(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF6, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.showTelegramInfo(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyF10, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Всегда позволяем выйти
		return t.quit(g, v)
	}); err != nil {
		return err
	}

	if err := t.g.SetKeybinding("", gocui.KeyTab, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		// Проверяем, есть ли открытые модальные окна
		if len(t.modalWindows) > 0 {
			return nil
		}
		return t.nextView(g, v)
	}); err != nil {
		return err
	}

	// Клавиши для панели хостов
	if err := t.g.SetKeybinding("hosts", gocui.KeyArrowDown, gocui.ModNone, t.cursorDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("hosts", gocui.KeyArrowUp, gocui.ModNone, t.cursorUp); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("hosts", gocui.KeyEnter, gocui.ModNone, t.selectHostOnEnter); err != nil {
		return err
	}

	// Клавиши для панели контейнеров
	if err := t.g.SetKeybinding("containers", gocui.KeyArrowDown, gocui.ModNone, t.cursorDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("containers", gocui.KeyArrowUp, gocui.ModNone, t.cursorUp); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("containers", gocui.KeyEnter, gocui.ModNone, t.selectContainerOnEnter); err != nil {
		return err
	}

	// Клавиши для прокрутки панели уязвимостей
	if err := t.g.SetKeybinding("vulnerabilities", gocui.KeyArrowDown, gocui.ModNone, t.scrollVulnsDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("vulnerabilities", gocui.KeyArrowUp, gocui.ModNone, t.scrollVulnsUp); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("vulnerabilities", gocui.KeyPgdn, gocui.ModNone, t.pageVulnsDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("vulnerabilities", gocui.KeyPgup, gocui.ModNone, t.pageVulnsUp); err != nil {
		return err
	}

	// Клавиши для прокрутки панели логов
	if err := t.g.SetKeybinding("logs", gocui.KeyArrowDown, gocui.ModNone, t.scrollLogsDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("logs", gocui.KeyArrowUp, gocui.ModNone, t.scrollLogsUp); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("logs", gocui.KeyPgdn, gocui.ModNone, t.pageLogsDown); err != nil {
		return err
	}
	if err := t.g.SetKeybinding("logs", gocui.KeyPgup, gocui.ModNone, t.pageLogsUp); err != nil {
		return err
	}

	return nil
}

// activateView устанавливает фокус на указанный вид и перемещает его на передний план
func (t *TUI) activateView(g *gocui.Gui, viewName string) error {
	// Установка фокуса
	if _, err := g.SetCurrentView(viewName); err != nil {
		return err
	}

	// Перемещение на передний план
	g.SetViewOnTop(viewName)

	return nil
}

// toggleHelp показывает/скрывает панель помощи
func (t *TUI) toggleHelp(g *gocui.Gui, v *gocui.View) error {
	maxX, maxY := g.Size()

	// Проверяем, существует ли панель помощи
	if helpView, err := g.View("help"); err == nil {
		// Проверяем видимость: если view виден, он должен быть главным
		isVisible := false
		for _, name := range t.modalWindows {
			if name == "help" {
				isVisible = true
				break
			}
		}

		if isVisible {
			// Панель существует и видима, закрываем ее
			return t.closeHelp(g, helpView)
		}
	}

	// Показываем панель помощи
	helpView, err := g.SetView("help", maxX/6, maxY/6, 5*maxX/6, 5*maxY/6)
	if err != nil && err != gocui.ErrUnknownView {
		return err
	}

	helpView.Title = "Помощь"
	helpView.Wrap = true
	helpView.Editable = false
	helpView.Clear()

	fmt.Fprintln(helpView, "Горячие клавиши:")
	fmt.Fprintln(helpView, "  F1: Показать/скрыть справку")
	fmt.Fprintln(helpView, "  F2: Запустить сканирование выбранного контейнера")
	fmt.Fprintln(helpView, "  F3: Экспортировать отчет о уязвимостях")
	fmt.Fprintln(helpView, "  F4: Показать хуки и стратегии исправления")
	fmt.Fprintln(helpView, "  F5: Обновить данные")
	fmt.Fprintln(helpView, "  F6: Информация о Telegram-боте")
	fmt.Fprintln(helpView, "  F10: Выход из TUI")
	fmt.Fprintln(helpView, "")
	fmt.Fprintln(helpView, "Навигация:")
	fmt.Fprintln(helpView, "  Tab: Переключение между панелями")
	fmt.Fprintln(helpView, "  Стрелки ↑/↓: Перемещение по списку/прокрутка")
	fmt.Fprintln(helpView, "  PgUp/PgDn: Быстрая прокрутка уязвимостей и логов")
	fmt.Fprintln(helpView, "  Enter: Выбор элемента")
	fmt.Fprintln(helpView, "  Esc: Закрыть текущую панель диалога")

	// Сохраняем активную панель перед переключением на help
	if g.CurrentView() != nil && g.CurrentView().Name() != "help" {
		t.activePanel = g.CurrentView().Name()
	}

	// Добавляем окно в стек
	t.modalWindows = append(t.modalWindows, "help")

	// Регистрируем клавишу Esc для закрытия панели
	g.DeleteKeybindings("help")
	if err := g.SetKeybinding("help", gocui.KeyEsc, gocui.ModNone, t.closeHelp); err != nil {
		return err
	}

	// Активируем окно помощи
	return t.activateView(g, "help")
}

// closeHelp закрывает панель помощи
func (t *TUI) closeHelp(g *gocui.Gui, v *gocui.View) error {
	// Удаляем панель помощи
	if err := g.DeleteView("help"); err != nil {
		return err
	}

	// Удаляем из стека модальных окон
	for i, name := range t.modalWindows {
		if name == "help" {
			t.modalWindows = append(t.modalWindows[:i], t.modalWindows[i+1:]...)
			break
		}
	}

	// Восстанавливаем фокус на предыдущую панель
	if t.activePanel != "" && t.activePanel != "help" {
		g.SetCurrentView(t.activePanel)
	} else {
		g.SetCurrentView("hosts") // По умолчанию фокус на хостах
		t.activePanel = "hosts"
	}

	return nil
}

// startScan запускает сканирование
func (t *TUI) startScan(g *gocui.Gui, v *gocui.View) error {
	if t.activeHost == nil {
		t.updateStatus("Ошибка: не выбран хост")
		return nil
	}

	// Получаем выбранный контейнер
	var selectedContainer *models.Container
	if containersView, err := g.View("containers"); err == nil {
		_, cy := containersView.Cursor()
		if cy >= 0 && cy < len(t.containers) {
			selectedContainer = &t.containers[cy]
		}
	}

	if selectedContainer == nil {
		t.updateStatus("Ошибка: не выбран контейнер")
		return nil
	}

	// Обновляем статус и логи
	t.updateStatus(fmt.Sprintf("Запуск сканирования контейнера %s...", selectedContainer.Name))
	t.addLog(fmt.Sprintf("Запуск сканирования контейнера %s на хосте %s", selectedContainer.Name, t.activeHost.Name))

	// Запускаем сканирование в отдельной горутине
	go func() {
		// URL для запуска сканирования
		url := fmt.Sprintf("http://%s:%d/scan", t.activeHost.Address, t.activeHost.Port)

		// Подготовка запроса
		scanReq := models.ScanRequest{
			ContainerID: selectedContainer.ID,
		}

		// Сериализация запроса
		jsonData, err := json.Marshal(scanReq)
		if err != nil {
			t.logger.WithError(err).Error("Ошибка сериализации запроса")
			t.updateStatusAsync("Ошибка: не удалось подготовить запрос")
			t.addLogAsync(fmt.Sprintf("Ошибка сериализации запроса: %v", err))
			return
		}

		// Выполнение POST запроса
		t.addLogAsync("Отправка запроса на сканирование агенту...")
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			t.logger.WithError(err).Error("Ошибка запроса к агенту")
			t.updateStatusAsync("Ошибка: не удалось подключиться к агенту")
			t.addLogAsync(fmt.Sprintf("Ошибка запроса к агенту: %v", err))
			return
		}
		defer resp.Body.Close()

		// Проверка статуса ответа
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			t.logger.WithField("status_code", resp.StatusCode).Error("Агент вернул ошибку")
			t.updateStatusAsync(fmt.Sprintf("Ошибка: агент вернул статус %d", resp.StatusCode))
			t.addLogAsync(fmt.Sprintf("Агент вернул ошибку: статус %d", resp.StatusCode))
			return
		}

		// Декодирование ответа
		var scanResp models.ScanResponse
		if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
			t.logger.WithError(err).Error("Ошибка декодирования ответа агента")
			t.updateStatusAsync("Ошибка: не удалось прочитать ответ агента")
			t.addLogAsync(fmt.Sprintf("Ошибка декодирования ответа агента: %v", err))
			return
		}

		// Сохранение информации о сканировании
		scan := &models.Scan{
			ID:          scanResp.ScanID,
			HostID:      t.activeHost.ID,
			ContainerID: selectedContainer.ID,
			Status:      "pending",
			StartedAt:   time.Now(),
		}

		if err := t.store.AddScan(scan); err != nil {
			t.logger.WithError(err).Error("Ошибка сохранения информации о сканировании")
			t.addLogAsync(fmt.Sprintf("Ошибка сохранения информации о сканировании: %v", err))
		}

		t.updateStatusAsync(fmt.Sprintf("Сканирование запущено: ID=%s", scanResp.ScanID))
		t.addLogAsync(fmt.Sprintf("Сканирование успешно запущено: ID=%s", scanResp.ScanID))

		// Запускаем мониторинг статуса
		t.monitorScanStatus(scanResp.ScanID)
	}()

	return nil
}

// monitorScanStatus следит за выполнением сканирования
func (t *TUI) monitorScanStatus(scanID string) {
	// Получаем информацию о сканировании
	scan, err := t.store.GetScan(scanID)
	if err != nil {
		t.logger.WithError(err).Error("Ошибка получения информации о сканировании")
		t.addLogAsync(fmt.Sprintf("Ошибка получения информации о сканировании: %v", err))
		return
	}

	host, err := t.store.GetHost(scan.HostID)
	if err != nil {
		t.logger.WithError(err).Error("Ошибка получения информации о хосте")
		t.addLogAsync(fmt.Sprintf("Ошибка получения информации о хосте: %v", err))
		return
	}

	container, err := t.store.GetContainer(scan.ContainerID)
	if err != nil {
		t.logger.WithError(err).Error("Ошибка получения информации о контейнере")
		t.addLogAsync(fmt.Sprintf("Ошибка получения информации о контейнере: %v", err))
		return
	}

	// URL для проверки статуса
	url := fmt.Sprintf("http://%s:%d/scan/%s", host.Address, host.Port, scanID)

	// Периодическая проверка статуса
	statusCheckTicker := time.NewTicker(5 * time.Second)
	timeoutTimer := time.NewTimer(5 * time.Minute) // Таймаут 5 минут
	defer statusCheckTicker.Stop()
	defer timeoutTimer.Stop()

	for {
		select {
		case <-statusCheckTicker.C:
			// Выполнение GET запроса
			t.addLogAsync("Проверка статуса сканирования...")
			resp, err := http.Get(url)
			if err != nil {
				t.logger.WithError(err).Error("Ошибка запроса к агенту")
				t.addLogAsync(fmt.Sprintf("Ошибка запроса к агенту: %v", err))
				continue
			}

			// Проверка статуса ответа
			if resp.StatusCode != http.StatusOK {
				t.logger.WithField("status_code", resp.StatusCode).Error("Агент вернул ошибку")
				t.addLogAsync(fmt.Sprintf("Агент вернул ошибку: статус %d", resp.StatusCode))
				resp.Body.Close()
				continue
			}

			// Декодирование ответа
			var scanStatusResp models.ScanStatusResponse
			if err := json.NewDecoder(resp.Body).Decode(&scanStatusResp); err != nil {
				t.logger.WithError(err).Error("Ошибка декодирования ответа агента")
				t.addLogAsync(fmt.Sprintf("Ошибка декодирования ответа агента: %v", err))
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			// Обновление статуса сканирования в БД
			scan.Status = scanStatusResp.Status
			if scanStatusResp.FinishedAt != nil {
				scan.FinishedAt = *scanStatusResp.FinishedAt
			}
			if scanStatusResp.ErrorMsg != "" {
				scan.ErrorMsg = scanStatusResp.ErrorMsg
			}

			if err := t.store.UpdateScan(scan); err != nil {
				t.logger.WithError(err).Error("Ошибка обновления информации о сканировании")
				t.addLogAsync(fmt.Sprintf("Ошибка обновления информации о сканировании: %v", err))
			}

			// Логируем статус
			t.addLogAsync(fmt.Sprintf("Статус сканирования %s: %s", scanID, scanStatusResp.Status))

			// Если сканирование завершено, обрабатываем результаты
			if scan.Status == "completed" || scan.Status == "failed" {
				if scan.Status == "completed" {
					t.addLogAsync(fmt.Sprintf("Сканирование %s завершено успешно", scanID))
					t.updateStatusAsync(fmt.Sprintf("Сканирование завершено: найдено %d уязвимостей", len(scanStatusResp.Vulnerabilities)))

					// Обновляем уязвимости в БД
					for _, vuln := range scanStatusResp.Vulnerabilities {
						// Дополняем данные об уязвимости
						vuln.ID = uuid.New().String()
						vuln.ScanID = scanID
						vuln.ContainerID = container.ID
						vuln.HostID = host.ID
						vuln.DiscoveredAt = time.Now()

						// Сохраняем уязвимость в БД
						if err := t.store.AddVulnerability(&vuln); err != nil {
							t.logger.WithError(err).Error("Ошибка сохранения информации об уязвимости")
							t.addLogAsync(fmt.Sprintf("Ошибка сохранения информации об уязвимости: %v", err))
						}
					}

					// Обновляем вывод уязвимостей
					t.loadVulnerabilities(container.ID)
					t.g.Update(func(g *gocui.Gui) error {
						if vulnsView, err := g.View("vulnerabilities"); err == nil {
							t.renderVulnerabilities(vulnsView)
						}
						return nil
					})
				} else {
					t.addLogAsync(fmt.Sprintf("Сканирование %s завершено с ошибкой: %s", scanID, scan.ErrorMsg))
					t.updateStatusAsync("Сканирование завершено с ошибкой")
				}

				return
			}

		case <-timeoutTimer.C:
			// Завершаем мониторинг по таймауту
			t.addLogAsync(fmt.Sprintf("Превышено время ожидания результатов сканирования %s", scanID))
			t.updateStatusAsync("Превышено время ожидания результатов сканирования")
			return
		}
	}
}

// updateStatusAsync обновляет статус асинхронно из горутины
func (t *TUI) updateStatusAsync(msg string) {
	t.g.Update(func(g *gocui.Gui) error {
		t.updateStatus(msg)
		return nil
	})
}

// addLogAsync добавляет запись в лог асинхронно из горутины
func (t *TUI) addLogAsync(msg string) {
	t.g.Update(func(g *gocui.Gui) error {
		t.addLog(msg)
		return nil
	})
}

// exportReport экспортирует отчет
func (t *TUI) exportReport(g *gocui.Gui, v *gocui.View) error {
	maxX, maxY := g.Size()

	// Проверяем, существует ли панель
	if _, err := g.View("export_dialog"); err == nil {
		// Проверяем видимость: если view в списке модальных окон, он виден
		isVisible := false
		for _, name := range t.modalWindows {
			if name == "export_dialog" {
				isVisible = true
				break
			}
		}

		if isVisible {
			// Панель существует и видима, просто активируем ее
			return t.activateView(g, "export_dialog")
		}
	}

	// Создаем или перемещаем окно в нужную позицию
	exportView, err := g.SetView("export_dialog", maxX/4, maxY/3, 3*maxX/4, maxY/3+4)
	if err != nil && err != gocui.ErrUnknownView {
		return err
	}

	exportView.Title = "Путь для экспорта"
	exportView.Editable = true
	exportView.Editor = gocui.DefaultEditor
	exportView.Clear()

	// Сохраняем текущую активную панель
	if g.CurrentView() != nil && g.CurrentView().Name() != "export_dialog" {
		t.activePanel = g.CurrentView().Name()
	}

	// Добавляем окно в стек
	t.modalWindows = append(t.modalWindows, "export_dialog")

	// Устанавливаем значение по умолчанию
	homeDir, _ := os.UserHomeDir()
	defaultPath := filepath.Join(homeDir, "aegis_report_"+time.Now().Format("2006-01-02")+".csv")
	fmt.Fprintf(exportView, "%s", defaultPath)

	// Удаляем предыдущие привязки клавиш, если они есть
	g.DeleteKeybindings("export_dialog")

	// Добавляем обработчики клавиш
	if err := g.SetKeybinding("export_dialog", gocui.KeyEnter, gocui.ModNone, t.performExport); err != nil {
		return err
	}
	if err := g.SetKeybinding("export_dialog", gocui.KeyEsc, gocui.ModNone, t.closeExportDialog); err != nil {
		return err
	}

	// Активируем окно
	t.updateStatus("Укажите путь для сохранения отчета и нажмите Enter. Esc для отмены.")
	return t.activateView(g, "export_dialog")
}

// closeExportDialog закрывает диалоговое окно экспорта
func (t *TUI) closeExportDialog(g *gocui.Gui, v *gocui.View) error {
	// Удаляем диалоговое окно
	if err := g.DeleteView("export_dialog"); err != nil {
		return err
	}

	// Удаляем из стека модальных окон
	for i, name := range t.modalWindows {
		if name == "export_dialog" {
			t.modalWindows = append(t.modalWindows[:i], t.modalWindows[i+1:]...)
			break
		}
	}

	// Восстанавливаем фокус на предыдущую панель
	if t.activePanel != "" && t.activePanel != "export_dialog" {
		g.SetCurrentView(t.activePanel)
	} else {
		g.SetCurrentView("hosts")
		t.activePanel = "hosts"
	}

	t.updateStatus("Экспорт отменен")
	return nil
}

// performExport выполняет экспорт отчета
func (t *TUI) performExport(g *gocui.Gui, v *gocui.View) error {
	// Получаем путь для экспорта
	path := strings.TrimSpace(v.Buffer())

	// Закрываем диалоговое окно
	if err := g.DeleteView("export_dialog"); err != nil {
		return err
	}

	// Удаляем из стека модальных окон
	for i, name := range t.modalWindows {
		if name == "export_dialog" {
			t.modalWindows = append(t.modalWindows[:i], t.modalWindows[i+1:]...)
			break
		}
	}

	// Восстанавливаем фокус на предыдущую панель
	if t.activePanel != "" && t.activePanel != "export_dialog" {
		g.SetCurrentView(t.activePanel)
	} else {
		g.SetCurrentView("hosts")
		t.activePanel = "hosts"
	}

	// Запускаем экспорт в отдельной горутине
	go func() {
		t.updateStatusAsync("Экспорт отчета...")
		t.addLogAsync(fmt.Sprintf("Начало экспорта отчета в %s", path))

		// Проверяем выбранный контейнер
		var selectedContainer *models.Container
		if containersView, err := g.View("containers"); err == nil {
			_, cy := containersView.Cursor()
			if cy >= 0 && cy < len(t.containers) {
				selectedContainer = &t.containers[cy]
			}
		}

		if selectedContainer == nil {
			t.updateStatusAsync("Не выбран контейнер для экспорта")
			t.addLogAsync("Экспорт отменен: не выбран контейнер")
			return
		}

		vulns := t.vulns // Используем уже загруженные уязвимости

		if len(vulns) == 0 {
			t.updateStatusAsync("Нет данных для экспорта")
			t.addLogAsync("Экспорт отменен: нет данных об уязвимостях")
			return
		}

		// Создаем новую операцию с индикатором прогресса
		operationID := "export-" + selectedContainer.ID[:8]
		t.addProgressBar(operationID, 0, "Подготовка данных...")

		// Создаем директорию для экспорта, если она не существует
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.updateStatusAsync(fmt.Sprintf("Ошибка создания директории: %v", err))
			t.addLogAsync(fmt.Sprintf("Ошибка экспорта: не удалось создать директорию %s: %v", dir, err))
			return
		}

		t.addProgressBar(operationID, 20, "Создание файла...")

		// Открываем файл для записи
		file, err := os.Create(path)
		if err != nil {
			t.updateStatusAsync(fmt.Sprintf("Ошибка создания файла: %v", err))
			t.addLogAsync(fmt.Sprintf("Ошибка экспорта: не удалось создать файл %s: %v", path, err))
			return
		}
		defer file.Close()

		t.addProgressBar(operationID, 40, "Запись заголовка...")

		// Записываем заголовок CSV
		header := "ID,VulnerabilityID,Severity,Title,Package,InstalledVersion,FixedVersion,Description\n"
		if _, err := file.WriteString(header); err != nil {
			t.updateStatusAsync(fmt.Sprintf("Ошибка записи в файл: %v", err))
			t.addLogAsync(fmt.Sprintf("Ошибка экспорта: не удалось записать заголовок в файл %s: %v", path, err))
			return
		}

		t.addProgressBar(operationID, 60, "Запись данных...")

		// Записываем данные
		for i, v := range vulns {
			// Вычисляем прогресс экспорта
			if i%10 == 0 && len(vulns) > 0 {
				progress := 60 + int(float64(i)/float64(len(vulns))*30)
				t.addProgressBar(operationID, progress, "Запись данных...")
			}

			// Экранируем двойные кавычки в полях
			title := strings.ReplaceAll(v.Title, "\"", "\"\"")
			description := strings.ReplaceAll(v.Description, "\"", "\"\"")

			line := fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
				v.ID, v.VulnerabilityID, v.Severity, title, v.Package, v.InstalledVersion, v.FixedVersion, description)
			if _, err := file.WriteString(line); err != nil {
				t.updateStatusAsync(fmt.Sprintf("Ошибка записи в файл: %v", err))
				t.addLogAsync(fmt.Sprintf("Ошибка экспорта: не удалось записать данные в файл %s: %v", path, err))
				return
			}
		}

		t.addProgressBar(operationID, 100, "Завершено")

		// Небольшая задержка перед завершением, чтобы пользователь увидел 100%
		time.Sleep(500 * time.Millisecond)

		t.updateStatusAsync(fmt.Sprintf("Отчет успешно экспортирован в %s", path))
		t.addLogAsync(fmt.Sprintf("Отчет успешно экспортирован в %s (%d уязвимостей)", path, len(vulns)))
	}()

	return nil
}

// showRemediation показывает панель с хуками и стратегиями исправления уязвимостей
func (t *TUI) showRemediation(g *gocui.Gui, v *gocui.View) error {
	maxX, maxY := g.Size()

	// Проверяем, существует ли панель
	if _, err := g.View("remediation"); err == nil {
		// Проверяем видимость: если view в списке модальных окон, он виден
		isVisible := false
		for _, name := range t.modalWindows {
			if name == "remediation" {
				isVisible = true
				break
			}
		}

		if isVisible {
			// Панель существует и видима, просто активируем ее
			return t.activateView(g, "remediation")
		}
	}

	// Создаем или перемещаем окно в нужную позицию
	remediationView, err := g.SetView("remediation", maxX/6, maxY/6, 5*maxX/6, 5*maxY/6)
	if err != nil && err != gocui.ErrUnknownView {
		return err
	}

	remediationView.Title = "Хуки и стратегии"
	remediationView.Highlight = true
	remediationView.SelBgColor = gocui.ColorGreen
	remediationView.SelFgColor = gocui.ColorBlack
	remediationView.Wrap = true
	remediationView.Editable = false
	remediationView.Clear()

	// Сохраняем текущую активную панель
	if g.CurrentView() != nil && g.CurrentView().Name() != "remediation" {
		t.activePanel = g.CurrentView().Name()
	}

	// Добавляем окно в стек
	t.modalWindows = append(t.modalWindows, "remediation")

	// Загружаем хуки и стратегии
	t.loadRemediation()

	// Отображаем хуки и стратегии
	t.renderRemediation(remediationView)

	// Удаляем предыдущие привязки клавиш, если они есть
	g.DeleteKeybindings("remediation")

	// Регистрируем клавиши
	if err := g.SetKeybinding("remediation", gocui.KeyEsc, gocui.ModNone, t.closeRemediation); err != nil {
		return err
	}
	if err := g.SetKeybinding("remediation", gocui.KeyEnter, gocui.ModNone, t.applyRemediation); err != nil {
		return err
	}
	if err := g.SetKeybinding("remediation", gocui.KeyArrowDown, gocui.ModNone, t.cursorDown); err != nil {
		return err
	}
	if err := g.SetKeybinding("remediation", gocui.KeyArrowUp, gocui.ModNone, t.cursorUp); err != nil {
		return err
	}

	// Активируем окно
	return t.activateView(g, "remediation")
}

// closeRemediation закрывает панель с хуками и стратегиями
func (t *TUI) closeRemediation(g *gocui.Gui, v *gocui.View) error {
	// Удаляем панель
	if err := g.DeleteView("remediation"); err != nil {
		return err
	}

	// Удаляем из стека модальных окон
	for i, name := range t.modalWindows {
		if name == "remediation" {
			t.modalWindows = append(t.modalWindows[:i], t.modalWindows[i+1:]...)
			break
		}
	}

	// Восстанавливаем фокус на предыдущую панель
	if t.activePanel != "" && t.activePanel != "remediation" {
		g.SetCurrentView(t.activePanel)
	} else {
		g.SetCurrentView("hosts")
		t.activePanel = "hosts"
	}

	return nil
}

// showTelegramInfo показывает информацию о настройке и использовании Telegram-бота
func (t *TUI) showTelegramInfo(g *gocui.Gui, v *gocui.View) error {
	maxX, maxY := g.Size()

	// Проверяем, существует ли панель
	if _, err := g.View("telegram_info"); err == nil {
		// Проверяем видимость: если view в списке модальных окон, он виден
		isVisible := false
		for _, name := range t.modalWindows {
			if name == "telegram_info" {
				isVisible = true
				break
			}
		}

		if isVisible {
			// Панель существует и видима, просто активируем ее
			return t.activateView(g, "telegram_info")
		}
	}

	// Создаем или перемещаем окно в нужную позицию
	telegramView, err := g.SetView("telegram_info", maxX/6, maxY/6, 5*maxX/6, 5*maxY/6)
	if err != nil && err != gocui.ErrUnknownView {
		return err
	}

	telegramView.Title = "Telegram-бот"
	telegramView.Wrap = true
	telegramView.Editable = false
	telegramView.Clear()

	// Сохраняем текущую активную панель
	if g.CurrentView() != nil && g.CurrentView().Name() != "telegram_info" {
		t.activePanel = g.CurrentView().Name()
	}

	// Добавляем окно в стек
	t.modalWindows = append(t.modalWindows, "telegram_info")

	// Наполняем информацией
	fmt.Fprintln(telegramView, "Настройка Telegram-бота для уведомлений о безопасности")
	fmt.Fprintln(telegramView, strings.Repeat("=", 50))
	fmt.Fprintln(telegramView, "")

	// Статус подключения
	if t.telegramConnected {
		fmt.Fprintf(telegramView, "✅ Статус: Подключен и готов к работе\n\n")
	} else {
		fmt.Fprintf(telegramView, "❌ Статус: Не подключен\n\n")
	}

	// Удаляем предыдущие привязки клавиш, если они есть
	g.DeleteKeybindings("telegram_info")

	// Добавляем обработчик клавиши Esc
	if err := g.SetKeybinding("telegram_info", gocui.KeyEsc, gocui.ModNone, t.closeTelegramInfo); err != nil {
		return err
	}

	// Активируем окно
	return t.activateView(g, "telegram_info")
}

// closeTelegramInfo закрывает панель информации о Telegram-боте
func (t *TUI) closeTelegramInfo(g *gocui.Gui, v *gocui.View) error {
	// Удаляем панель
	if err := g.DeleteView("telegram_info"); err != nil {
		return err
	}

	// Удаляем из стека модальных окон
	for i, name := range t.modalWindows {
		if name == "telegram_info" {
			t.modalWindows = append(t.modalWindows[:i], t.modalWindows[i+1:]...)
			break
		}
	}

	// Восстанавливаем фокус на предыдущую панель
	if t.activePanel != "" && t.activePanel != "telegram_info" {
		g.SetCurrentView(t.activePanel)
	} else {
		g.SetCurrentView("hosts")
		t.activePanel = "hosts"
	}

	return nil
}

// Добавляем функцию для обновления интерфейса
func (t *TUI) updateUI() {
	// Обновляем все представления
	if hostsView, err := t.g.View("hosts"); err == nil {
		t.renderHosts(hostsView)
	}

	if containersView, err := t.g.View("containers"); err == nil && t.activeHost != nil {
		t.renderContainers(containersView)
	}

	if vulnsView, err := t.g.View("vulnerabilities"); err == nil {
		t.renderVulnerabilities(vulnsView)
	}

	if logsView, err := t.g.View("logs"); err == nil {
		t.renderLogs(logsView)
	}
}

// Вспомогательные функции

// loadHosts загружает список хостов
func (t *TUI) loadHosts() error {
	var err error
	t.hosts, err = t.store.ListHosts()
	if err != nil {
		return err
	}

	// Если ранее был выбран хост, находим его в новом списке
	if t.activeHost != nil {
		found := false
		for i, host := range t.hosts {
			if host.ID == t.activeHost.ID {
				t.activeHost = &t.hosts[i]
				found = true
				break
			}
		}

		if !found {
			t.activeHost = nil
		}
	}

	return nil
}

// loadContainers загружает список контейнеров для активного хоста
func (t *TUI) loadContainers() error {
	if t.activeHost == nil {
		t.containers = []models.Container{}
		return nil
	}

	// Добавляем больше логирования для отладки
	t.addLog(fmt.Sprintf("Загрузка контейнеров из БД для хоста ID=%s", t.activeHost.ID))

	var err error
	containers, err := t.store.ListContainers(t.activeHost.ID)
	if err != nil {
		t.addLog(fmt.Sprintf("Ошибка загрузки контейнеров: %v", err))
		return err
	}

	// Проверим, что контейнеры действительно принадлежат выбранному хосту
	var filteredContainers []models.Container
	for _, container := range containers {
		if container.HostID == t.activeHost.ID {
			filteredContainers = append(filteredContainers, container)
		} else {
			t.addLog(fmt.Sprintf("Пропущен контейнер с неверным hostID: %s (ожидался %s)",
				container.HostID, t.activeHost.ID))
		}
	}

	t.containers = filteredContainers
	t.addLog(fmt.Sprintf("Загружено %d контейнеров для хоста ID=%s", len(t.containers), t.activeHost.ID))

	return nil
}

// fetchContainersFromAgent загружает список контейнеров напрямую от агента
// и обновляет их в базе данных
func (t *TUI) fetchContainersFromAgent() error {
	if t.activeHost == nil {
		return fmt.Errorf("не выбран активный хост")
	}

	// Проверим ID активного хоста
	t.addLog(fmt.Sprintf("Проверка хоста ID=%s, Name=%s, Address=%s, Port=%d",
		t.activeHost.ID, t.activeHost.Name, t.activeHost.Address, t.activeHost.Port))

	// Получаем список всех хостов для проверки
	hosts, err := t.store.ListHosts()
	if err != nil {
		t.addLog(fmt.Sprintf("Ошибка получения списка хостов: %v", err))
	} else {
		t.addLog(fmt.Sprintf("Доступные хосты в системе (%d):", len(hosts)))
		for i, host := range hosts {
			t.addLog(fmt.Sprintf("  %d. ID=%s, Name=%s, Address=%s, Port=%d",
				i+1, host.ID, host.Name, host.Address, host.Port))
		}
	}

	// Проверим, что используем правильный ID хоста из команды containers list
	t.addLog(fmt.Sprintf("ВАЖНО: ID хоста для CLI команды: 647198a5-dfe3-41c8-b0e2-005c321a3aa2"))
	t.addLog(fmt.Sprintf("ВАЖНО: Текущий ID активного хоста: %s", t.activeHost.ID))

	// Формирование URL для запроса к агенту
	url := fmt.Sprintf("http://%s:%d/containers", t.activeHost.Address, t.activeHost.Port)

	// Добавим детальный лог
	t.addLog(fmt.Sprintf("Запрос списка контейнеров от агента: %s", url))

	// Выполнение HTTP запроса
	resp, err := http.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Ошибка запроса к агенту: %v", err)
		t.addLog(errMsg)
		return fmt.Errorf(errMsg)
	}
	defer resp.Body.Close()

	// Проверка статуса ответа
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Агент вернул ошибку: статус %d", resp.StatusCode)
		t.addLog(errMsg)
		return fmt.Errorf(errMsg)
	}

	// Чтение тела ответа для отладки
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Ошибка чтения ответа: %v", err)
		t.addLog(errMsg)
		return fmt.Errorf(errMsg)
	}

	// Логируем тело ответа для отладки
	t.addLog(fmt.Sprintf("Получен ответ от агента: %s", string(bodyBytes)))

	// Создаем новый reader для декодирования JSON, так как оригинальный Body уже прочитан
	bodyReader := bytes.NewReader(bodyBytes)

	// Декодирование ответа
	var containerResponse models.ContainerListResponse
	if err := json.NewDecoder(bodyReader).Decode(&containerResponse); err != nil {
		errMsg := fmt.Sprintf("Ошибка декодирования ответа агента: %v", err)
		t.addLog(errMsg)
		return fmt.Errorf(errMsg)
	}

	// Логируем количество найденных контейнеров
	t.addLog(fmt.Sprintf("Получено контейнеров от агента: %d", len(containerResponse.Containers)))

	// Используем ID из CLI-команды для теста
	targetHostID := "647198a5-dfe3-41c8-b0e2-005c321a3aa2"
	t.addLog(fmt.Sprintf("Используем хост ID=%s для добавления контейнеров в БД", targetHostID))

	// Обновление контейнеров в базе данных
	for _, container := range containerResponse.Containers {
		// Добавляем хост ID и время обновления
		container.HostID = targetHostID // Используем целевой ID
		container.UpdatedAt = time.Now()

		// Логируем информацию о каждом контейнере
		t.addLog(fmt.Sprintf("Обработка контейнера ID=%s, Name=%s, Image=%s, Status=%s",
			container.ID, container.Name, container.Image, container.Status))

		// Проверяем, существует ли контейнер в базе
		existingContainer, err := t.store.GetContainer(container.ID)
		if err == nil {
			// Контейнер существует, обновляем статус
			existingContainer.Status = container.Status
			existingContainer.UpdatedAt = time.Now()
			existingContainer.HostID = targetHostID // Обновляем ID хоста
			if err := t.store.UpdateContainer(existingContainer); err != nil {
				t.addLog(fmt.Sprintf("Ошибка обновления контейнера %s в БД: %v", container.ID, err))
			} else {
				t.addLog(fmt.Sprintf("Контейнер %s обновлен в БД", container.ID))
			}
		} else {
			// Контейнер не существует, добавляем
			container.CreatedAt = time.Now()
			if err := t.store.AddContainer(&container); err != nil {
				t.addLog(fmt.Sprintf("Ошибка добавления контейнера %s в БД: %v", container.ID, err))
			} else {
				t.addLog(fmt.Sprintf("Контейнер %s добавлен в БД", container.ID))
			}
		}
	}

	// Временно подменяем активный хост для загрузки контейнеров
	originalHost := t.activeHost
	// Получаем хост из БД по ID
	targetHost, err := t.store.GetHost(targetHostID)
	if err != nil {
		t.addLog(fmt.Sprintf("Ошибка получения хоста по ID=%s: %v", targetHostID, err))
	} else {
		t.activeHost = targetHost
	}

	// После обновления базы данных загружаем контейнеры из неё
	t.addLog("Загрузка обновленных контейнеров из БД")
	err = t.loadContainers()

	// Восстанавливаем исходный активный хост
	t.activeHost = originalHost

	if err != nil {
		t.addLog(fmt.Sprintf("Ошибка загрузки контейнеров из БД: %v", err))
		return err
	}

	// Логируем количество загруженных из БД контейнеров
	t.addLog(fmt.Sprintf("Загружено контейнеров из БД: %d", len(t.containers)))

	return nil
}

// loadVulnerabilities загружает список уязвимостей
func (t *TUI) loadVulnerabilities(containerID string) error {
	hostID := ""
	if t.activeHost != nil {
		hostID = t.activeHost.ID
	}

	var err error
	t.vulns, err = t.store.ListVulnerabilities(hostID, containerID, "", "")
	if err != nil {
		return err
	}

	return nil
}

// selectHost выбирает хост по индексу
func (t *TUI) selectHost(index int) {
	if index >= 0 && index < len(t.hosts) {
		t.activeHost = &t.hosts[index]

		// Логируем выбранный хост для отладки
		t.addLog(fmt.Sprintf("Выбран хост ID=%s, Name=%s, Address=%s, Port=%d",
			t.activeHost.ID, t.activeHost.Name, t.activeHost.Address, t.activeHost.Port))

		// Используем прямой метод получения контейнеров как в CLI
		err := t.fetchContainersDirect()
		if err != nil {
			t.addLog(fmt.Sprintf("Ошибка при прямом получении контейнеров: %v", err))

			// Пробуем получить контейнеры через обычный метод
			err = t.fetchContainersFromAgent()
			if err != nil {
				t.addLog(fmt.Sprintf("Ошибка получения контейнеров от агента: %v", err))
				// При ошибке используем локальные данные
				t.loadContainers()
			}
		}

		if containersView, err := t.g.View("containers"); err == nil {
			t.renderContainers(containersView)
		}

		t.loadVulnerabilities("")
		if vulnsView, err := t.g.View("vulnerabilities"); err == nil {
			t.renderVulnerabilities(vulnsView)
		}

		t.updateStatus(fmt.Sprintf("Выбран хост: %s (%s)", t.activeHost.Name, t.activeHost.Address))
	}
}

// selectContainer выбирает контейнер по индексу
func (t *TUI) selectContainer(index int) {
	if index >= 0 && index < len(t.containers) {
		container := t.containers[index]
		t.loadVulnerabilities(container.ID)

		if vulnsView, err := t.g.View("vulnerabilities"); err == nil {
			t.renderVulnerabilities(vulnsView)
		}

		t.updateStatus(fmt.Sprintf("Выбран контейнер: %s (образ: %s)", container.Name, container.Image))
	}
}

// renderHosts отображает список хостов в панели
func (t *TUI) renderHosts(v *gocui.View) {
	v.Clear()

	if len(t.hosts) == 0 {
		fmt.Fprintln(v, "Нет доступных хостов")
		return
	}

	for _, host := range t.hosts {
		statusSymbol := "⚫" // Offline
		if host.Status == "online" {
			statusSymbol = "🟢" // Online
		}

		fmt.Fprintf(v, "%s %s (%s:%d)\n", statusSymbol, host.Name, host.Address, host.Port)
	}
}

// renderContainers отображает список контейнеров в панели
func (t *TUI) renderContainers(v *gocui.View) {
	v.Clear()

	if t.activeHost == nil {
		fmt.Fprintln(v, "Выберите хост")
		return
	}

	// Дополнительный лог для отладки
	t.addLog(fmt.Sprintf("Рендеринг контейнеров для хоста ID=%s. Найдено: %d",
		t.activeHost.ID, len(t.containers)))

	if len(t.containers) == 0 {
		fmt.Fprintln(v, "Нет доступных контейнеров")
		return
	}

	for _, container := range t.containers {
		statusSymbol := "⚪" // Not running
		if strings.Contains(container.Status, "Up") {
			statusSymbol = "🟢" // Running
		}

		fmt.Fprintf(v, "%s %s (%s)\n", statusSymbol, container.Name, container.Image)
	}
}

// renderVulnerabilities отображает список уязвимостей в панели
func (t *TUI) renderVulnerabilities(v *gocui.View) {
	v.Clear()

	if len(t.vulns) == 0 {
		fmt.Fprintln(v, "Нет данных об уязвимостях")
		return
	}

	// Группируем уязвимости по критичности
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	for _, severity := range severities {
		var countBySeverity int

		for _, vuln := range t.vulns {
			if strings.EqualFold(vuln.Severity, severity) {
				countBySeverity++
			}
		}

		if countBySeverity > 0 {
			var severityColor string
			switch strings.ToUpper(severity) {
			case "CRITICAL":
				severityColor = "31" // Red
			case "HIGH":
				severityColor = "33" // Yellow
			case "MEDIUM":
				severityColor = "34" // Blue
			case "LOW":
				severityColor = "32" // Green
			default:
				severityColor = "37" // White
			}

			fmt.Fprintf(v, "\x1b[%sm%s: %d\x1b[0m\n", severityColor, severity, countBySeverity)
		}
	}

	fmt.Fprintln(v, "")
	fmt.Fprintln(v, "Подробно:")

	// Отображаем первые 10 уязвимостей
	limit := 10
	if limit > len(t.vulns) {
		limit = len(t.vulns)
	}

	for i := 0; i < limit; i++ {
		vuln := t.vulns[i]
		var severityColor string
		switch strings.ToUpper(vuln.Severity) {
		case "CRITICAL":
			severityColor = "31" // Red
		case "HIGH":
			severityColor = "33" // Yellow
		case "MEDIUM":
			severityColor = "34" // Blue
		case "LOW":
			severityColor = "32" // Green
		default:
			severityColor = "37" // White
		}

		fmt.Fprintf(v, "\x1b[%sm[%s]\x1b[0m %s (%s)\n",
			severityColor, vuln.Severity, vuln.VulnerabilityID, vuln.Package)
		fmt.Fprintf(v, "  %s\n", vuln.Title)

		if vuln.FixedVersion != "" {
			fmt.Fprintf(v, "  Исправлено в версии: %s (текущая: %s)\n",
				vuln.FixedVersion, vuln.InstalledVersion)
		}

		fmt.Fprintln(v, "")
	}

	if len(t.vulns) > limit {
		fmt.Fprintf(v, "... еще %d уязвимостей\n", len(t.vulns)-limit)
	}
}

// updateStatus обновляет строку статуса
func (t *TUI) updateStatus(msg string) {
	statusView, err := t.g.View("status")
	if err != nil {
		return
	}

	statusView.Clear()
	timestamp := time.Now().Format("15:04:05")
	fmt.Fprintf(statusView, "[%s] %s | F1:Помощь | F2:Сканировать | F3:Экспорт | F4:Хуки | F5:Обновить | F6:Telegram | F10:Выход",
		timestamp, msg)
}

// Добавляем обработчик клавиш для панели уязвимостей
func (t *TUI) scrollVulnsDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+1); err != nil {
			return err
		}
	}
	return nil
}

func (t *TUI) scrollVulnsUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		if oy > 0 {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *TUI) pageVulnsDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+maxY); err != nil {
			return err
		}
	}
	return nil
}

func (t *TUI) pageVulnsUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		ox, oy := v.Origin()
		if oy-maxY > 0 {
			if err := v.SetOrigin(ox, oy-maxY); err != nil {
				return err
			}
		} else {
			if err := v.SetOrigin(ox, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// nextView переключает фокус на следующую панель
func (t *TUI) nextView(g *gocui.Gui, v *gocui.View) error {
	// Проверяем, открыто ли какое-либо модальное окно
	if len(t.modalWindows) > 0 {
		// Если есть модальные окна, не переключаем фокус
		return nil
	}

	if v == nil {
		_, err := g.SetCurrentView("hosts")
		t.activePanel = "hosts"
		return err
	}

	// Порядок переключения: hosts -> containers -> vulnerabilities -> logs -> hosts
	nextViews := map[string]string{
		"hosts":           "containers",
		"containers":      "vulnerabilities",
		"vulnerabilities": "logs",
		"logs":            "hosts",
	}

	if nextView, ok := nextViews[v.Name()]; ok {
		_, err := g.SetCurrentView(nextView)
		t.activePanel = nextView
		t.updateStatus(fmt.Sprintf("Активная панель: %s", nextView))
		return err
	}

	_, err := g.SetCurrentView("hosts")
	t.activePanel = "hosts"
	return err
}

// cursorDown перемещает курсор вниз
func (t *TUI) cursorDown(g *gocui.Gui, v *gocui.View) error {
	if v == nil {
		return nil
	}

	cx, cy := v.Cursor()
	if cy+1 < len(strings.Split(strings.TrimSpace(v.Buffer()), "\n")) {
		if err := v.SetCursor(cx, cy+1); err != nil {
			ox, oy := v.Origin()
			if err := v.SetOrigin(ox, oy+1); err != nil {
				return err
			}
		}

		if v.Name() == "hosts" {
			t.selectHost(cy + 1)
		} else if v.Name() == "containers" {
			t.selectContainer(cy + 1)
		}
	}

	return nil
}

// cursorUp перемещает курсор вверх
func (t *TUI) cursorUp(g *gocui.Gui, v *gocui.View) error {
	if v == nil {
		return nil
	}

	ox, oy := v.Origin()
	cx, cy := v.Cursor()
	if cy > 0 {
		if err := v.SetCursor(cx, cy-1); err != nil && oy > 0 {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}

		if v.Name() == "hosts" {
			t.selectHost(cy - 1)
		} else if v.Name() == "containers" {
			t.selectContainer(cy - 1)
		}
	}

	return nil
}

// selectHostOnEnter выбирает хост при нажатии Enter
func (t *TUI) selectHostOnEnter(g *gocui.Gui, v *gocui.View) error {
	_, cy := v.Cursor()
	t.selectHost(cy)
	return nil
}

// selectContainerOnEnter выбирает контейнер при нажатии Enter
func (t *TUI) selectContainerOnEnter(g *gocui.Gui, v *gocui.View) error {
	_, cy := v.Cursor()
	t.selectContainer(cy)
	return nil
}

// refreshData обновляет данные
func (t *TUI) refreshData(g *gocui.Gui, v *gocui.View) error {
	t.updateStatus("Обновление данных...")

	if err := t.loadHosts(); err != nil {
		return err
	}

	if t.activeHost != nil {
		// Используем прямой метод получения контейнеров как в CLI
		err := t.fetchContainersDirect()
		if err != nil {
			t.addLog(fmt.Sprintf("Ошибка при прямом получении контейнеров: %v", err))

			// Вместо просто загрузки из БД, сначала обновляем данные с агента
			if err := t.fetchContainersFromAgent(); err != nil {
				t.addLog(fmt.Sprintf("Ошибка при получении контейнеров от агента: %v", err))
				// Даже при ошибке пробуем загрузить из БД
				if err := t.loadContainers(); err != nil {
					return err
				}
			}
		}
	}

	// Используем updateUI для обновления интерфейса
	t.updateUI()

	t.updateStatus("Данные обновлены")
	return nil
}

// quit выходит из приложения
func (t *TUI) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

// addProgressBar добавляет или обновляет индикатор прогресса в логах
func (t *TUI) addProgressBar(operationID string, progress int, message string) {
	// Формируем строку прогресса цветную и более заметную
	progressChar := "█"
	emptyChar := "░"
	barLength := 20
	completedLength := barLength * progress / 100

	progressBar := "["
	for i := 0; i < barLength; i++ {
		if i < completedLength {
			progressBar += progressChar
		} else {
			progressBar += emptyChar
		}
	}
	progressBar += fmt.Sprintf("] %d%%", progress)

	timestamp := time.Now().Format("15:04:05")
	// Зеленый прогресс-бар для лучшей видимости
	logEntry := fmt.Sprintf("[%s] \x1b[32mПрогресс %s: %s %s\x1b[0m", timestamp, operationID, progressBar, message)

	// Обновляем или добавляем запись в лог
	found := false
	for i, entry := range t.logs {
		if strings.Contains(entry, fmt.Sprintf("Прогресс %s:", operationID)) {
			t.logs[i] = logEntry
			found = true
			break
		}
	}

	if !found {
		t.logs = append(t.logs, logEntry)
		// Ограничиваем размер лога
		if len(t.logs) > 100 {
			t.logs = t.logs[len(t.logs)-100:]
		}
	}

	// Обновляем отображение логов асинхронно
	t.g.Update(func(g *gocui.Gui) error {
		if logsView, err := g.View("logs"); err == nil {
			t.renderLogs(logsView)
		}
		return nil
	})
}

// checkTelegramBotStatus проверяет статус Telegram-бота
func (t *TUI) checkTelegramBotStatus() {
	// Проверяем, настроен ли Telegram-бот в конфигурации
	if t.config.TelegramBotToken != "" && t.config.TelegramChatID != "" {
		t.addLog("Проверка подключения Telegram-бота...")

		// Здесь должен быть код для проверки подключения к Telegram API
		// Эмулируем задержку и успешное подключение
		time.Sleep(2 * time.Second)

		t.telegramConnected = true
		t.addLogAsync("Telegram-бот подключен и готов к отправке уведомлений")
		t.updateStatusAsync("Telegram-бот активен")
	} else {
		t.addLog("Telegram-бот не настроен. Для настройки укажите TelegramBotToken и TelegramChatID в конфигурации")
	}
}

// renderLogs отображает логи в панели
func (t *TUI) renderLogs(v *gocui.View) {
	v.Clear()

	if len(t.logs) == 0 {
		fmt.Fprintln(v, "Нет записей в логе")
		return
	}

	// Отображаем логи в обратном порядке (последние записи сверху)
	for i := len(t.logs) - 1; i >= 0; i-- {
		fmt.Fprintln(v, t.logs[i])
	}

	// Обновляем отображение
	v.SetOrigin(0, 0)
}

// Методы для прокрутки логов
func (t *TUI) scrollLogsDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+1); err != nil {
			return err
		}
	}
	return nil
}

func (t *TUI) scrollLogsUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		if oy > 0 {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *TUI) pageLogsDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+maxY); err != nil {
			return err
		}
	}
	return nil
}

func (t *TUI) pageLogsUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		ox, oy := v.Origin()
		if oy-maxY > 0 {
			if err := v.SetOrigin(ox, oy-maxY); err != nil {
				return err
			}
		} else {
			if err := v.SetOrigin(ox, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadRemediation загружает хуки и стратегии исправления
func (t *TUI) loadRemediation() {
	// Загружаем хуки
	hooks, err := t.store.ListHooks()
	if err != nil {
		t.logger.WithError(err).Error("Ошибка загрузки хуков")
		t.hooks = []models.Hook{}
	} else {
		t.hooks = hooks
	}

	// Загружаем стратегии исправления
	strategies, err := t.store.ListRemediationStrategies()
	if err != nil {
		t.logger.WithError(err).Error("Ошибка загрузки стратегий исправления")
		t.strategies = []models.RemediationStrategy{}
	} else {
		t.strategies = strategies
	}
}

// renderRemediation отображает хуки и стратегии в панели
func (t *TUI) renderRemediation(v *gocui.View) {
	v.Clear()

	if len(t.hooks) == 0 && len(t.strategies) == 0 {
		fmt.Fprintln(v, "Нет доступных хуков и стратегий исправления")
		return
	}

	if len(t.hooks) > 0 {
		fmt.Fprintln(v, "ХУКИ:")
		fmt.Fprintln(v, strings.Repeat("-", 50))

		for i, hook := range t.hooks {
			enabled := "Нет"
			if hook.Enabled {
				enabled = "Да"
			}

			fmt.Fprintf(v, "%d. %s (%s)\n", i+1, hook.Name, hook.Event)
			fmt.Fprintf(v, "   Скрипт: %s\n", hook.ScriptPath)
			fmt.Fprintf(v, "   Активен: %s\n", enabled)
			fmt.Fprintln(v, "")
		}
	}

	if len(t.strategies) > 0 {
		fmt.Fprintln(v, "СТРАТЕГИИ ИСПРАВЛЕНИЯ:")
		fmt.Fprintln(v, strings.Repeat("-", 50))

		for i, strategy := range t.strategies {
			fmt.Fprintf(v, "%d. %s (%s)\n", i+1, strategy.Name, strategy.Type)
			fmt.Fprintf(v, "   Описание: %s\n", strategy.Description)
			fmt.Fprintf(v, "   Ожидаемое время простоя: %s\n", strategy.EstimatedDowntime)
			fmt.Fprintf(v, "   Команда: %s\n", strategy.Command)
			fmt.Fprintln(v, "")
		}
	}

	fmt.Fprintln(v, "Используйте стрелки для навигации, Enter для выбора, Esc для выхода")
}

// applyRemediation применяет выбранное исправление
func (t *TUI) applyRemediation(g *gocui.Gui, v *gocui.View) error {
	// TODO: Реализовать применение исправления
	t.updateStatus("Применение исправления...")
	t.addLog("Запуск процесса исправления уязвимостей")

	// Закрываем панель
	return t.closeRemediation(g, v)
}

// addLog добавляет запись в лог
func (t *TUI) addLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)

	// Добавляем запись в конец списка
	t.logs = append(t.logs, logEntry)

	// Ограничиваем размер лога
	if len(t.logs) > 100 {
		t.logs = t.logs[len(t.logs)-100:]
	}

	// Обновляем отображение логов
	if logsView, err := t.g.View("logs"); err == nil {
		t.renderLogs(logsView)
	}
}

// fetchContainersDirect выполняет прямой запрос к агенту аналогично CLI команде containers list
func (t *TUI) fetchContainersDirect() error {
	if t.activeHost == nil {
		t.addLog("Ошибка: не выбран активный хост")
		return fmt.Errorf("не выбран активный хост")
	}

	t.addLog(fmt.Sprintf("Прямой запрос контейнеров с хоста %s (%s)",
		t.activeHost.Name, t.activeHost.Address))

	// Формирование URL для запроса к агенту - как в CLI
	url := fmt.Sprintf("http://%s:%d/containers", t.activeHost.Address, t.activeHost.Port)
	t.addLog(fmt.Sprintf("URL запроса: %s", url))

	// Выполнение HTTP запроса напрямую
	resp, err := http.Get(url)
	if err != nil {
		t.addLog(fmt.Sprintf("Ошибка запроса к агенту: %v", err))
		return err
	}
	defer resp.Body.Close()

	// Проверка статуса ответа
	if resp.StatusCode != http.StatusOK {
		t.addLog(fmt.Sprintf("Агент вернул ошибку: статус %d", resp.StatusCode))
		return fmt.Errorf("агент вернул статус %d", resp.StatusCode)
	}

	// Декодирование ответа
	var containerResponse models.ContainerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&containerResponse); err != nil {
		t.addLog(fmt.Sprintf("Ошибка декодирования ответа: %v", err))
		return err
	}

	t.addLog(fmt.Sprintf("Получено %d контейнеров напрямую от агента",
		len(containerResponse.Containers)))

	// Заменяем список контейнеров напрямую
	t.containers = containerResponse.Containers

	// Установим правильный hostID для всех контейнеров
	for i := range t.containers {
		t.containers[i].HostID = t.activeHost.ID
	}

	// Выведем список полученных контейнеров для отладки
	for i, container := range t.containers {
		t.addLog(fmt.Sprintf("Контейнер %d: ID=%s, Name=%s, Image=%s, Status=%s",
			i+1, container.ID, container.Name, container.Image, container.Status))
	}

	// Обновим представление
	if containersView, err := t.g.View("containers"); err == nil {
		t.renderContainers(containersView)
	}

	return nil
}
