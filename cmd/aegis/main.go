package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aegis/aegis-cli/pkg/config"
	"github.com/aegis/aegis-cli/pkg/db"
	"github.com/aegis/aegis-cli/pkg/models"
	"github.com/aegis/aegis-cli/pkg/tui"
	"github.com/aegis/aegis-cli/pkg/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func main() {
	// Отладочная информация
	fmt.Println("Aegis CLI v0.1.0")
	fmt.Println("Запуск...")
	fmt.Println("Текущая директория:", getCurrentDir())

	// Логирование
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Создаем файл для логирования ошибок
	logFile, err := os.OpenFile("aegis-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logger.SetOutput(logFile)
	} else {
		fmt.Println("Ошибка открытия файла лога:", err)
	}

	logger.SetLevel(logrus.DebugLevel)
	logger.Debug("Начало выполнения программы")

	// Проверка аргументов командной строки
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		logger.Debug("Отображение справки")
		printUsage()
		logAndExit(logger, 0, "Выход - отображена справка")
		return
	}

	// Загрузка конфигурации
	logger.Debug("Загрузка конфигурации")
	cfg, err := config.LoadCliConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка загрузки конфигурации: %v\n", err)
		logger.WithError(err).Error("Ошибка загрузки конфигурации")
		logAndExit(logger, 1, "Выход с ошибкой: не удалось загрузить конфигурацию")
		return
	}
	logger.Debug("Конфигурация загружена успешно")

	// Настройка логгера на основе конфигурации
	if cfg.LogFile != "" {
		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.WithError(err).Fatal("Не удалось открыть файл логов")
			os.Exit(1)
		}
		logger.SetOutput(file)
	}

	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logger.SetLevel(logLevel)
	}

	// Инициализация БД
	logger.Debug("Инициализация БД")
	store, err := db.NewStore(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка подключения к БД: %v\n", err)
		logger.WithError(err).Error("Ошибка подключения к БД")
		logAndExit(logger, 1, "Выход с ошибкой: не удалось подключиться к БД")
		return
	}
	logger.Debug("БД инициализирована успешно")
	defer store.Close()

	// Инициализация менеджера уведомлений
	notificationManager := utils.NewNotificationManager(cfg, logger)

	// Запуск соответствующей команды
	cmd := os.Args[1]
	switch cmd {
	case "hosts":
		handleHosts(os.Args[2:], store, logger, cfg)
	case "containers":
		handleContainers(os.Args[2:], store, logger, cfg)
	case "scan":
		handleScan(os.Args[2:], store, logger, cfg, notificationManager)
	case "vulnerabilities":
		handleVulnerabilities(os.Args[2:], store, logger, cfg)
	case "hook":
		handleHooks(os.Args[2:], store, logger, cfg)
	case "tui":
		startTUI(store, logger, cfg, notificationManager)
	case "version":
		fmt.Println("Aegis CLI v0.1.0")
	case "help", "-h", "--help":
		printUsage()
	default:
		logger.WithField("command", cmd).Error("Неизвестная команда")
		fmt.Fprintf(os.Stderr, "Неизвестная команда: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// Вспомогательная функция для получения текущей директории
func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("Ошибка: %v", err)
	}
	return dir
}

func printUsage() {
	fmt.Println(`Использование: aegis КОМАНДА [ОПЦИИ]

Команды:
  hosts           Управление агентами (list|add|remove|update)
  containers      Список контейнеров (list --host HOST_ID)
  scan            Управление сканированием (run|status)
  vulnerabilities Список уязвимостей (list [--host HOST_ID] [--container CONTAINER_ID])
  hook            Управление хуками (list|add|remove|update)
  tui             Запуск интерактивного терминального интерфейса
  version         Вывод версии приложения
  help            Вывод этой справки
`)
}

func handleHosts(args []string, store *db.Store, logger *logrus.Logger, cfg *config.CliConfig) {
	if len(args) == 0 {
		fmt.Println("Использование: aegis hosts КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: list, add, remove, update")
		return
	}

	subCmd := args[0]
	switch subCmd {
	case "list":
		// Получение списка хостов
		hosts, err := store.ListHosts()
		if err != nil {
			logger.WithError(err).Error("Ошибка получения списка хостов")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		// Вывод информации о хостах
		if len(hosts) == 0 {
			fmt.Println("Хосты не найдены")
			return
		}

		fmt.Printf("%-36s %-20s %-15s %-5s %-10s %-20s\n", "ID", "Имя", "Адрес", "Порт", "Статус", "Последняя активность")
		fmt.Println(strings.Repeat("-", 110))
		for _, host := range hosts {
			lastSeen := "Нет данных"
			if !host.LastSeen.IsZero() {
				lastSeen = host.LastSeen.Format("2006-01-02 15:04:05")
			}
			fmt.Printf("%-36s %-20s %-15s %-5d %-10s %-20s\n",
				host.ID, host.Name, host.Address, host.Port, host.Status, lastSeen)
		}

	case "add":
		// Парсинг флагов для добавления хоста
		hostCmd := flag.NewFlagSet("hosts add", flag.ExitOnError)
		name := hostCmd.String("name", "", "Имя хоста")
		address := hostCmd.String("address", "", "Адрес хоста")
		port := hostCmd.Int("port", cfg.DefaultAgentPort, "Порт агента")
		description := hostCmd.String("description", "", "Описание хоста")
		// Новые параметры для установки агента
		installAgent := hostCmd.Bool("install-agent", false, "Установить агент на удаленный хост")
		sshUser := hostCmd.String("ssh-user", "root", "SSH пользователь для подключения")
		sshKey := hostCmd.String("ssh-key", "", "Путь к SSH ключу")
		sshPort := hostCmd.Int("ssh-port", 22, "SSH порт")
		sshPassword := hostCmd.Bool("ssh-password", false, "Запросить SSH пароль")
		sudoPassword := hostCmd.Bool("sudo-password", false, "Запросить sudo пароль")
		hostCmd.Parse(args[1:])

		// Проверка обязательных параметров
		if *name == "" || *address == "" {
			fmt.Println("Ошибка: необходимо указать имя и адрес хоста")
			fmt.Println("Использование: aegis hosts add --name ИМЯ --address АДРЕС [--port ПОРТ] [--description ОПИСАНИЕ] [--install-agent] [--ssh-user ПОЛЬЗОВАТЕЛЬ] [--ssh-key ПУТЬ] [--ssh-port ПОРТ] [--ssh-password] [--sudo-password]")
			return
		}

		// Создание новой записи хоста
		host := &models.Host{
			ID:          uuid.New().String(),
			Name:        *name,
			Address:     *address,
			Port:        *port,
			Status:      "offline", // По умолчанию считаем хост оффлайн до первой проверки
			CreatedAt:   time.Now(),
			Description: *description,
		}

		// Сохранение хоста в БД
		if err := store.AddHost(host); err != nil {
			logger.WithError(err).Error("Ошибка добавления хоста")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		fmt.Printf("Хост добавлен: ID=%s, Имя=%s, Адрес=%s:%d\n",
			host.ID, host.Name, host.Address, host.Port)

		// Установка агента если указан флаг --install-agent
		if *installAgent {
			fmt.Println("Начало установки агента на удаленный хост...")

			// Формирование команды для Ansible
			inventoryFile := fmt.Sprintf("%s,", host.Address)
			playbookPath := "deploy/ansible/install-agent.yml"

			// Базовая команда ansible-playbook
			ansibleCmd := []string{
				"ansible-playbook",
				"-i", inventoryFile,
			}

			// Добавление SSH пользователя
			if *sshUser != "" {
				ansibleCmd = append(ansibleCmd, "--user", *sshUser)
			}

			// Добавление SSH ключа
			if *sshKey != "" {
				ansibleCmd = append(ansibleCmd, "--private-key", *sshKey)
			}

			// Добавление SSH порта
			if *sshPort != 22 {
				ansibleCmd = append(ansibleCmd, "--port", fmt.Sprintf("%d", *sshPort))
			}

			// Добавление флагов для запроса паролей
			if *sshPassword {
				ansibleCmd = append(ansibleCmd, "--ask-pass")
			}

			if *sudoPassword {
				ansibleCmd = append(ansibleCmd, "--become", "--ask-become-pass")
			} else {
				// Если sudo пароль не запрашивается, все равно добавляем --become для привилегированного доступа
				ansibleCmd = append(ansibleCmd, "--become")
			}

			// Добавление переменных для настройки агента
			ansibleCmd = append(ansibleCmd,
				"-e", fmt.Sprintf("agent_port=%d", *port),
				playbookPath,
			)

			// Выполнение команды Ansible
			cmd := exec.Command(ansibleCmd[0], ansibleCmd[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			logger.WithField("command", strings.Join(ansibleCmd, " ")).Info("Запуск установки агента")

			if err := cmd.Run(); err != nil {
				logger.WithError(err).Error("Ошибка установки агента")
				fmt.Fprintf(os.Stderr, "Ошибка установки агента: %v\n", err)
				return
			}

			fmt.Println("Агент успешно установлен на удаленный хост")

			// Обновление статуса хоста
			host.Status = "online"
			if err := store.UpdateHost(host); err != nil {
				logger.WithError(err).Error("Ошибка обновления статуса хоста")
			}
		}

	case "remove":
		// Проверка наличия ID хоста
		if len(args) < 2 {
			fmt.Println("Ошибка: необходимо указать ID хоста")
			fmt.Println("Использование: aegis hosts remove HOST_ID")
			return
		}

		hostID := args[1]

		// Проверка существования хоста
		_, err := store.GetHost(hostID)
		if err != nil {
			logger.WithError(err).WithField("host_id", hostID).Error("Хост не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хост с ID=%s не найден\n", hostID)
			return
		}

		// Удаление хоста
		if err := store.DeleteHost(hostID); err != nil {
			logger.WithError(err).WithField("host_id", hostID).Error("Ошибка удаления хоста")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		fmt.Printf("Хост с ID=%s успешно удален\n", hostID)

	case "update":
		// Проверка наличия ID хоста
		if len(args) < 2 {
			fmt.Println("Ошибка: необходимо указать ID хоста")
			fmt.Println("Использование: aegis hosts update HOST_ID [--name ИМЯ] [--address АДРЕС] [--port ПОРТ] [--description ОПИСАНИЕ]")
			return
		}

		hostID := args[1]

		// Получение текущей информации о хосте
		host, err := store.GetHost(hostID)
		if err != nil {
			logger.WithError(err).WithField("host_id", hostID).Error("Хост не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хост с ID=%s не найден\n", hostID)
			return
		}

		// Парсинг флагов для обновления хоста
		hostCmd := flag.NewFlagSet("hosts update", flag.ExitOnError)
		name := hostCmd.String("name", host.Name, "Имя хоста")
		address := hostCmd.String("address", host.Address, "Адрес хоста")
		port := hostCmd.Int("port", host.Port, "Порт агента")
		description := hostCmd.String("description", host.Description, "Описание хоста")
		hostCmd.Parse(args[2:])

		// Обновление информации о хосте
		host.Name = *name
		host.Address = *address
		host.Port = *port
		host.Description = *description
		host.UpdatedAt = time.Now()

		// Сохранение обновленной информации
		if err := store.UpdateHost(host); err != nil {
			logger.WithError(err).WithField("host_id", hostID).Error("Ошибка обновления хоста")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		fmt.Printf("Хост обновлен: ID=%s, Имя=%s, Адрес=%s:%d\n",
			host.ID, host.Name, host.Address, host.Port)

	default:
		fmt.Printf("Неизвестная команда: %s\n", subCmd)
		fmt.Println("Использование: aegis hosts КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: list, add, remove, update")
	}
}

func handleContainers(args []string, store *db.Store, logger *logrus.Logger, cfg *config.CliConfig) {
	if len(args) == 0 || args[0] != "list" {
		fmt.Println("Использование: aegis containers list --host HOST_ID")
		return
	}

	// Парсинг флагов для команды containers list
	containersCmd := flag.NewFlagSet("containers list", flag.ExitOnError)
	hostID := containersCmd.String("host", "", "ID хоста")
	containersCmd.Parse(args[1:])

	// Проверка обязательных параметров
	if *hostID == "" {
		fmt.Println("Ошибка: необходимо указать ID хоста")
		fmt.Println("Использование: aegis containers list --host HOST_ID")
		return
	}

	// Проверка существования хоста
	host, err := store.GetHost(*hostID)
	if err != nil {
		logger.WithError(err).WithField("host_id", *hostID).Error("Хост не найден")
		fmt.Fprintf(os.Stderr, "Ошибка: хост с ID=%s не найден\n", *hostID)
		return
	}

	// Формирование URL для запроса к агенту
	url := fmt.Sprintf("http://%s:%d/containers", host.Address, host.Port)

	// Выполнение HTTP запроса
	logger.WithFields(logrus.Fields{
		"host_id": *hostID,
		"url":     url,
	}).Info("Запрос списка контейнеров от агента")

	resp, err := http.Get(url)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"host_id": *hostID,
			"url":     url,
		}).Error("Ошибка запроса к агенту")
		fmt.Fprintf(os.Stderr, "Ошибка подключения к агенту: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Проверка статуса ответа
	if resp.StatusCode != http.StatusOK {
		logger.WithFields(logrus.Fields{
			"host_id":     *hostID,
			"url":         url,
			"status_code": resp.StatusCode,
		}).Error("Агент вернул ошибку")
		fmt.Fprintf(os.Stderr, "Ошибка: агент вернул статус %d\n", resp.StatusCode)
		return
	}

	// Декодирование ответа
	var containerResponse models.ContainerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&containerResponse); err != nil {
		logger.WithError(err).WithField("host_id", *hostID).Error("Ошибка декодирования ответа агента")
		fmt.Fprintf(os.Stderr, "Ошибка декодирования ответа: %v\n", err)
		return
	}

	// Обновление контейнеров в базе данных
	for _, container := range containerResponse.Containers {
		// Добавляем хост ID и время обновления
		container.HostID = *hostID
		container.UpdatedAt = time.Now()

		// Проверяем, существует ли контейнер в базе
		existingContainer, err := store.GetContainer(container.ID)
		if err == nil {
			// Контейнер существует, обновляем статус
			existingContainer.Status = container.Status
			existingContainer.UpdatedAt = time.Now()
			if err := store.UpdateContainer(existingContainer); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": container.ID,
				}).Error("Ошибка обновления контейнера в БД")
			}
		} else {
			// Контейнер не существует, добавляем
			container.CreatedAt = time.Now()
			if err := store.AddContainer(&container); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": container.ID,
				}).Error("Ошибка добавления контейнера в БД")
			}
		}
	}

	// Вывод списка контейнеров
	if len(containerResponse.Containers) == 0 {
		fmt.Println("Контейнеры не найдены")
		return
	}

	fmt.Printf("%-15s %-40s %-30s %-10s\n", "ID", "Имя", "Образ", "Статус")
	fmt.Println(strings.Repeat("-", 100))

	for _, container := range containerResponse.Containers {
		// Сокращаем ID для отображения
		shortID := container.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		// Сокращаем слишком длинные имена
		name := container.Name
		if len(name) > 38 {
			name = name[:35] + "..."
		}

		// Сокращаем длинные имена образов
		image := container.Image
		if len(image) > 28 {
			image = image[:25] + "..."
		}

		fmt.Printf("%-15s %-40s %-30s %-10s\n", shortID, name, image, container.Status)
	}
}

func handleScan(args []string, store *db.Store, logger *logrus.Logger, cfg *config.CliConfig, notificationManager *utils.NotificationManager) {
	if len(args) == 0 {
		fmt.Println("Использование: aegis scan КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: run, status")
		return
	}

	subCmd := args[0]
	switch subCmd {
	case "run":
		// Парсинг флагов для запуска сканирования
		scanCmd := flag.NewFlagSet("scan run", flag.ExitOnError)
		hostID := scanCmd.String("host", "", "ID хоста для сканирования")
		containerID := scanCmd.String("container", "", "ID контейнера для сканирования")
		allContainers := scanCmd.Bool("all", false, "Сканировать все контейнеры хоста")
		scanCmd.Parse(args[1:])

		// Проверка обязательных параметров
		if *hostID == "" {
			fmt.Println("Ошибка: необходимо указать ID хоста")
			fmt.Println("Использование: aegis scan run --host HOST_ID [--container CONTAINER_ID|--all]")
			return
		}

		// Проверка существования хоста
		host, err := store.GetHost(*hostID)
		if err != nil {
			logger.WithError(err).WithField("host_id", *hostID).Error("Хост не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хост с ID=%s не найден\n", *hostID)
			return
		}

		// Проверка параметров --container и --all
		if *containerID == "" && !*allContainers {
			fmt.Println("Ошибка: необходимо указать ID контейнера (--container) или флаг --all")
			fmt.Println("Использование: aegis scan run --host HOST_ID [--container CONTAINER_ID|--all]")
			return
		}

		if *containerID != "" && *allContainers {
			fmt.Println("Ошибка: нельзя одновременно указывать ID контейнера и флаг --all")
			fmt.Println("Использование: aegis scan run --host HOST_ID [--container CONTAINER_ID|--all]")
			return
		}

		// Запуск сканирования одного контейнера
		if *containerID != "" {
			// Проверка существования контейнера
			_, err := store.GetContainer(*containerID)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": *containerID,
				}).Error("Контейнер не найден")
				fmt.Fprintf(os.Stderr, "Ошибка: контейнер с ID=%s не найден\n", *containerID)
				return
			}

			// Формирование URL для запроса к агенту
			url := fmt.Sprintf("http://%s:%d/scan", host.Address, host.Port)

			// Подготовка запроса на сканирование
			scanReq := models.ScanRequest{
				ContainerID: *containerID,
			}

			jsonData, err := json.Marshal(scanReq)
			if err != nil {
				logger.WithError(err).Error("Ошибка сериализации запроса")
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
				return
			}

			// Выполнение POST запроса к агенту
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": *containerID,
					"url":          url,
				}).Error("Ошибка запроса к агенту")
				fmt.Fprintf(os.Stderr, "Ошибка подключения к агенту: %v\n", err)
				return
			}
			defer resp.Body.Close()

			// Проверка статуса ответа
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
				logger.WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": *containerID,
					"url":          url,
					"status_code":  resp.StatusCode,
				}).Error("Агент вернул ошибку")
				fmt.Fprintf(os.Stderr, "Ошибка: агент вернул статус %d\n", resp.StatusCode)
				return
			}

			// Декодирование ответа
			var scanResp models.ScanResponse
			if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": *containerID,
				}).Error("Ошибка декодирования ответа агента")
				fmt.Fprintf(os.Stderr, "Ошибка декодирования ответа: %v\n", err)
				return
			}

			// Сохранение информации о сканировании в БД
			scan := &models.Scan{
				ID:          scanResp.ScanID,
				HostID:      *hostID,
				ContainerID: *containerID,
				Status:      "pending",
				StartedAt:   time.Now(),
			}

			if err := store.AddScan(scan); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id":      *hostID,
					"container_id": *containerID,
					"scan_id":      scanResp.ScanID,
				}).Error("Ошибка сохранения информации о сканировании")
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
				return
			}

			fmt.Printf("Сканирование запущено: ID=%s\n", scanResp.ScanID)
			fmt.Println("Используйте команду 'aegis scan status SCAN_ID' для проверки статуса")

		} else if *allContainers {
			// Запрос списка контейнеров от агента
			containersURL := fmt.Sprintf("http://%s:%d/containers", host.Address, host.Port)

			resp, err := http.Get(containersURL)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"host_id": *hostID,
					"url":     containersURL,
				}).Error("Ошибка запроса к агенту")
				fmt.Fprintf(os.Stderr, "Ошибка подключения к агенту: %v\n", err)
				return
			}

			// Декодирование ответа
			var containerResp models.ContainerListResponse
			if err := json.NewDecoder(resp.Body).Decode(&containerResp); err != nil {
				logger.WithError(err).WithField("host_id", *hostID).Error("Ошибка декодирования ответа агента")
				fmt.Fprintf(os.Stderr, "Ошибка декодирования ответа: %v\n", err)
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			// Проверка наличия контейнеров
			if len(containerResp.Containers) == 0 {
				fmt.Println("Контейнеры не найдены")
				return
			}

			// Запуск сканирования для каждого контейнера
			scanURL := fmt.Sprintf("http://%s:%d/scan", host.Address, host.Port)
			var successCount, failCount int

			for _, container := range containerResp.Containers {
				// Подготовка запроса на сканирование
				scanReq := models.ScanRequest{
					ContainerID: container.ID,
				}

				jsonData, err := json.Marshal(scanReq)
				if err != nil {
					logger.WithError(err).Error("Ошибка сериализации запроса")
					failCount++
					continue
				}

				// Выполнение POST запроса к агенту
				scanResp, err := http.Post(scanURL, "application/json", bytes.NewBuffer(jsonData))
				if err != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"host_id":      *hostID,
						"container_id": container.ID,
						"url":          scanURL,
					}).Error("Ошибка запроса к агенту")
					failCount++
					continue
				}

				// Проверка статуса ответа
				if scanResp.StatusCode != http.StatusOK && scanResp.StatusCode != http.StatusAccepted {
					logger.WithFields(logrus.Fields{
						"host_id":      *hostID,
						"container_id": container.ID,
						"url":          scanURL,
						"status_code":  scanResp.StatusCode,
					}).Error("Агент вернул ошибку")
					scanResp.Body.Close()
					failCount++
					continue
				}

				// Декодирование ответа
				var scanRespObj models.ScanResponse
				if err := json.NewDecoder(scanResp.Body).Decode(&scanRespObj); err != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"host_id":      *hostID,
						"container_id": container.ID,
					}).Error("Ошибка декодирования ответа агента")
					scanResp.Body.Close()
					failCount++
					continue
				}
				scanResp.Body.Close()

				// Сохранение информации о сканировании в БД
				scan := &models.Scan{
					ID:          scanRespObj.ScanID,
					HostID:      *hostID,
					ContainerID: container.ID,
					Status:      "pending",
					StartedAt:   time.Now(),
				}

				if err := store.AddScan(scan); err != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"host_id":      *hostID,
						"container_id": container.ID,
						"scan_id":      scanRespObj.ScanID,
					}).Error("Ошибка сохранения информации о сканировании")
					failCount++
					continue
				}

				successCount++
				fmt.Printf("Сканирование запущено для контейнера %s: ID=%s\n", container.Name, scanRespObj.ScanID)
			}

			fmt.Printf("\nСканирование запущено для %d контейнеров, не удалось запустить для %d контейнеров\n",
				successCount, failCount)
			fmt.Println("Используйте команду 'aegis vulnerabilities list' для просмотра результатов")
		}

	case "status":
		// Проверка указания ID сканирования
		if len(args) < 2 {
			fmt.Println("Ошибка: необходимо указать ID сканирования")
			fmt.Println("Использование: aegis scan status SCAN_ID")
			return
		}

		scanID := args[1]

		// Получение информации о сканировании из БД
		scan, err := store.GetScan(scanID)
		if err != nil {
			logger.WithError(err).WithField("scan_id", scanID).Error("Сканирование не найдено")
			fmt.Fprintf(os.Stderr, "Ошибка: сканирование с ID=%s не найдено\n", scanID)
			return
		}

		// Получение информации о хосте
		host, err := store.GetHost(scan.HostID)
		if err != nil {
			logger.WithError(err).WithField("host_id", scan.HostID).Error("Хост не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хост не найден\n")
			return
		}

		// Если сканирование уже завершено, просто выводим информацию из БД
		if scan.Status == "completed" || scan.Status == "failed" {
			container, _ := store.GetContainer(scan.ContainerID)
			containerName := scan.ContainerID
			if container != nil {
				containerName = container.Name
			}

			fmt.Printf("Сканирование: %s\n", scanID)
			fmt.Printf("Хост: %s (%s)\n", host.Name, host.Address)
			fmt.Printf("Контейнер: %s\n", containerName)
			fmt.Printf("Статус: %s\n", scan.Status)
			fmt.Printf("Начало: %s\n", scan.StartedAt.Format("2006-01-02 15:04:05"))

			if !scan.FinishedAt.IsZero() {
				fmt.Printf("Завершение: %s\n", scan.FinishedAt.Format("2006-01-02 15:04:05"))
				duration := scan.FinishedAt.Sub(scan.StartedAt)
				fmt.Printf("Длительность: %s\n", duration.String())
			}

			if scan.Status == "failed" && scan.ErrorMsg != "" {
				fmt.Printf("Ошибка: %s\n", scan.ErrorMsg)
			}

			if scan.Status == "completed" {
				// Получение количества найденных уязвимостей
				vulnerabilities, err := store.ListVulnerabilities("", "", scanID, "")
				if err == nil {
					// Группировка уязвимостей по серьезности
					var criticalCount, highCount, mediumCount, lowCount int
					for _, vuln := range vulnerabilities {
						switch strings.ToUpper(vuln.Severity) {
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

					fmt.Println("\nРезультаты сканирования:")
					fmt.Printf("- Критических: %d\n", criticalCount)
					fmt.Printf("- Высоких: %d\n", highCount)
					fmt.Printf("- Средних: %d\n", mediumCount)
					fmt.Printf("- Низких: %d\n", lowCount)

					fmt.Println("\nДля просмотра подробной информации используйте:")
					fmt.Printf("aegis vulnerabilities list --scan %s\n", scanID)
				}
			}

			return
		}

		// Формирование URL для запроса статуса к агенту
		url := fmt.Sprintf("http://%s:%d/scan/%s", host.Address, host.Port, scanID)

		// Выполнение HTTP запроса
		resp, err := http.Get(url)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"host_id": scan.HostID,
				"scan_id": scanID,
				"url":     url,
			}).Error("Ошибка запроса к агенту")
			fmt.Fprintf(os.Stderr, "Ошибка подключения к агенту: %v\n", err)
			return
		}
		defer resp.Body.Close()

		// Проверка статуса ответа
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			logger.WithFields(logrus.Fields{
				"host_id":     scan.HostID,
				"scan_id":     scanID,
				"url":         url,
				"status_code": resp.StatusCode,
			}).Error("Агент вернул ошибку")
			fmt.Fprintf(os.Stderr, "Ошибка: агент вернул статус %d\n", resp.StatusCode)
			return
		}

		// Декодирование ответа
		var scanStatusResp models.ScanStatusResponse
		if err := json.NewDecoder(resp.Body).Decode(&scanStatusResp); err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"host_id": scan.HostID,
				"scan_id": scanID,
			}).Error("Ошибка декодирования ответа агента")
			fmt.Fprintf(os.Stderr, "Ошибка декодирования ответа: %v\n", err)
			return
		}

		// Обновление статуса сканирования в БД
		scan.Status = scanStatusResp.Status
		if scanStatusResp.FinishedAt != nil {
			scan.FinishedAt = *scanStatusResp.FinishedAt
		}
		if scanStatusResp.ErrorMsg != "" {
			scan.ErrorMsg = scanStatusResp.ErrorMsg
		}

		if err := store.UpdateScan(scan); err != nil {
			logger.WithError(err).WithField("scan_id", scanID).Error("Ошибка обновления информации о сканировании")
		}

		// Если сканирование завершено и есть результаты, сохраняем их в БД
		if scan.Status == "completed" && len(scanStatusResp.Vulnerabilities) > 0 {
			for _, vuln := range scanStatusResp.Vulnerabilities {
				// Дополняем данные об уязвимости
				vuln.ID = uuid.New().String()
				vuln.ScanID = scanID
				vuln.ContainerID = scan.ContainerID
				vuln.HostID = scan.HostID
				vuln.DiscoveredAt = time.Now()

				// Сохраняем уязвимость в БД
				if err := store.AddVulnerability(&vuln); err != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"scan_id":          scanID,
						"host_id":          scan.HostID,
						"container_id":     scan.ContainerID,
						"vulnerability_id": vuln.VulnerabilityID,
					}).Error("Ошибка сохранения информации об уязвимости")
				}
			}
		}

		// Получение информации о контейнере
		container, _ := store.GetContainer(scan.ContainerID)
		containerName := scan.ContainerID
		if container != nil {
			containerName = container.Name
		}

		// Вывод информации о сканировании
		fmt.Printf("Сканирование: %s\n", scanID)
		fmt.Printf("Хост: %s (%s)\n", host.Name, host.Address)
		fmt.Printf("Контейнер: %s\n", containerName)
		fmt.Printf("Статус: %s\n", scan.Status)
		fmt.Printf("Начало: %s\n", scan.StartedAt.Format("2006-01-02 15:04:05"))

		if scan.Status == "completed" || scan.Status == "failed" {
			if !scan.FinishedAt.IsZero() {
				fmt.Printf("Завершение: %s\n", scan.FinishedAt.Format("2006-01-02 15:04:05"))
				duration := scan.FinishedAt.Sub(scan.StartedAt)
				fmt.Printf("Длительность: %s\n", duration.String())
			}

			if scan.Status == "failed" && scan.ErrorMsg != "" {
				fmt.Printf("Ошибка: %s\n", scan.ErrorMsg)
			}

			if scan.Status == "completed" {
				// Вывод количества найденных уязвимостей
				fmt.Printf("\nНайдено уязвимостей: %d\n", len(scanStatusResp.Vulnerabilities))

				// Группировка уязвимостей по серьезности
				var criticalCount, highCount, mediumCount, lowCount int
				for _, vuln := range scanStatusResp.Vulnerabilities {
					switch strings.ToUpper(vuln.Severity) {
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

				fmt.Println("\nРезультаты сканирования:")
				fmt.Printf("- Критических: %d\n", criticalCount)
				fmt.Printf("- Высоких: %d\n", highCount)
				fmt.Printf("- Средних: %d\n", mediumCount)
				fmt.Printf("- Низких: %d\n", lowCount)

				fmt.Println("\nДля просмотра подробной информации используйте:")
				fmt.Printf("aegis vulnerabilities list --scan %s\n", scanID)

				// Отправка уведомления о завершении сканирования
				if notificationManager != nil {
					notificationManager.SendScanCompletedNotification(
						host.Name, containerName,
						scanStatusResp.Vulnerabilities,
						scan.FinishedAt.Sub(scan.StartedAt))
				}
			}
		} else {
			fmt.Println("\nСканирование выполняется...")
			fmt.Println("Для обновления статуса повторите команду позже.")
		}

	default:
		fmt.Printf("Неизвестная команда: %s\n", subCmd)
		fmt.Println("Использование: aegis scan КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: run, status")
	}
}

func handleVulnerabilities(args []string, store *db.Store, logger *logrus.Logger, cfg *config.CliConfig) {
	if len(args) == 0 || args[0] != "list" {
		fmt.Println("Использование: aegis vulnerabilities list [--host HOST_ID] [--container CONTAINER_ID] [--scan SCAN_ID] [--severity SEVERITY]")
		return
	}

	// Парсинг флагов для команды vulnerabilities list
	vulnsCmd := flag.NewFlagSet("vulnerabilities list", flag.ExitOnError)
	hostID := vulnsCmd.String("host", "", "ID хоста для фильтрации")
	containerID := vulnsCmd.String("container", "", "ID контейнера для фильтрации")
	scanID := vulnsCmd.String("scan", "", "ID сканирования для фильтрации")
	severity := vulnsCmd.String("severity", "", "Серьезность уязвимостей (CRITICAL, HIGH, MEDIUM, LOW)")
	vulnsCmd.Parse(args[1:])

	// Получение списка уязвимостей
	vulnerabilities, err := store.ListVulnerabilities(*hostID, *containerID, *scanID, *severity)
	if err != nil {
		logger.WithError(err).Error("Ошибка получения списка уязвимостей")
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		return
	}

	// Проверка наличия результатов
	if len(vulnerabilities) == 0 {
		fmt.Println("Уязвимости не найдены")
		return
	}

	// Группировка уязвимостей по серьезности
	var criticalCount, highCount, mediumCount, lowCount int
	for _, vuln := range vulnerabilities {
		switch strings.ToUpper(vuln.Severity) {
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

	// Вывод общей статистики
	fmt.Printf("Найдено уязвимостей: %d\n", len(vulnerabilities))
	fmt.Printf("- Критических: %d\n", criticalCount)
	fmt.Printf("- Высоких: %d\n", highCount)
	fmt.Printf("- Средних: %d\n", mediumCount)
	fmt.Printf("- Низких: %d\n", lowCount)
	fmt.Println()

	// Вывод уязвимостей
	fmt.Printf("%-15s %-15s %-40s %-10s %-20s\n", "ID", "CVE", "Пакет", "Серьезность", "Обнаружено")
	fmt.Println(strings.Repeat("-", 105))

	for _, vuln := range vulnerabilities {
		// Сокращаем ID для отображения
		shortID := vuln.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		// Сокращаем CVE для отображения
		cve := vuln.VulnerabilityID
		if len(cve) > 13 {
			cve = cve[:13]
		}

		// Сокращаем имя пакета
		pkg := fmt.Sprintf("%s (%s -> %s)", vuln.Package, vuln.InstalledVersion, vuln.FixedVersion)
		if len(pkg) > 38 {
			pkg = pkg[:35] + "..."
		}

		fmt.Printf("%-15s %-15s %-40s %-10s %-20s\n",
			shortID, cve, pkg, vuln.Severity, vuln.DiscoveredAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()

	// Если был указан конкретный ID сканирования, выводим подробности
	if *scanID != "" {
		fmt.Println("Подробная информация о найденных уязвимостях:")
		fmt.Println()

		scan, err := store.GetScan(*scanID)
		if err == nil {
			host, _ := store.GetHost(scan.HostID)
			container, _ := store.GetContainer(scan.ContainerID)

			if host != nil && container != nil {
				fmt.Printf("Хост: %s (%s)\n", host.Name, host.Address)
				fmt.Printf("Контейнер: %s\n", container.Name)
				fmt.Printf("Образ: %s\n", container.Image)
				fmt.Printf("Дата сканирования: %s\n\n", scan.StartedAt.Format("2006-01-02 15:04:05"))
			}
		}

		// Группировка по серьезности и сортировка
		critical := make([]models.Vulnerability, 0)
		high := make([]models.Vulnerability, 0)
		medium := make([]models.Vulnerability, 0)
		low := make([]models.Vulnerability, 0)

		for _, vuln := range vulnerabilities {
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				critical = append(critical, vuln)
			case "HIGH":
				high = append(high, vuln)
			case "MEDIUM":
				medium = append(medium, vuln)
			case "LOW":
				low = append(low, vuln)
			}
		}

		// Вывод критических уязвимостей
		if len(critical) > 0 {
			fmt.Println("КРИТИЧЕСКИЕ УЯЗВИМОСТИ:")
			fmt.Println(strings.Repeat("-", 80))
			for _, vuln := range critical {
				printVulnerabilityDetails(vuln)
			}
		}

		// Вывод высоких уязвимостей
		if len(high) > 0 {
			fmt.Println("ВЫСОКИЕ УЯЗВИМОСТИ:")
			fmt.Println(strings.Repeat("-", 80))
			for _, vuln := range high {
				printVulnerabilityDetails(vuln)
			}
		}

		// Вывод средних уязвимостей
		if len(medium) > 0 {
			fmt.Println("СРЕДНИЕ УЯЗВИМОСТИ:")
			fmt.Println(strings.Repeat("-", 80))
			for _, vuln := range medium {
				printVulnerabilityDetails(vuln)
			}
		}

		// Вывод низких уязвимостей
		if len(low) > 0 {
			fmt.Println("НИЗКИЕ УЯЗВИМОСТИ:")
			fmt.Println(strings.Repeat("-", 80))
			for _, vuln := range low {
				printVulnerabilityDetails(vuln)
			}
		}

		// Вывод информации о возможных стратегиях восстановления
		strategies, err := store.ListRemediationStrategies()
		if err == nil && len(strategies) > 0 {
			fmt.Println("\nВОЗМОЖНЫЕ СТРАТЕГИИ УСТРАНЕНИЯ УЯЗВИМОСТЕЙ:")
			fmt.Println(strings.Repeat("-", 80))
			for _, strategy := range strategies {
				fmt.Printf("Название: %s\n", strategy.Name)
				fmt.Printf("Тип: %s\n", strategy.Type)
				fmt.Printf("Описание: %s\n", strategy.Description)
				fmt.Printf("Ожидаемое время простоя: %s\n", strategy.EstimatedDowntime)
				fmt.Printf("Команда: %s\n", strategy.Command)
				fmt.Println(strings.Repeat("-", 80))
			}
		}
	}
}

// printVulnerabilityDetails выводит подробную информацию об уязвимости
func printVulnerabilityDetails(vuln models.Vulnerability) {
	fmt.Printf("CVE: %s\n", vuln.VulnerabilityID)
	fmt.Printf("Пакет: %s\n", vuln.Package)
	fmt.Printf("Установленная версия: %s\n", vuln.InstalledVersion)
	if vuln.FixedVersion != "" {
		fmt.Printf("Исправлено в версии: %s\n", vuln.FixedVersion)
	}
	fmt.Printf("Серьезность: %s\n", vuln.Severity)
	fmt.Printf("Название: %s\n", vuln.Title)
	if vuln.Description != "" {
		fmt.Printf("Описание: %s\n", vuln.Description)
	}

	// Вывод ссылок
	if vuln.References != "" {
		fmt.Println("Ссылки:")
		references := strings.Split(vuln.References, ",")
		for _, ref := range references {
			if ref != "" {
				fmt.Printf("- %s\n", ref)
			}
		}
	}
	fmt.Println(strings.Repeat("-", 80))
}

func handleHooks(args []string, store *db.Store, logger *logrus.Logger, cfg *config.CliConfig) {
	if len(args) == 0 {
		fmt.Println("Использование: aegis hook КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: list, add, remove, update")
		return
	}

	subCmd := args[0]
	switch subCmd {
	case "list":
		// Получение списка хуков
		hooks, err := store.ListHooks()
		if err != nil {
			logger.WithError(err).Error("Ошибка получения списка хуков")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		// Вывод информации о хуках
		if len(hooks) == 0 {
			fmt.Println("Хуки не найдены")
			return
		}

		fmt.Printf("%-36s %-20s %-16s %-40s %-10s %-10s\n", "ID", "Имя", "Событие", "Скрипт", "Таймаут", "Активен")
		fmt.Println(strings.Repeat("-", 140))
		for _, hook := range hooks {
			enabled := "Нет"
			if hook.Enabled {
				enabled = "Да"
			}

			// Сокращаем путь к скрипту, если он слишком длинный
			scriptPath := hook.ScriptPath
			if len(scriptPath) > 38 {
				scriptPath = "..." + scriptPath[len(scriptPath)-35:]
			}

			fmt.Printf("%-36s %-20s %-16s %-40s %-10d %-10s\n",
				hook.ID, hook.Name, hook.Event, scriptPath, hook.TimeoutSeconds, enabled)
		}

	case "add":
		// Парсинг флагов для добавления хука
		hookCmd := flag.NewFlagSet("hook add", flag.ExitOnError)
		name := hookCmd.String("name", "", "Имя хука")
		event := hookCmd.String("event", "", "Событие (on_scan_start, on_scan_complete, on_error)")
		scriptPath := hookCmd.String("script", "", "Путь к скрипту")
		timeout := hookCmd.Int("timeout", 30, "Таймаут выполнения в секундах")
		hookCmd.Parse(args[1:])

		// Проверка обязательных параметров
		if *name == "" || *event == "" || *scriptPath == "" {
			fmt.Println("Ошибка: необходимо указать имя, событие и путь к скрипту")
			fmt.Println("Использование: aegis hook add --name ИМЯ --event СОБЫТИЕ --script ПУТЬ [--timeout СЕКУНДЫ]")
			fmt.Println("Доступные события: on_scan_start, on_scan_complete, on_error")
			return
		}

		// Проверка корректности указанного события
		validEvents := map[string]bool{
			"on_scan_start":    true,
			"on_scan_complete": true,
			"on_error":         true,
		}
		if !validEvents[*event] {
			fmt.Println("Ошибка: некорректное событие")
			fmt.Println("Доступные события: on_scan_start, on_scan_complete, on_error")
			return
		}

		// Проверка существования файла скрипта
		if _, err := os.Stat(*scriptPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Ошибка: файл скрипта не существует: %s\n", *scriptPath)
			return
		}

		// Проверка исполняемости файла
		if err := checkExecutable(*scriptPath); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: файл скрипта не является исполняемым: %s\n", *scriptPath)
			return
		}

		// Создание новой записи хука
		hook := &models.Hook{
			ID:             uuid.New().String(),
			Name:           *name,
			Event:          *event,
			ScriptPath:     *scriptPath,
			TimeoutSeconds: *timeout,
			Enabled:        true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		// Сохранение хука в БД
		if err := store.AddHook(hook); err != nil {
			logger.WithError(err).Error("Ошибка добавления хука")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		fmt.Printf("Хук добавлен: ID=%s, Имя=%s, Событие=%s\n", hook.ID, hook.Name, hook.Event)

	case "remove":
		// Проверка наличия ID хука
		if len(args) < 2 {
			fmt.Println("Ошибка: необходимо указать ID хука")
			fmt.Println("Использование: aegis hook remove HOOK_ID")
			return
		}

		hookID := args[1]

		// Проверка существования хука
		_, err := store.GetHook(hookID)
		if err != nil {
			logger.WithError(err).WithField("hook_id", hookID).Error("Хук не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хук с ID=%s не найден\n", hookID)
			return
		}

		// Удаление хука
		if err := store.DeleteHook(hookID); err != nil {
			logger.WithError(err).WithField("hook_id", hookID).Error("Ошибка удаления хука")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		fmt.Printf("Хук с ID=%s успешно удален\n", hookID)

	case "update":
		// Проверка наличия ID хука
		if len(args) < 2 {
			fmt.Println("Ошибка: необходимо указать ID хука")
			fmt.Println("Использование: aegis hook update HOOK_ID [--name ИМЯ] [--event СОБЫТИЕ] [--script ПУТЬ] [--timeout СЕКУНДЫ] [--enabled true|false]")
			return
		}

		hookID := args[1]

		// Получение текущей информации о хуке
		hook, err := store.GetHook(hookID)
		if err != nil {
			logger.WithError(err).WithField("hook_id", hookID).Error("Хук не найден")
			fmt.Fprintf(os.Stderr, "Ошибка: хук с ID=%s не найден\n", hookID)
			return
		}

		// Парсинг флагов для обновления хука
		hookCmd := flag.NewFlagSet("hook update", flag.ExitOnError)
		name := hookCmd.String("name", hook.Name, "Имя хука")
		event := hookCmd.String("event", hook.Event, "Событие (on_scan_start, on_scan_complete, on_error)")
		scriptPath := hookCmd.String("script", hook.ScriptPath, "Путь к скрипту")
		timeout := hookCmd.Int("timeout", hook.TimeoutSeconds, "Таймаут выполнения в секундах")
		enabled := hookCmd.Bool("enabled", hook.Enabled, "Статус активации (true/false)")
		hookCmd.Parse(args[2:])

		// Проверка корректности указанного события
		if *event != hook.Event {
			validEvents := map[string]bool{
				"on_scan_start":    true,
				"on_scan_complete": true,
				"on_error":         true,
			}
			if !validEvents[*event] {
				fmt.Println("Ошибка: некорректное событие")
				fmt.Println("Доступные события: on_scan_start, on_scan_complete, on_error")
				return
			}
		}

		// Проверка существования и исполняемости файла скрипта, если он был изменен
		if *scriptPath != hook.ScriptPath {
			if _, err := os.Stat(*scriptPath); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Ошибка: файл скрипта не существует: %s\n", *scriptPath)
				return
			}

			if err := checkExecutable(*scriptPath); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: файл скрипта не является исполняемым: %s\n", *scriptPath)
				return
			}
		}

		// Обновление информации о хуке
		hook.Name = *name
		hook.Event = *event
		hook.ScriptPath = *scriptPath
		hook.TimeoutSeconds = *timeout
		hook.Enabled = *enabled
		hook.UpdatedAt = time.Now()

		// Сохранение обновленной информации
		if err := store.UpdateHook(hook); err != nil {
			logger.WithError(err).WithField("hook_id", hookID).Error("Ошибка обновления хука")
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			return
		}

		enabled_str := "неактивен"
		if hook.Enabled {
			enabled_str = "активен"
		}

		fmt.Printf("Хук обновлен: ID=%s, Имя=%s, Событие=%s, Статус=%s\n",
			hook.ID, hook.Name, hook.Event, enabled_str)

	default:
		fmt.Printf("Неизвестная команда: %s\n", subCmd)
		fmt.Println("Использование: aegis hook КОМАНДА [ОПЦИИ]")
		fmt.Println("Команды: list, add, remove, update")
	}
}

// checkExecutable проверяет, является ли файл исполняемым
func checkExecutable(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Проверка разрешения на исполнение (для Unix-подобных ОС)
	if fileInfo.Mode()&0111 == 0 {
		return fmt.Errorf("файл не имеет разрешения на исполнение")
	}

	return nil
}

func startTUI(store *db.Store, logger *logrus.Logger, cfg *config.CliConfig, notificationManager *utils.NotificationManager) {
	app := tui.NewTUI(store, logger, cfg, notificationManager)
	if err := app.Run(); err != nil {
		logger.WithError(err).Error("Ошибка запуска TUI")
		fmt.Fprintf(os.Stderr, "Ошибка запуска TUI: %v\n", err)
	}
}

// Вспомогательная функция для логирования выхода
func logAndExit(logger *logrus.Logger, code int, message string) {
	logger.Debug(message)
	if logFile, ok := logger.Out.(*os.File); ok {
		logFile.Close()
	}
	os.Exit(code)
}
