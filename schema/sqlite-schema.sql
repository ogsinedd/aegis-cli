-- SQLite схема для Aegis

-- Таблица хостов
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_seen TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    description TEXT
);

-- Таблица контейнеров
CREATE TABLE IF NOT EXISTS containers (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

-- Таблица сканирований
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
);

-- Таблица уязвимостей
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
    references TEXT,
    discovered_at TIMESTAMP NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (container_id) REFERENCES containers(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

-- Таблица хуков
CREATE TABLE IF NOT EXISTS hooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    event TEXT NOT NULL,
    script_path TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Таблица выполнений хуков
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
);

-- Таблица стратегий восстановления
CREATE TABLE IF NOT EXISTS remediation_strategies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    estimated_downtime TEXT NOT NULL,
    command TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL
);

-- Начальные данные для стратегий восстановления
INSERT INTO remediation_strategies (id, name, type, estimated_downtime, command, description, created_at)
VALUES 
    ('strategy-1', 'Горячее обновление', 'hot-patch', 'Нет простоя', 'apt-get update && apt-get upgrade -y {{package}}', 'Обновление пакета без перезапуска контейнера', CURRENT_TIMESTAMP),
    ('strategy-2', 'Перезапуск', 'restart', '10-30 секунд', 'docker restart {{container_id}}', 'Перезапуск контейнера после обновления образа', CURRENT_TIMESTAMP),
    ('strategy-3', 'Постепенное обновление', 'rolling-update', '1-5 минут на узел', 'kubectl rollout restart deployment/{{deployment_name}}', 'Постепенное обновление контейнеров в Kubernetes', CURRENT_TIMESTAMP);

-- Индексы для ускорения запросов
CREATE INDEX IF NOT EXISTS idx_containers_host_id ON containers(host_id);
CREATE INDEX IF NOT EXISTS idx_scans_host_id ON scans(host_id);
CREATE INDEX IF NOT EXISTS idx_scans_container_id ON scans(container_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_container_id ON vulnerabilities(container_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_hook_executions_hook_id ON hook_executions(hook_id);
CREATE INDEX IF NOT EXISTS idx_hook_executions_scan_id ON hook_executions(scan_id); 
 