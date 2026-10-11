# Локальный запуск и сборка

## 1. Подготовить папку и настройки

Для запуска из исходников и сборки нужен Go версии из `go.mod`. При первом запуске Go может загрузить зависимости из сети.

```sh
cd /Users/andrei/Documents/personal/loki
```

Программа читает `.env` из этой папки. Используйте существующий файл; если его нет, скопируйте `.env.example` в `.env`. Для мониторинга нужны `GRAFANA_TOKEN`, `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID`. Для предпросмотра достаточно `GRAFANA_TOKEN`. Выполнять `source .env` не нужно. Как получить ID уже добавленной группы — в [шаге 2 QUICKSTART](QUICKSTART.md#2-подключить-уже-добавленного-в-группу-бота).

Выберите один из двух вариантов запуска ниже. Перед сменой варианта остановите предыдущий `watch` через **Ctrl+C**.

## 2. Запустить код через Go

```sh
# Проверить один цикл без отправки сообщений и изменения базы.
go run ./cmd/lokictl watch --once --dry-run

# Включить постоянный сбор, запись в SQLite и уведомления Telegram.
go run ./cmd/lokictl watch
```

Go сам собирает и запускает актуальный код; отдельная команда сборки не нужна. После изменения кода перезапустите команду.

## 3. Собрать и запустить бинарник

```sh
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/lokictl ./cmd/lokictl

# Проверить один цикл.
./bin/lokictl watch --once --dry-run

# Включить постоянный мониторинг.
./bin/lokictl watch
```

При следующих запусках достаточно `./bin/lokictl watch`. После изменения кода бинарник нужно пересобрать. Оба варианта используют те же `.env`, базу `local/loki.db` и состояние уведомлений; пути можно изменить через `WATCH_*` в `.env`. Остановка — **Ctrl+C**.

Другие команды запускаются так же: например, `go run ./cmd/lokictl check` или `./bin/lokictl check`. Список команд — `go run ./cmd/lokictl --help` или `./bin/lokictl --help`.

## 4. Собрать архивы для коллег

Дополнительно нужны `zip` и `shasum`:

```sh
sh scripts/build-release.sh
```

Скрипт собирает четыре комплекта в `dist/`: Mac Apple Silicon, Mac Intel, Linux amd64 и Windows amd64. Для обновления своего `bin/lokictl` используйте шаг 3. Запуск через `sh` не требует исполняемого бита и устраняет эту причину `permission denied`; для прямого запуска `./scripts/build-release.sh` сначала выполните `chmod u+x scripts/build-release.sh`.

Выбор архива и состав комплекта — в [spec/distribution.md](spec/distribution.md). Запуск готового комплекта без Go — в [QUICKSTART.md](QUICKSTART.md).
